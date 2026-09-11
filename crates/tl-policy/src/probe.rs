//! Reading the facts a policy has to be compiled against.
//!
//! Every one of these is a thing people get wrong by assuming. The Tor
//! port is 9040 *if* someone configured it. The VPN interface is `tun0`
//! *if* it is OpenVPN and the first one. Your own session is on port 22
//! *if* nobody moved it. Assumptions here are not conservative — they
//! produce a ruleset that loads cleanly and does the wrong thing, which
//! is the failure that ends with a machine you cannot reach.
//!
//! So each is read, and anything that cannot be read stays `None` and
//! becomes a refusal rather than a default.

use std::collections::BTreeSet;
use std::path::Path as FsPath;

use tl_inventory::ports::EphemeralPorts;
use tl_inventory::proc_net::State;
use tl_inventory::snapshot::{self, Direction, Listeners};

use crate::Host;

/// Read everything about this host that a policy depends on.
#[must_use]
pub fn host(proc_root: &FsPath, sys_root: &FsPath, torrc: &FsPath) -> Host {
    let flows = snapshot::collect(proc_root);

    let (tor_trans_port, tor_dns_port) = tor_ports(torrc);
    // Tor's uid comes from the PROCESS, not from one of its sockets.
    //
    // A socket's recorded uid is whoever created it, and a daemon that
    // binds a privileged port before dropping privileges keeps holding
    // that socket afterwards. On this host Tor runs as uid 105 and holds
    // three sockets owned by 105 and one owned by 0. Taking the first
    // socket found yielded 0 — and `meta skuid 0 return` exempts every
    // root process on the machine from the redirect, silently, while the
    // ruleset loads cleanly and reports success.
    //
    // What the exclusion must match is the uid stamped on sockets Tor
    // opens from now on, which is the running process's effective uid.
    let tor_uid = flows
        .iter()
        .filter_map(|f| f.holder.as_ref())
        .find(|h| h.comm == "tor")
        .and_then(|h| effective_uid(proc_root, h.pid));

    let admin_peers = admin_candidates(proc_root)
        .into_iter()
        .filter(|c| c.likely)
        .map(|c| c.peer)
        .collect();

    Host {
        interfaces: interfaces(sys_root),
        tor_trans_port,
        tor_dns_port,
        tor_uid,
        admin_peers,
        tunnel_endpoints: Vec::new(),
        rp_filter: rp_filter(proc_root),
        cgroups: cgroups(sys_root),
    }
}

/// `rp_filter` for every interface, from `/proc/sys/net/ipv4/conf/*`.
///
/// Includes the pseudo-interface `all`, because the kernel takes the
/// MAXIMUM of `all` and the specific interface — so `all=1` makes every
/// interface strict no matter what its own setting says, and reading only
/// the named interface reports "loose" for a host that will drop the
/// replies anyway.
#[must_use]
pub fn rp_filter(proc_root: &FsPath) -> Vec<(String, u8)> {
    let root = proc_root.join("sys/net/ipv4/conf");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return out;
    };
    for e in entries.flatten() {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if let Ok(v) = std::fs::read_to_string(e.path().join("rp_filter")) {
            if let Ok(n) = v.trim().parse::<u8>() {
                out.push((name, n));
            }
        }
    }
    out.sort();
    out
}

/// A live inbound session that a policy must not cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSession {
    /// The remote address, spelled the way an nftables rule will see it.
    pub peer: String,
    /// The local port it arrived on.
    pub port: u16,
    /// The process holding it.
    pub holder: String,
    /// Whether this looks like somebody who has actually logged in.
    pub likely: bool,
    /// What that judgement is based on, in words, because it is a
    /// judgement and the person confirming it deserves to see the basis.
    pub evidence: String,
}

/// Inbound sessions that might be the operator's, with the evidence for
/// each.
///
/// This is deliberately a list of CANDIDATES rather than an answer,
/// because on a current Linux host there is no reliable way to ask "is
/// this connection authenticated". Checked on a live Debian 13 machine:
///
/// * `/run/utmp` does not exist — it was replaced by wtmpdb.
/// * `/run/systemd/sessions/*` recorded `REMOTE=0` for a session that had
///   arrived over SSH.
/// * every `sshd-session` process stayed under `system.slice/ssh.service`,
///   authenticated or not, so the cgroup does not separate them.
///
/// What remains is that sshd drops to the logged-in user's uid once
/// authentication succeeds, so a holder running as a real user is good
/// evidence and a root-only holder is not. That is a convention, not a
/// guarantee — hence a candidate for a person to confirm.
///
/// The stakes are not theoretical: a TCP connection to port 22 reaches
/// ESTABLISHED before any password is offered, so every brute-force
/// attempt looks like a session. Treating those as the operator lets a
/// stranger choose an address the policy will exempt, just by knocking.
#[must_use]
pub fn admin_candidates(proc_root: &FsPath) -> Vec<AdminSession> {
    let flows = snapshot::collect(proc_root);
    let ports = EphemeralPorts::load(proc_root);
    let listeners = Listeners::from_flows(&flows, ports);
    let uid_min = uid_min(FsPath::new("/etc/login.defs"));

    let ssh_ports: BTreeSet<u16> = flows
        .iter()
        .filter(|f| {
            f.socket.state == tl_inventory::proc_net::State::Listen
                && f.holder.as_ref().is_some_and(|h| h.comm.starts_with("sshd"))
        })
        .map(|f| f.socket.local_port)
        .collect();

    let mut out: Vec<AdminSession> = Vec::new();
    for f in &flows {
        if f.socket.state != State::Established
            || f.direction(&listeners) != Direction::Inbound
            || !ssh_ports.contains(&f.socket.local_port)
        {
            continue;
        }
        let peer = normalise(&f.socket.remote_addr.to_string());
        if out.iter().any(|c| c.peer == peer && c.port == f.socket.local_port) {
            continue;
        }
        let holder = f.holder.as_ref();
        // EVERY process holding this socket, not just the canonical one.
        // sshd keeps a privilege-separated monitor running as root next
        // to the child that has dropped to the logged-in user, and both
        // hold the same inode. Attribution picks the lowest pid, which is
        // the root monitor — so asking only about that one reported the
        // operator's own live session as unauthenticated.
        let euids: Vec<u32> = holders_of_inode(proc_root, f.socket.inode)
            .into_iter()
            .filter_map(|pid| effective_uid(proc_root, pid))
            .collect();
        let euid = euids.iter().copied().max();
        let likely = euids.iter().any(|u| *u >= uid_min);
        let evidence = match euid {
            Some(u) if likely => format!(
                "one of the {} processes holding this socket runs as uid {u}, a login \
                 account -- sshd drops to the user's uid only after authentication",
                euids.len()
            ),
            Some(u) => format!(
                "every process holding this socket still runs as uid {u} ({} of them). A \
                 connection reaches ESTABLISHED before any password is offered, so this \
                 may be an unauthenticated attempt rather than a session",
                euids.len()
            ),
            None => "the holding process is not readable, so nothing can be said about \
                 whether this connection is authenticated"
                .to_owned(),
        };
        out.push(AdminSession {
            peer,
            port: f.socket.local_port,
            holder: holder.map_or_else(|| "unattributed".to_owned(), |h| h.label()),
            likely,
            evidence,
        });
    }
    out.sort_by(|a, b| b.likely.cmp(&a.likely).then(a.peer.cmp(&b.peer)));
    out
}

/// The cgroups that currently own a connection leaving this machine.
///
/// A list of every unit on the host is a list of mostly-irrelevant
/// things. What someone wants to route is what is talking right now, so
/// the editor can offer those first instead of alphabetically, where the
/// interesting entry is wherever the alphabet put it.
#[must_use]
pub fn active_cgroups(proc_root: &FsPath) -> Vec<String> {
    let flows = snapshot::collect(proc_root);
    let ports = EphemeralPorts::load(proc_root);
    let listeners = Listeners::from_flows(&flows, ports);
    let mut out: Vec<String> = flows
        .iter()
        .filter(|f| f.direction(&listeners) == Direction::Outbound)
        .filter_map(|f| f.holder.as_ref())
        .filter_map(|h| {
            let body = std::fs::read_to_string(
                proc_root.join(h.pid.to_string()).join("cgroup"),
            )
            .ok()?;
            let path = body
                .lines()
                .find(|l| l.starts_with("0::"))?
                .trim_start_matches("0::")
                .trim_matches('/')
                .to_owned();
            (!path.is_empty()).then_some(path)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Every pid holding a given socket inode.
///
/// [`tl_inventory::procs::holders_by_inode`] answers "who owns this",
/// deliberately collapsing to one process. This answers "who is holding
/// it", which is a different question with a different right answer when
/// a daemon forks.
#[must_use]
pub fn holders_of_inode(proc_root: &FsPath, inode: u64) -> Vec<u32> {
    if inode == 0 {
        return Vec::new();
    }
    let target = format!("socket:[{inode}]");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else {
            continue;
        };
        if fds
            .flatten()
            .filter_map(|fd| std::fs::read_link(fd.path()).ok())
            .any(|t| t.to_string_lossy() == target)
        {
            out.push(pid);
        }
    }
    out.sort_unstable();
    out
}

/// `UID_MIN` from `/etc/login.defs` — where real login accounts start on
/// this host. Read rather than assumed at 1000, because it is a setting.
#[must_use]
pub fn uid_min(login_defs: &FsPath) -> u32 {
    std::fs::read_to_string(login_defs)
        .ok()
        .and_then(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#'))
                .find_map(|l| l.strip_prefix("UID_MIN")?.trim().parse().ok())
        })
        .unwrap_or(1000)
}

/// The effective uid of a running process, from `/proc/<pid>/status`.
///
/// Fields are `Uid: <real> <effective> <saved> <fs>`. Effective is the
/// one the kernel stamps on sockets the process creates.
#[must_use]
pub fn effective_uid(proc_root: &FsPath, pid: u32) -> Option<u32> {
    let text = std::fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// `::ffff:a.b.c.d` is the same host as `a.b.c.d`, and an nftables `ip
/// daddr` match will never see the v6-mapped spelling.
fn normalise(addr: &str) -> String {
    addr.strip_prefix("::ffff:").unwrap_or(addr).to_owned()
}

/// Interface names from `/sys/class/net`.
#[must_use]
pub fn interfaces(sys_root: &FsPath) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(sys_root.join("class/net"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    v.sort();
    v
}

/// Every cgroup v2 path under `system.slice` and `user.slice`, relative
/// to the cgroup root.
///
/// Only these two: they are where a service or a user's session lives,
/// and they are what a policy can usefully name. Walking the whole tree
/// would add thousands of paths nobody would ever select.
#[must_use]
pub fn cgroups(sys_root: &FsPath) -> Vec<String> {
    let root = sys_root.join("fs/cgroup");
    let mut out = Vec::new();
    for slice in ["system.slice", "user.slice"] {
        let Ok(entries) = std::fs::read_dir(root.join(slice)) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            if !e.path().is_dir() {
                continue;
            }
            out.push(format!("{slice}/{name}"));
            // One level deeper covers a user's own units, which is where
            // a desktop application actually lives.
            if let Ok(inner) = std::fs::read_dir(e.path()) {
                for i in inner.flatten() {
                    if i.path().is_dir()
                        && let Ok(n) = i.file_name().into_string()
                    {
                        out.push(format!("{slice}/{name}/{n}"));
                    }
                }
            }
        }
    }
    out.sort();
    out
}

/// `TransPort` and `DNSPort` from a torrc, if they are set.
///
/// Only an explicit setting counts. Tor does not open these by default,
/// so reporting a default here would produce a ruleset that redirects to
/// a closed port — every connection failing, with nothing to say why.
#[must_use]
pub fn tor_ports(torrc: &FsPath) -> (Option<u16>, Option<u16>) {
    let Ok(text) = std::fs::read_to_string(torrc) else {
        return (None, None);
    };
    let find = |key: &str| -> Option<u16> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let rest = l.strip_prefix(key)?;
                if !rest.starts_with(char::is_whitespace) {
                    return None;
                }
                // "9040", "127.0.0.1:9040", "0.0.0.0:9040 IsolateDestAddr"
                let val = rest.split_whitespace().next()?;
                val.rsplit(':').next()?.parse().ok()
            })
    };
    (find("TransPort"), find("DNSPort"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_ports_are_read_in_every_spelling_torrc_allows() {
        let dir = std::env::temp_dir().join(format!("tl-torrc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("torrc");
        std::fs::write(
            &f,
            "# TransPort 1111\n\
             SocksPort 9050\n\
             TransPort 127.0.0.1:9040 IsolateDestAddr\n\
             DNSPort 9053\n",
        )
        .unwrap();
        assert_eq!(tor_ports(&f), (Some(9040), Some(9053)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unset_port_is_none_and_never_a_default() {
        // Tor does not open TransPort unless told to. Returning 9040 here
        // would generate a redirect to a closed port: every connection
        // fails, and the ruleset looks correct.
        let dir = std::env::temp_dir().join(format!("tl-torrc2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("torrc");
        std::fs::write(&f, "SocksPort 9050\n# DNSPort 9053\n").unwrap();
        assert_eq!(tor_ports(&f), (None, None));
        assert_eq!(tor_ports(FsPath::new("/nonexistent/torrc")), (None, None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_that_merely_starts_the_same_is_not_matched() {
        let dir = std::env::temp_dir().join(format!("tl-torrc3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("torrc");
        std::fs::write(&f, "TransPortFoo 1234\nDNSPortWhatever 5678\n").unwrap();
        assert_eq!(tor_ports(&f), (None, None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_v4_mapped_peer_is_written_the_way_nftables_will_see_it() {
        // An inbound SSH session over a dual-stack listener shows as
        // ::ffff:a.b.c.d. An `ip daddr` rule never matches that spelling,
        // so the exclusion protecting that session would silently miss.
        assert_eq!(normalise("::ffff:198.51.100.7"), "198.51.100.7");
        assert_eq!(normalise("198.51.100.7"), "198.51.100.7");
        assert_eq!(normalise("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn a_daemons_uid_comes_from_the_process_not_from_a_socket_it_inherited() {
        // Reading our own status proves the parse; the point of the rule
        // is that a socket's uid and a process's uid are different facts
        // and only one of them predicts the next socket.
        let me = std::process::id();
        let uid = effective_uid(FsPath::new("/proc"), me).expect("own status readable");
        // Safe: getuid cannot fail and has no side effects.
        let expected = unsafe { libc_geteuid() };
        assert_eq!(uid, expected, "parsed Uid: line must be the effective uid");
        assert_eq!(effective_uid(FsPath::new("/proc"), 0), None, "pid 0 has no status");
    }

    /// `geteuid(2)` without pulling in a crate for one number.
    unsafe fn libc_geteuid() -> u32 {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() }
    }

    #[test]
    fn uid_min_is_read_from_the_host_not_assumed() {
        let dir = std::env::temp_dir().join(format!("tl-defs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("login.defs");
        std::fs::write(&f, "# UID_MIN 500\nUID_MAX 60000\nUID_MIN 2000\n").unwrap();
        assert_eq!(uid_min(&f), 2000);
        assert_eq!(uid_min(FsPath::new("/nonexistent")), 1000, "documented fallback");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_admin_candidate_carries_the_evidence_for_its_verdict() {
        // The verdict is a judgement, so it must never appear without its
        // basis -- a person is being asked to confirm it.
        for c in admin_candidates(FsPath::new("/proc")) {
            assert!(!c.evidence.is_empty(), "{c:?}");
            assert!(!c.peer.is_empty());
            if c.likely {
                assert!(c.evidence.contains("after authentication"), "{c:?}");
            } else {
                assert!(
                    c.evidence.contains("unauthenticated") || c.evidence.contains("not readable"),
                    "{c:?}"
                );
            }
        }
    }

    #[test]
    fn a_scan_on_the_ssh_port_cannot_get_itself_excluded() {
        // Someone knocking on port 22 leaves a SYN-RECV row. If that
        // counted as "a session administering this host", any stranger
        // could pick an address to exempt from the policy by scanning.
        // This host had a scanner's address in the list alongside the
        // real one.
        let flows = snapshot::collect(FsPath::new("/proc"));
        let ports = EphemeralPorts::load(FsPath::new("/proc"));
        let listeners = Listeners::from_flows(&flows, ports);
        let half_open = flows
            .iter()
            .filter(|f| f.socket.state == State::SynRecv)
            .count();
        let h = host(
            FsPath::new("/proc"),
            FsPath::new("/sys"),
            FsPath::new("/etc/tor/torrc"),
        );
        for p in &h.admin_peers {
            let live = flows.iter().any(|f| {
                f.socket.state == State::Established
                    && f.direction(&listeners) == Direction::Inbound
                    && normalise(&f.socket.remote_addr.to_string()) == *p
            });
            assert!(live, "{p} is not an established session ({half_open} half-open rows present)");
        }
    }

    #[test]
    fn reverse_path_filtering_is_read_for_every_interface_including_all() {
        // `all` matters as much as the named interface: the kernel takes
        // the maximum of the two, so all=1 makes everything strict and a
        // check that read only the named interface would report a host as
        // safe when every reply will be dropped.
        let rp = rp_filter(FsPath::new("/proc"));
        assert!(!rp.is_empty(), "no interfaces read");
        assert!(rp.iter().any(|(n, _)| n == "all"), "{rp:?}");
        assert!(rp.iter().any(|(n, _)| n == "lo"), "{rp:?}");
        assert!(rp.iter().all(|(_, v)| *v <= 2), "{rp:?}");
    }

    #[test]
    fn the_live_host_has_interfaces_and_cgroups() {
        // Not a fixture: if these come back empty on a running Linux
        // machine the probe is broken, whatever the other tests say.
        let ifs = interfaces(FsPath::new("/sys"));
        assert!(ifs.iter().any(|i| i == "lo"), "{ifs:?}");
        let cg = cgroups(FsPath::new("/sys"));
        assert!(cg.iter().any(|c| c.starts_with("system.slice/")), "{}", cg.len());
    }
}
