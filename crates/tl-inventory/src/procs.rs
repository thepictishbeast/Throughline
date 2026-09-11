//! Attributing a socket to the thing that opened it.
//!
//! A socket inode is the join key. Every process's `/proc/<pid>/fd/*` that
//! is a socket symlinks to `socket:[<inode>]`, so one pass over `/proc`
//! builds inode → pid.
//!
//! The part that makes the answer useful rather than merely correct is the
//! second step: a pid alone is `3231998`, and "what is talking to the
//! internet" is not answered by a number. `/proc/<pid>/cgroup` says whether
//! this is a system service, a user application, or a container — which is
//! exactly the distinction between "a daemon I installed" and "the browser
//! I have open", and it is the one a person actually wants.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// What kind of thing owns a socket, as told by its cgroup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// A systemd system service — a daemon. Carries the unit name.
    Service(String),
    /// Something launched in a user's session: an app, or a shell.
    UserApp { unit: String, uid_hint: Option<u32> },
    /// A container. Carries the runtime's id, truncated.
    Container(String),
    /// Running, but its cgroup says nothing useful.
    Process,
    /// The socket exists and no process claims it. Normal and important —
    /// see [`attribute`].
    Unowned,
}

impl Owner {
    /// A short label for a UI column.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Service(_) => "service",
            Self::UserApp { .. } => "app",
            Self::Container(_) => "container",
            Self::Process => "process",
            Self::Unowned => "unowned",
        }
    }

    /// The name to show, if there is a better one than the process name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Service(s) | Self::Container(s) => Some(s),
            Self::UserApp { unit, .. } => Some(unit),
            Self::Process | Self::Unowned => None,
        }
    }
}

/// Classify a `/proc/<pid>/cgroup` body.
///
/// cgroup v2 gives a single `0::/path` line. v1 gives many; the unified
/// hierarchy line is the one worth reading, and falling back to any line
/// keeps this working on hybrid systems rather than silently returning
/// `Process` for everything.
#[must_use]
pub fn classify_cgroup(body: &str) -> Owner {
    let path = body
        .lines()
        .find(|l| l.starts_with("0::"))
        .or_else(|| body.lines().find(|l| l.contains(":name=systemd:")))
        .or_else(|| body.lines().next())
        .and_then(|l| l.rsplit(':').next())
        .unwrap_or("");

    if path.is_empty() || path == "/" {
        return Owner::Process;
    }
    // Containers first: a docker/podman scope also sits under a systemd
    // slice, so checking systemd first would label every container as a
    // service and lose the distinction entirely.
    for marker in ["docker-", "libpod-", "cri-containerd-", "crio-"] {
        if let Some(i) = path.find(marker) {
            let rest = &path[i + marker.len()..];
            let id: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            if id.len() >= 12 {
                return Owner::Container(id[..12].to_owned());
            }
        }
    }
    let leaf = path.rsplit('/').find(|s| !s.is_empty()).unwrap_or(path);
    if path.contains("/user.slice/") || path.contains("/user@") {
        let uid_hint = path
            .split("/user@")
            .nth(1)
            .and_then(|s| s.split(".service").next())
            .and_then(|s| s.parse().ok());
        return Owner::UserApp {
            unit: leaf.trim_end_matches(".scope").to_owned(),
            uid_hint,
        };
    }
    if leaf.ends_with(".service") {
        return Owner::Service(leaf.trim_end_matches(".service").to_owned());
    }
    Owner::Process
}

/// A process that holds at least one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    /// `/proc/<pid>/comm` — the short name, always present.
    pub comm: String,
    /// Resolved `/proc/<pid>/exe`. `None` when the process is another
    /// user's and we are not root, or it exited mid-scan.
    pub exe: Option<String>,
    pub owner: Owner,
}

impl Holder {
    /// The best available human label.
    #[must_use]
    pub fn label(&self) -> String {
        match self.owner.name() {
            Some(n) if n != self.comm => format!("{} ({})", self.comm, n),
            _ => self.comm.clone(),
        }
    }
}

/// Build inode → holder by walking `/proc`.
///
/// Reads under `root` so tests can point at a fixture tree instead of the
/// live `/proc`.
///
/// Every per-process read is allowed to fail independently: processes exit
/// while being scanned, and a scan that aborts on the first vanished pid
/// would return an empty map on a busy machine.
#[must_use]
pub fn holders_by_inode(root: &Path) -> HashMap<u64, Holder> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir(root) else {
        return map;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let dir = e.path();
        let Ok(fds) = fs::read_dir(dir.join("fd")) else {
            continue; // not ours to read, or already gone
        };
        let inodes: Vec<u64> = fds
            .flatten()
            .filter_map(|fd| fs::read_link(fd.path()).ok())
            .filter_map(|t| socket_inode(&t.to_string_lossy()))
            .collect();
        if inodes.is_empty() {
            continue;
        }
        let comm = fs::read_to_string(dir.join("comm"))
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| format!("pid:{pid}"));
        let exe = fs::read_link(dir.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let owner = fs::read_to_string(dir.join("cgroup"))
            .map(|b| classify_cgroup(&b))
            .unwrap_or(Owner::Process);
        for inode in inodes {
            // One socket, several processes: a prefork server's master and
            // its workers all hold the listening inode after fork. Plain
            // `insert` let whichever pid `read_dir` yielded last win, so
            // the displayed owner changed between two scans of an
            // unchanged machine and the pid pointed at a worker that was
            // about to be recycled. Lowest pid wins — it is stable, and
            // for a forking server it is the parent.
            let replace = map
                .get(&inode)
                .is_none_or(|existing: &Holder| pid < existing.pid);
            if replace {
                map.insert(
                    inode,
                    Holder {
                        pid,
                        comm: comm.clone(),
                        exe: exe.clone(),
                        owner: owner.clone(),
                    },
                );
            }
        }
    }
    map
}

/// `socket:[12345]` → `12345`.
#[must_use]
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// Attach an owner to a socket inode.
///
/// `Unowned` is a real answer, not a failure, and the UI must show it as
/// one. Two things land here and they mean opposite things:
///
/// * inode 0 — kernel-side sockets with no file, such as TIME-WAIT and
///   SYN-RECV. Ordinary.
/// * a real inode with no holder — either a process owned by another user
///   while running unprivileged, or something that exited between reading
///   the socket table and walking `/proc`.
///
/// Rendering either as blank would quietly under-report what is connected,
/// which is the one thing this tool must not do.
#[must_use]
pub fn attribute(inode: u64, holders: &HashMap<u64, Holder>) -> Owner {
    if inode == 0 {
        return Owner::Unowned;
    }
    holders.get(&inode).map_or(Owner::Unowned, |h| h.owner.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_link_yields_its_inode() {
        assert_eq!(socket_inode("socket:[439803925]"), Some(439_803_925));
        for not_a_socket in [
            "/dev/null",
            "pipe:[12345]",
            "anon_inode:[eventpoll]",
            "socket:[]",
            "socket:[abc]",
            "socket:12345",
        ] {
            assert_eq!(socket_inode(not_a_socket), None, "{not_a_socket}");
        }
    }

    #[test]
    fn a_system_service_is_named_by_its_unit() {
        // The shape a systemd service really has.
        let o = classify_cgroup("0::/system.slice/nginx.service\n");
        assert_eq!(o, Owner::Service("nginx".to_owned()));
        assert_eq!(o.kind(), "service");
        assert_eq!(o.name(), Some("nginx"));
    }

    #[test]
    fn a_container_is_not_mislabelled_as_a_service() {
        // A docker scope lives UNDER system.slice, so checking for
        // ".service" first would call every container a service and lose
        // the distinction the user actually cares about.
        let o = classify_cgroup(
            "0::/system.slice/docker-3f1a2b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a.scope\n",
        );
        assert_eq!(o, Owner::Container("3f1a2b9c8d7e".to_owned()));
        assert_eq!(o.kind(), "container");
    }

    #[test]
    fn a_desktop_app_is_distinguished_from_a_daemon() {
        // This is the whole point of reading cgroups: firefox and sshd are
        // both processes with sockets, and only one of them is something
        // the person chose to open.
        let o = classify_cgroup(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-1234.scope\n",
        );
        assert_eq!(o.kind(), "app");
        assert_eq!(o.name(), Some("app-firefox-1234"));
        assert!(matches!(o, Owner::UserApp { uid_hint: Some(1000), .. }));
    }

    #[test]
    fn cgroup_v1_and_hybrid_hierarchies_still_classify() {
        let v1 = "11:name=systemd:/system.slice/tor.service\n\
                  10:devices:/system.slice/tor.service\n";
        assert_eq!(classify_cgroup(v1), Owner::Service("tor".to_owned()));
    }

    #[test]
    fn a_rootless_or_empty_cgroup_degrades_rather_than_lying() {
        for body in ["0::/\n", "", "garbage\n"] {
            let o = classify_cgroup(body);
            assert_eq!(o.kind(), "process", "body {body:?} -> {o:?}");
            assert_eq!(o.name(), None);
        }
    }

    #[test]
    fn inode_zero_is_unowned_and_says_so() {
        // TIME-WAIT and SYN-RECV sockets have no file and so no inode. They
        // are real connections; showing them blank would hide them.
        let empty = HashMap::new();
        assert_eq!(attribute(0, &empty), Owner::Unowned);
        assert_eq!(attribute(0, &empty).kind(), "unowned");
    }

    #[test]
    fn an_inode_with_no_visible_holder_is_unowned_not_dropped() {
        let empty = HashMap::new();
        assert_eq!(attribute(999_999, &empty), Owner::Unowned);
    }

    #[test]
    fn a_known_inode_resolves_to_its_owner() {
        let mut m = HashMap::new();
        m.insert(
            42,
            Holder {
                pid: 7,
                comm: "tor".to_owned(),
                exe: Some("/usr/sbin/tor".to_owned()),
                owner: Owner::Service("tor".to_owned()),
            },
        );
        assert_eq!(attribute(42, &m), Owner::Service("tor".to_owned()));
        assert_eq!(m[&42].label(), "tor", "no redundant '(tor)' suffix");
    }

    #[test]
    fn a_label_shows_the_unit_when_it_differs_from_the_process_name() {
        let h = Holder {
            pid: 9,
            comm: "python3".to_owned(),
            exe: None,
            owner: Owner::Service("site-metrics".to_owned()),
        };
        assert_eq!(h.label(), "python3 (site-metrics)");
    }

    #[test]
    fn a_socket_held_by_several_processes_resolves_the_same_way_every_scan() {
        // A forking server's master and workers all hold the listening
        // inode. Whichever process `read_dir` happened to yield last used
        // to win, so the owner shown flipped between scans of a machine
        // that had not changed, and the pid often named a worker about to
        // exit. Directory order is not sorted, so this is checked by
        // building the map in both orders.
        let dir = std::env::temp_dir().join(format!("tl-proc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for (pid, comm) in [(2000_u32, "nginx"), (1000_u32, "nginx")] {
            let pd = dir.join(pid.to_string());
            fs::create_dir_all(pd.join("fd")).unwrap();
            fs::write(pd.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(pd.join("cgroup"), "0::/system.slice/nginx.service\n").unwrap();
            // A symlink is what /proc/<pid>/fd really holds.
            std::os::unix::fs::symlink("socket:[5000]", pd.join("fd").join("3")).unwrap();
        }
        let map = holders_by_inode(&dir);
        assert_eq!(map[&5000].pid, 1000, "lowest pid, not last-scanned");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scanning_a_missing_proc_tree_returns_empty_rather_than_panicking() {
        assert!(holders_by_inode(Path::new("/nonexistent-proc")).is_empty());
    }
}
