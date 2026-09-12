//! Whether this process can see the machine at all.
//!
//! Everything else in this crate reports what it managed to read. Nothing
//! asks whether reading worked — and on a host that withholds the socket
//! tables, "nothing is connected" and "I am not allowed to look" produce
//! byte-identical output.
//!
//! Found by running it: under Termux on Android, with SSH sessions open,
//! the view was empty. Android returns `/proc/net/tcp` header-only to an
//! unprivileged process — which is why `ss` and `netstat` show nothing
//! there either. The parser was correct, the attribution was correct, and
//! the screen said the machine had no connections.
//!
//! That is the one failure this crate's own documentation forbids: a view
//! which silently drops rows is worse than no view, because it is
//! trusted. So before believing an empty result, check the instrument.
//!
//! The check is a comparison, not a guess: `/proc/net/dev` is readable
//! when the socket tables are not, and it counts packets. Interfaces that
//! have carried traffic, with no sockets to show for it, means the tables
//! are being withheld.

use std::path::Path;

/// How much of the machine this process can actually see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sight {
    /// Sockets readable, and other processes' file descriptors too.
    Full,
    /// Sockets readable, but no process other than ours can be inspected,
    /// so most connections will be attributed to nobody.
    OwnProcessOnly,
    /// The socket tables exist and report nothing, while the interfaces
    /// say otherwise. The kernel is withholding them.
    TablesWithheld,
    /// There is no `/proc/net` to read.
    NoProcNet,
}

impl Sight {
    /// Whether an empty result can be believed.
    #[must_use]
    pub const fn can_be_trusted(self) -> bool {
        matches!(self, Self::Full | Self::OwnProcessOnly)
    }
}

/// What the instrument check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visibility {
    pub sight: Sight,
    /// The measurement that settled it, in words.
    pub evidence: String,
    /// What a person could do about it, when there is something.
    pub remedy: Option<String>,
    /// Android restricts this differently and the remedy differs with it.
    pub android: bool,
}

impl Visibility {
    /// One sentence for a status line.
    #[must_use]
    pub fn headline(&self) -> String {
        match self.sight {
            Sight::Full => "reading this machine".to_owned(),
            Sight::OwnProcessOnly => {
                "can see connections, but not which programs own them".to_owned()
            }
            Sight::TablesWithheld => {
                "CANNOT SEE — this system is withholding the socket tables".to_owned()
            }
            Sight::NoProcNet => "CANNOT SEE — there is no /proc/net on this system".to_owned(),
        }
    }
}

/// Interfaces that have carried packets, from `/proc/net/dev`.
///
/// Loopback is excluded: it is always busy and says nothing about whether
/// the machine has been on a network.
#[must_use]
pub fn interfaces_with_traffic(proc_root: &Path) -> usize {
    let Ok(text) = std::fs::read_to_string(proc_root.join("net/dev")) else {
        return 0;
    };
    text.lines()
        .skip(2) // two header lines
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let name = name.trim();
            if name == "lo" {
                return None;
            }
            let rx: u64 = rest.split_whitespace().next()?.parse().ok()?;
            let tx: u64 = rest.split_whitespace().nth(8)?.parse().ok()?;
            (rx > 0 || tx > 0).then_some(())
        })
        .count()
}

/// Whether this looks like Android.
///
/// Worth naming, because the remedy there is not "run with sudo" and a
/// person told to do that will conclude the tool is broken.
#[must_use]
pub fn is_android(proc_root: &Path) -> bool {
    std::fs::read_to_string(proc_root.join("version"))
        .is_ok_and(|v| v.to_ascii_lowercase().contains("android"))
        || Path::new("/system/build.prop").exists()
        || std::env::var_os("TERMUX_VERSION").is_some()
}

/// Check the instrument before trusting what it reports.
///
/// `socket_rows` is how many rows the socket tables actually yielded, and
/// `attributable` how many of them could be traced to a process. Passing
/// them in keeps this function free of the parsing it is checking.
#[must_use]
pub fn assess(proc_root: &Path, socket_rows: usize, attributable: usize) -> Visibility {
    let android = is_android(proc_root);
    let remedy_privileged = Some(if android {
        "Android does not expose other processes' sockets to an unprivileged app. \
         A rooted device can, with su; otherwise this machine cannot be read from here."
            .to_owned()
    } else {
        "run it as root — most sockets on a machine belong to other users".to_owned()
    });

    if !proc_root.join("net/tcp").exists() && !proc_root.join("net/tcp6").exists() {
        return Visibility {
            sight: Sight::NoProcNet,
            evidence: format!("{}/net/tcp and tcp6 do not exist", proc_root.display()),
            remedy: None,
            android,
        };
    }

    let busy = interfaces_with_traffic(proc_root);
    if socket_rows == 0 && busy > 0 {
        return Visibility {
            sight: Sight::TablesWithheld,
            evidence: format!(
                "the socket tables yielded no rows, while {busy} interface(s) in \
                 /proc/net/dev have carried packets. A machine that has moved traffic \
                 and reports no sockets is not idle — it is not telling us."
            ),
            remedy: remedy_privileged,
            android,
        };
    }

    if socket_rows > 0 && attributable == 0 {
        return Visibility {
            sight: Sight::OwnProcessOnly,
            evidence: format!(
                "{socket_rows} socket(s) readable, but none could be traced to a \
                 process: no /proc/<pid>/fd outside this process is readable."
            ),
            remedy: remedy_privileged,
            android,
        };
    }

    Visibility {
        sight: Sight::Full,
        evidence: format!("{socket_rows} socket(s), {attributable} attributed to a process"),
        remedy: None,
        android,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree(name: &str, dev: &str, with_tcp: bool) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tl-vis-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("net")).unwrap();
        fs::write(d.join("net/dev"), dev).unwrap();
        if with_tcp {
            fs::write(d.join("net/tcp"), "  sl  local_address rem_address   st\n").unwrap();
        }
        d
    }

    /// The real shape of /proc/net/dev: two header lines, then
    /// `iface: rx_bytes rx_packets ... tx_bytes ...`.
    const BUSY: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo: 9999999   12345    0    0    0     0          0         0  9999999   12345
  eth0: 4823991    9021    0    0    0     0          0         0  1922233    7654
";
    const IDLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo:       0       0    0    0    0     0          0         0        0       0
  eth0:       0       0    0    0    0     0          0         0        0       0
";

    #[test]
    fn an_empty_table_on_a_machine_that_has_moved_traffic_is_a_refusal_not_a_fact() {
        // This is the Termux case. Android hands back a header-only
        // socket table, the parser correctly finds nothing, and the
        // screen says the machine has no connections.
        let d = tree("withheld", BUSY, true);
        let v = assess(&d, 0, 0);
        assert_eq!(v.sight, Sight::TablesWithheld);
        assert!(!v.sight.can_be_trusted());
        assert!(v.evidence.contains("carried packets"), "{}", v.evidence);
        assert!(v.headline().starts_with("CANNOT SEE"));
        assert!(v.remedy.is_some());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn an_empty_table_on_a_machine_that_has_moved_nothing_is_believed() {
        // The mirror case, and the reason the check is a comparison
        // rather than a guess: a freshly booted host with no traffic
        // really does have no sockets, and must not be called blind.
        let d = tree("idle", IDLE, true);
        let v = assess(&d, 0, 0);
        assert_eq!(v.sight, Sight::Full);
        assert!(v.sight.can_be_trusted());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn seeing_sockets_but_owning_none_of_them_is_its_own_state() {
        // Running unprivileged on an ordinary Linux box: the tables are
        // readable, but /proc/<pid>/fd is not, so everything is
        // "unattributed". That is worth saying out loud rather than
        // filling a column with the same word.
        let d = tree("ownonly", BUSY, true);
        let v = assess(&d, 42, 0);
        assert_eq!(v.sight, Sight::OwnProcessOnly);
        assert!(v.sight.can_be_trusted(), "the connections are real");
        assert!(v.headline().contains("not which programs"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn no_proc_net_at_all_is_distinguished_from_being_refused() {
        let d = tree("noproc", BUSY, false);
        let v = assess(&d, 0, 0);
        assert_eq!(v.sight, Sight::NoProcNet);
        assert!(v.remedy.is_none(), "root will not conjure /proc/net");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn loopback_alone_does_not_count_as_having_been_on_a_network() {
        // lo is always busy. Counting it would make every machine look
        // like it was withholding.
        let lo_only = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo: 9999999   12345    0    0    0     0          0         0  9999999   12345
";
        let d = tree("loonly", lo_only, true);
        assert_eq!(interfaces_with_traffic(&d), 0);
        assert_eq!(assess(&d, 0, 0).sight, Sight::Full);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_android_remedy_is_not_the_linux_one() {
        // Telling an Android user to "run as root" when they cannot is
        // how a person concludes the tool is broken.
        let d = tree("droid", BUSY, true);
        fs::write(d.join("version"), "Linux version 5.10.0-android13-4\n").unwrap();
        let v = assess(&d, 0, 0);
        assert!(v.android);
        assert!(v.remedy.as_ref().unwrap().contains("Android"), "{:?}", v.remedy);
        assert!(!v.remedy.as_ref().unwrap().contains("run it as root"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn this_machine_can_see_itself() {
        // Not a fixture: if the live host reports anything but Full while
        // running as root, the check itself is wrong.
        let flows = crate::snapshot::collect(Path::new("/proc"));
        let attributed = flows.iter().filter(|f| f.holder.is_some()).count();
        let v = assess(Path::new("/proc"), flows.len(), attributed);
        if unsafe { geteuid() } == 0 {
            assert_eq!(v.sight, Sight::Full, "{}", v.evidence);
        }
        assert!(!v.headline().is_empty());
    }

    unsafe extern "C" {
        fn geteuid() -> u32;
    }
}
