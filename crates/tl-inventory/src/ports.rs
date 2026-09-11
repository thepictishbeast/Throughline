//! The local port range, read from the kernel rather than assumed.
//!
//! A bound socket with no peer looks identical whether it is a server
//! waiting for requests or a client halfway through a UDP query. On this
//! host that is 11 real services against 205 client sockets, so getting
//! it wrong either buries the services or invents two hundred of them.
//!
//! What separates them is the ephemeral range — the ports the kernel
//! hands out for outgoing connections. It is tunable per host, so the
//! kernel is asked instead of a constant being written down here.

use std::path::Path;

/// The range the kernel assigns to outgoing connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralPorts {
    pub low: u16,
    pub high: u16,
}

impl Default for EphemeralPorts {
    /// The kernel's own compiled-in default, used only when
    /// `ip_local_port_range` cannot be read.
    ///
    /// This is a fallback for an unreadable file, not a substitute for
    /// asking: a host that has tuned the range and cannot be read will be
    /// judged by a range it does not use.
    fn default() -> Self {
        Self { low: 32768, high: 60999 }
    }
}

impl EphemeralPorts {
    /// Read `/proc/sys/net/ipv4/ip_local_port_range`: two integers,
    /// whitespace-separated.
    #[must_use]
    pub fn load(proc_root: &Path) -> Self {
        let path = proc_root.join("sys/net/ipv4/ip_local_port_range");
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| Self::parse(&t))
            .unwrap_or_default()
    }

    /// Parse the file's contents. `None` when it is not two ordered
    /// numbers, so the caller falls back rather than adopting nonsense.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut f = text.split_whitespace();
        let low: u16 = f.next()?.parse().ok()?;
        let high: u16 = f.next()?.parse().ok()?;
        (low <= high).then_some(Self { low, high })
    }

    /// Whether the kernel would hand this port out for an outgoing
    /// connection.
    #[must_use]
    pub const fn is_ephemeral(&self, port: u16) -> bool {
        port >= self.low && port <= self.high
    }

    /// Whether a port looks like one something deliberately bound to
    /// serve on. Port 0 is not a port.
    #[must_use]
    pub const fn is_service_port(&self, port: u16) -> bool {
        port != 0 && !self.is_ephemeral(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernels_range_is_read_not_assumed() {
        // Exact format of /proc/sys/net/ipv4/ip_local_port_range: two
        // numbers separated by a tab.
        let p = EphemeralPorts::parse("32768\t60999\n").unwrap();
        assert_eq!(p, EphemeralPorts { low: 32768, high: 60999 });
        assert!(p.is_ephemeral(41000));
        assert!(!p.is_ephemeral(443));
    }

    #[test]
    fn a_host_that_tuned_its_range_is_judged_by_that_range() {
        // A host set to start at 10000 really does hand out 15000 for
        // outgoing connections, so 15000 must not read as a service.
        let p = EphemeralPorts::parse("10000 65535").unwrap();
        assert!(p.is_ephemeral(15000));
        assert!(!p.is_service_port(15000));
        assert!(p.is_service_port(9050));
    }

    #[test]
    fn a_service_port_is_outside_the_range_and_is_not_zero() {
        let p = EphemeralPorts::default();
        assert!(p.is_service_port(53));
        assert!(p.is_service_port(9050));
        assert!(!p.is_service_port(0), "port 0 is not a port");
        assert!(!p.is_service_port(45123));
    }

    #[test]
    fn junk_falls_back_rather_than_adopting_nonsense() {
        for bad in ["", "32768", "abc def", "60999 32768", "x\ty"] {
            assert_eq!(EphemeralPorts::parse(bad), None, "{bad:?}");
        }
        let p = EphemeralPorts::load(Path::new("/nonexistent"));
        assert_eq!(p, EphemeralPorts::default());
    }
}
