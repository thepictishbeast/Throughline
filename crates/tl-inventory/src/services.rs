//! Port names, taken from the machine rather than from a list we wrote.
//!
//! A built-in table of "well-known" ports is wrong on two counts: it only
//! ever covers the software whoever wrote it happened to think of, and it
//! is confidently wrong when a host uses a port for something else. Every
//! Unix already ships `/etc/services`, maintained by the distribution, so
//! that is the source.
//!
//! It is a hint, never an identity. `/etc/services` says what a port is
//! *conventionally* for; the process actually holding the socket is the
//! truth, and that is what [`crate::procs`] supplies. Where the two
//! disagree, the process wins and the disagreement is itself worth
//! showing.

use std::collections::HashMap;
use std::path::Path;

/// Port + transport → the name the system gives it.
#[derive(Debug, Default, Clone)]
pub struct ServiceNames {
    by_port: HashMap<(u16, Proto), String>,
}

/// The transport half of an `/etc/services` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl ServiceNames {
    /// Read a services file. A missing or unreadable file yields an empty
    /// table rather than an error: a name is a nicety, and a host without
    /// `/etc/services` (a minimal container, say) must still work.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .map(|t| Self::parse(&t))
            .unwrap_or_default()
    }

    /// Parse `/etc/services` text.
    ///
    /// The format is `name port/proto [aliases...]` with `#` comments. The
    /// first entry for a port wins: the canonical name is the first field
    /// on the first line, and later lines are aliases of it.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut by_port = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut f = line.split_whitespace();
            let (Some(name), Some(portproto)) = (f.next(), f.next()) else {
                continue;
            };
            let mut parts = portproto.split('/');
            let (Some(port), Some(proto)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else { continue };
            let proto = match proto {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => continue, // sctp, ddp and friends: not sockets we read
            };
            by_port.entry((port, proto)).or_insert_with(|| name.to_owned());
        }
        Self { by_port }
    }

    /// The system's name for a port, if it has one.
    #[must_use]
    pub fn name(&self, port: u16, proto: Proto) -> Option<&str> {
        self.by_port.get(&(port, proto)).map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shape taken from a real /etc/services, including the comment styles
    // and the alias lines that must NOT overwrite the canonical name.
    const SAMPLE: &str = "\
# Network services, Internet style
ssh             22/tcp                          # SSH Remote Login Protocol
ssh             22/udp
domain          53/tcp
domain          53/udp
http            80/tcp          www             # WorldWideWeb HTTP
https          443/tcp
nntp           119/tcp         readnews untp    # USENET
tor-socks     9050/tcp
discard          9/sctp
malformed
noport         abc/tcp
";

    #[test]
    fn the_system_supplies_the_name_for_a_port() {
        let s = ServiceNames::parse(SAMPLE);
        assert_eq!(s.name(22, Proto::Tcp), Some("ssh"));
        assert_eq!(s.name(443, Proto::Tcp), Some("https"));
        assert_eq!(s.name(9050, Proto::Tcp), Some("tor-socks"));
    }

    #[test]
    fn tcp_and_udp_are_separate_namespaces() {
        // 53 is domain on both here, but nothing guarantees a port means
        // the same thing on each transport, so they are keyed apart.
        let s = ServiceNames::parse("domain 53/udp\nsomethingelse 53/tcp\n");
        assert_eq!(s.name(53, Proto::Udp), Some("domain"));
        assert_eq!(s.name(53, Proto::Tcp), Some("somethingelse"));
    }

    #[test]
    fn an_alias_line_does_not_displace_the_canonical_name() {
        let s = ServiceNames::parse(SAMPLE);
        assert_eq!(s.name(80, Proto::Tcp), Some("http"), "not the 'www' alias");
        assert_eq!(s.name(119, Proto::Tcp), Some("nntp"));
    }

    #[test]
    fn junk_lines_are_skipped_rather_than_poisoning_the_table() {
        let s = ServiceNames::parse(SAMPLE);
        assert_eq!(s.name(9, Proto::Tcp), None, "sctp entry is not a socket");
        assert_eq!(s.name(0, Proto::Tcp), None);
        // Everything well-formed in SAMPLE is still present.
        assert!(s.len() >= 7, "{} entries", s.len());
    }

    #[test]
    fn an_unknown_port_has_no_name_rather_than_a_guess() {
        let s = ServiceNames::parse(SAMPLE);
        assert_eq!(s.name(48123, Proto::Tcp), None);
    }

    #[test]
    fn a_missing_services_file_is_an_empty_table_not_a_failure() {
        let s = ServiceNames::load(Path::new("/nonexistent/etc/services"));
        assert!(s.is_empty());
        assert_eq!(s.name(22, Proto::Tcp), None);
    }
}
