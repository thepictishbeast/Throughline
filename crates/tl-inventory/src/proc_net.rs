//! Parsing `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! This is the same source `ss` and `lsof` read. It is parsed here rather
//! than shelled out to, for two reasons that matter for a tool whose whole
//! job is to be believed:
//!
//! 1. `ss` output is a human format that changes between releases. A parser
//!    for it is a parser for a moving target, and when it drifts the failure
//!    is a *missing row* — a connection you are not shown, on a screen whose
//!    entire claim is that it shows everything.
//! 2. Shelling out means the tool's answer depends on a binary somewhere on
//!    `$PATH`. For this program that is a supply-chain question, not a
//!    convenience one.
//!
//! Everything here is a pure function over a `&str`, so the tests exercise
//! real kernel output captured as fixtures rather than whatever the machine
//! running the suite happens to be doing.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which `/proc/net` table a row came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Proto {
    /// The `/proc/net` file this protocol lives in.
    #[must_use]
    pub const fn proc_file(self) -> &'static str {
        match self {
            Self::Tcp => "/proc/net/tcp",
            Self::Tcp6 => "/proc/net/tcp6",
            Self::Udp => "/proc/net/udp",
            Self::Udp6 => "/proc/net/udp6",
        }
    }

    /// True for the v6 tables, which encode addresses as 32 hex chars.
    #[must_use]
    pub const fn is_v6(self) -> bool {
        matches!(self, Self::Tcp6 | Self::Udp6)
    }

    /// The transport, for looking a port up in `/etc/services`.
    #[must_use]
    pub const fn transport(self) -> crate::services::Proto {
        match self {
            Self::Tcp | Self::Tcp6 => crate::services::Proto::Tcp,
            Self::Udp | Self::Udp6 => crate::services::Proto::Udp,
        }
    }

    /// Human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tcp6 => "tcp6",
            Self::Udp => "udp",
            Self::Udp6 => "udp6",
        }
    }
}

/// TCP connection state, as the kernel's `st` column.
///
/// UDP rows carry the same column; only `Established` (1) and `Close` (7)
/// are meaningful there, which is why this is not a TCP-only type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown(u8),
}

impl State {
    #[must_use]
    const fn from_hex(v: u8) -> Self {
        match v {
            0x01 => Self::Established,
            0x02 => Self::SynSent,
            0x03 => Self::SynRecv,
            0x04 => Self::FinWait1,
            0x05 => Self::FinWait2,
            0x06 => Self::TimeWait,
            0x07 => Self::Close,
            0x08 => Self::CloseWait,
            0x09 => Self::LastAck,
            0x0A => Self::Listen,
            0x0B => Self::Closing,
            other => Self::Unknown(other),
        }
    }

    /// True when this socket represents traffic actually leaving or
    /// arriving, rather than a listener or a corpse.
    ///
    /// `TimeWait` counts: it is a connection that just happened, and a view
    /// that hides it loses the last thing an app did before you looked.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Established
                | Self::SynSent
                | Self::SynRecv
                | Self::FinWait1
                | Self::FinWait2
                | Self::TimeWait
                | Self::CloseWait
                | Self::LastAck
                | Self::Closing
        )
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Established => "ESTAB",
            Self::SynSent => "SYN-SENT",
            Self::SynRecv => "SYN-RECV",
            Self::FinWait1 => "FIN-WAIT-1",
            Self::FinWait2 => "FIN-WAIT-2",
            Self::TimeWait => "TIME-WAIT",
            Self::Close => "CLOSE",
            Self::CloseWait => "CLOSE-WAIT",
            Self::LastAck => "LAST-ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::Unknown(v) => return write!(f, "UNKNOWN({v:#04x})"),
        };
        f.write_str(s)
    }
}

/// One socket, exactly as the kernel reports it. No attribution yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub proto: Proto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: State,
    /// Owning uid. Cheap attribution when the pid scan cannot see the
    /// process (another user's, or gone between reads).
    pub uid: u32,
    /// The socket inode. This is the join key to `/proc/<pid>/fd`.
    pub inode: u64,
}

impl Socket {
    /// True when the peer is a real remote, not a placeholder.
    ///
    /// Listening sockets and unconnected UDP report `0.0.0.0:0` or `[::]:0`.
    #[must_use]
    pub fn has_peer(&self) -> bool {
        self.remote_port != 0 && !self.remote_addr.is_unspecified()
    }
}

/// Parse one `/proc/net` table.
///
/// Unparseable rows are skipped rather than failing the whole table: a
/// kernel that adds a column should cost you one row, not the entire view.
/// The header line is skipped by the same mechanism.
#[must_use]
pub fn parse_table(proto: Proto, text: &str) -> Vec<Socket> {
    text.lines().filter_map(|l| parse_row(proto, l)).collect()
}

fn parse_row(proto: Proto, line: &str) -> Option<Socket> {
    let mut f = line.split_whitespace();
    // Column 0 is "sl" — "0:" etc. Its presence distinguishes a data row
    // from the header, whose first field is "sl" with no colon.
    let sl = f.next()?;
    if !sl.ends_with(':') {
        return None;
    }
    let (local_addr, local_port) = parse_endpoint(f.next()?, proto.is_v6())?;
    let (remote_addr, remote_port) = parse_endpoint(f.next()?, proto.is_v6())?;
    let state = State::from_hex(u8::from_str_radix(f.next()?, 16).ok()?);
    let _queues = f.next()?;
    let _timer = f.next()?;
    let _retrans = f.next()?;
    let uid: u32 = f.next()?.parse().ok()?;
    let _timeout = f.next()?;
    let inode: u64 = f.next()?.parse().ok()?;
    Some(Socket {
        proto,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        uid,
        inode,
    })
}

/// `ADDR:PORT` where ADDR is 8 hex chars (v4) or 32 (v6), PORT is 4 hex.
///
/// The kernel writes each 32-bit word in host byte order, which on
/// little-endian means the bytes come out reversed *within each word* but
/// the words themselves are in order. Getting this wrong produces
/// plausible-looking addresses that are silently the wrong host — the kind
/// of bug that survives a demo.
fn parse_endpoint(s: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if v6 {
        if addr.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for word in 0..4 {
            let hex = &addr[word * 8..word * 8 + 8];
            let w = u32::from_str_radix(hex, 16).ok()?;
            octets[word * 4..word * 4 + 4].copy_from_slice(&w.to_ne_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        if addr.len() != 8 {
            return None;
        }
        let w = u32::from_str_radix(addr, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(w.to_ne_bytes())), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real kernel's output format, with documentation-range
    /// addresses (RFC 5737) in place of any real host's.
    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 24503 1 0000000000000000 100 0 0 10 0
   1: 077100CB:0016 2A6433C6:D8E6 01 00000000:00000000 02:000AFB4C 00000000     0        0 3459124 4 0000000000000000 20 4 31 10 -1
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27061 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn a_listener_and_an_established_connection_are_both_read() {
        let rows = parse_table(Proto::Tcp, TCP);
        assert_eq!(rows.len(), 2, "header must not become a row: {rows:?}");

        let listener = &rows[0];
        assert_eq!(listener.state, State::Listen);
        assert_eq!(listener.local_port, 0x35, "port 53");
        assert_eq!(
            listener.local_addr.to_string(),
            "127.0.0.53",
            "the kernel writes each word little-endian; reading it big-endian \
             yields 53.0.0.127, which is a real-looking and wrong address"
        );
        assert!(!listener.has_peer());
        assert_eq!(listener.uid, 101);
        assert_eq!(listener.inode, 24503);

        let conn = &rows[1];
        assert_eq!(conn.state, State::Established);
        assert_eq!(conn.local_addr.to_string(), "203.0.113.7");
        assert_eq!(conn.local_port, 22);
        assert_eq!(conn.remote_addr.to_string(), "198.51.100.42");
        assert_eq!(conn.remote_port, 55526);
        assert!(conn.has_peer());
    }

    #[test]
    fn v6_addresses_round_trip_through_the_word_swap() {
        let rows = parse_table(Proto::Tcp6, TCP6);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local_addr.to_string(), "::");
        assert_eq!(rows[0].local_port, 443);
    }

    #[test]
    fn a_real_v6_address_is_not_byte_swapped_wholesale() {
        // A full v6 address in the kernel's own encoding. The first
        // attempt at writing this constant by hand was wrong, which is
        // the argument for the test:
        // each 32-bit word is little-endian with the words left in order,
        // and both "reverse the whole thing" and "reverse nothing" produce
        // real-looking addresses that are silently a different host.
        let good = "   3: B80D0120AB1670300000000002000000:01BB \
                    00000000000000000000000000000000:0000 01 00000000:00000000 \
                    00:00000000 00000000     0        0 42 1 0 100 0 0 10 0";
        let rows = parse_table(Proto::Tcp6, good);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].local_addr.to_string(), "2001:db8:3070:16ab::2");
        assert_eq!(rows[0].local_port, 443);
        assert_eq!(rows[0].inode, 42);

        // One hex digit short: skipped, never padded into a guess.
        let short = good.replace("B80D0120AB1670300000000002000000", "80D0120AB1670300000000002000000");
        assert!(parse_table(Proto::Tcp6, &short).is_empty());
    }

    #[test]
    fn the_header_line_is_never_a_row() {
        for (p, t) in [(Proto::Tcp, TCP), (Proto::Tcp6, TCP6)] {
            let header = t.lines().next().unwrap();
            assert!(
                parse_table(p, header).is_empty(),
                "{} header parsed as data",
                p.label()
            );
        }
    }

    #[test]
    fn a_truncated_or_alien_row_is_skipped_not_guessed() {
        for junk in [
            "",
            "garbage",
            "   0: 3500007F:0035",                       // truncated
            "   0: ZZZZZZZZ:0035 00000000:0000 0A 0 0 0 0 0 1", // bad hex
            "   0: 3500007F:0035 00000000:0000 0A 0 0 0 notauid 0 1", // bad uid
        ] {
            assert!(
                parse_table(Proto::Tcp, junk).is_empty(),
                "junk parsed into a row: {junk:?}"
            );
        }
    }

    #[test]
    fn one_bad_row_does_not_cost_the_whole_table() {
        // The failure that matters: a kernel change eating every row and
        // leaving a screen that claims nothing is connected.
        let mixed = format!("{TCP}   2: nonsense\n");
        assert_eq!(parse_table(Proto::Tcp, &mixed).len(), 2);
    }

    #[test]
    fn listeners_are_not_counted_as_active_traffic() {
        assert!(!State::Listen.is_active());
        assert!(!State::Close.is_active());
        assert!(State::Established.is_active());
        // TIME-WAIT is the last thing an app did. Hiding it loses exactly
        // the connection you opened the tool to look for.
        assert!(State::TimeWait.is_active());
    }
}
