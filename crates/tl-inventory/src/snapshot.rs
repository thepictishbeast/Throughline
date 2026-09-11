//! One attributed picture of the host's network activity.
//!
//! Serialised by hand rather than with serde: this crate has no
//! dependencies on purpose, and the shape is small enough that a
//! dependency would cost more than it saves.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::proc_net::{Proto, Socket, State, parse_table};
use crate::procs::{Holder, Owner, holders_by_inode};

/// A socket plus who owns it.
#[derive(Debug, Clone)]
pub struct Flow {
    pub socket: Socket,
    pub holder: Option<Holder>,
    pub owner: Owner,
}

impl Flow {
    /// Best label for the thing at the near end.
    #[must_use]
    pub fn actor(&self) -> String {
        self.holder
            .as_ref()
            .map_or_else(|| "unattributed".to_owned(), Holder::label)
    }

    /// True when this leaves the machine, as opposed to loopback chatter.
    ///
    /// Loopback is most of the rows on a busy host and none of the answer
    /// to "what is talking to the internet", but it is not noise either —
    /// an app talking to a local Tor or VPN proxy is exactly the first hop
    /// of the path this tool exists to draw. So it is classified, not
    /// dropped.
    ///
    /// NOTE this says *off-host*, not *outbound*. Use [`Flow::direction`]
    /// for which way the arrow points.
    #[must_use]
    pub fn leaves_host(&self) -> bool {
        self.socket.has_peer() && !is_local(self.socket.remote_addr)
    }

    /// Which way this connection was initiated.
    ///
    /// `/proc/net/tcp` does not record who dialled. Two things recover it:
    ///
    /// * `SYN-RECV` is unambiguous — it is the state of a half-open
    ///   connection we are *accepting*. Nothing we dial is ever in it.
    /// * otherwise, a connection whose LOCAL socket matches one of this
    ///   host's listeners was accepted on that listener; anything else
    ///   with a peer was dialled by us.
    ///
    /// Without this the view is not merely imprecise, it is backwards: on
    /// this host 38 inbound hits on :443 and :22 were being drawn as
    /// outbound connections in the "what is my machine talking to" lane —
    /// strangers' addresses presented as destinations we chose. The tool's
    /// whole claim is that the arrows are right.
    #[must_use]
    pub fn direction(&self, listening: &Listeners) -> Direction {
        if self.socket.state == State::Listen {
            return Direction::Listening;
        }
        if !self.socket.has_peer() && self.socket.state != State::SynRecv {
            return Direction::Idle;
        }
        // Loopback is decided FIRST, and the order is the meaning. Put the
        // listener check above it and the 41 localhost clients of redis on
        // this host get reported as "something reached into this machine"
        // — the server side of a connection that never touched the NIC.
        // Nothing crossed an interface, so nothing is inbound.
        if is_local(self.socket.remote_addr) {
            return Direction::Loopback;
        }
        if self.socket.state == State::SynRecv
            || listening.accepts(self.socket.local_addr, self.socket.local_port)
        {
            return Direction::Inbound;
        }
        Direction::Outbound
    }
}

/// Which way a connection was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We dialled something off this machine.
    Outbound,
    /// Something dialled a port we listen on.
    Inbound,
    /// We dialled something on this machine — often the first hop of a
    /// path, e.g. an app into a local Tor SOCKS port.
    Loopback,
    /// A listening socket.
    Listening,
    /// A socket with no peer and not listening.
    Idle,
}

impl Direction {
    /// Lower-case tag for the UI.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
            Self::Loopback => "loopback",
            Self::Listening => "listening",
            Self::Idle => "idle",
        }
    }
}

/// Where this host accepts connections.
///
/// Port alone is not enough. A listener bound to `127.0.0.1:8080` accepts
/// nothing from the network, so an outbound connection that happens to be
/// assigned local port 8080 on a real interface must NOT be read as
/// inbound. Matching the address as well as the port keeps that case
/// right, while a wildcard bind (`0.0.0.0`, `::`) still matches every
/// local address as it does in the kernel.
#[derive(Debug, Default, Clone)]
pub struct Listeners {
    by_port: HashMap<u16, Vec<IpAddr>>,
}

impl Listeners {
    /// Build from a snapshot's LISTEN rows.
    #[must_use]
    pub fn from_flows(flows: &[Flow]) -> Self {
        let mut by_port: HashMap<u16, Vec<IpAddr>> = HashMap::new();
        for f in flows.iter().filter(|f| f.socket.state == State::Listen) {
            let v = by_port.entry(f.socket.local_port).or_default();
            if !v.contains(&f.socket.local_addr) {
                v.push(f.socket.local_addr);
            }
        }
        Self { by_port }
    }

    /// True when a listener on this host would have accepted a connection
    /// arriving at `addr:port`.
    #[must_use]
    pub fn accepts(&self, addr: IpAddr, port: u16) -> bool {
        let Some(bound) = self.by_port.get(&port) else {
            return false;
        };
        bound
            .iter()
            .any(|b| b.is_unspecified() || same_addr(*b, addr))
    }

    /// How many distinct ports are listening — the header count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_port.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }
}

/// Address equality across the v4/v6-mapped divide.
///
/// A dual-stack listener shows in `/proc/net/tcp6` as `::` while the
/// accepted connection shows its local address as `::ffff:203.0.113.7`.
/// Comparing the raw values would miss the match and label the whole
/// connection outbound — which is the exact bug this module is fixing.
fn same_addr(a: IpAddr, b: IpAddr) -> bool {
    fn flat(x: IpAddr) -> IpAddr {
        match x {
            IpAddr::V6(v) => v.to_ipv4_mapped().map_or(x, IpAddr::V4),
            v4 => v4,
        }
    }
    flat(a) == flat(b)
}

fn is_local(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(v) => v.is_loopback() || v.is_unspecified(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.to_ipv4_mapped().is_some_and(|m| m.is_loopback())
        }
    }
}

/// Read every socket table and attribute each row.
#[must_use]
pub fn collect(proc_root: &Path) -> Vec<Flow> {
    let holders = holders_by_inode(proc_root);
    let mut out = Vec::new();
    for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
        let path = proc_root.join("net").join(p.label());
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for socket in parse_table(p, &text) {
            let holder = holders.get(&socket.inode).cloned();
            let owner = holder
                .as_ref()
                .map_or(Owner::Unowned, |h| h.owner.clone());
            out.push(Flow {
                socket,
                holder,
                owner,
            });
        }
    }
    out
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Render flows as JSON for the UI.
#[must_use]
pub fn to_json(flows: &[Flow]) -> String {
    let listening = &Listeners::from_flows(flows);
    let mut s = String::from("{\"flows\":[");
    for (i, f) in flows.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let sk = &f.socket;
        s.push_str(&format!(
            "{{\"proto\":\"{}\",\"state\":\"{}\",\"local\":\"{}\",\"lport\":{},\
             \"remote\":\"{}\",\"rport\":{},\"inode\":{},\"uid\":{},\
             \"actor\":\"{}\",\"kind\":\"{}\",\"pid\":{},\"exe\":\"{}\",\
             \"leaves\":{},\"listening\":{},\"dir\":\"{}\"}}",
            sk.proto.label(),
            sk.state,
            sk.local_addr,
            sk.local_port,
            sk.remote_addr,
            sk.remote_port,
            sk.inode,
            sk.uid,
            esc(&f.actor()),
            f.owner.kind(),
            f.holder.as_ref().map_or(0, |h| h.pid),
            esc(f.holder.as_ref().and_then(|h| h.exe.as_deref()).unwrap_or("")),
            f.direction(listening) == Direction::Outbound,
            sk.state == State::Listen,
            f.direction(listening).tag(),
        ));
    }
    s.push_str("]}");
    s
}

/// Count of flows by owner kind, for the UI's summary row.
#[must_use]
pub fn by_kind(flows: &[Flow]) -> HashMap<&'static str, usize> {
    let mut m = HashMap::new();
    for f in flows {
        *m.entry(f.owner.kind()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_net::Proto;
    use std::net::Ipv4Addr;

    fn sock(remote: [u8; 4], port: u16, state: State) -> Socket {
        Socket {
            proto: Proto::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            local_port: 1234,
            remote_addr: IpAddr::V4(Ipv4Addr::from(remote)),
            remote_port: port,
            state,
            uid: 0,
            inode: 1,
        }
    }

    fn at(local: &str, lport: u16, remote: &str, state: State) -> Flow {
        flow(Socket {
            proto: Proto::Tcp,
            local_addr: local.parse().unwrap(),
            local_port: lport,
            remote_addr: remote.parse().unwrap(),
            remote_port: if state == State::Listen { 0 } else { 40000 },
            state,
            uid: 0,
            inode: 1,
        })
    }

    fn flow(s: Socket) -> Flow {
        Flow { socket: s, holder: None, owner: Owner::Unowned }
    }

    #[test]
    fn loopback_is_classified_not_counted_as_leaving() {
        assert!(!flow(sock([127, 0, 0, 1], 9050, State::Established)).leaves_host());
        assert!(flow(sock([1, 1, 1, 1], 443, State::Established)).leaves_host());
    }

    #[test]
    fn a_listener_has_no_peer_so_it_does_not_leave() {
        assert!(!flow(sock([0, 0, 0, 0], 0, State::Listen)).leaves_host());
    }

    #[test]
    fn json_escapes_a_hostile_process_name() {
        // A process can name itself anything. An unescaped quote here
        // would break the UI's parse and blank the whole view.
        let f = Flow {
            socket: sock([1, 1, 1, 1], 443, State::Established),
            holder: Some(Holder {
                pid: 1,
                comm: "evil\"name\\with\nnewline".to_owned(),
                exe: None,
                owner: Owner::Process,
            }),
            owner: Owner::Process,
        };
        let j = to_json(&[f]);
        assert!(j.contains(r#"\"name\\with\nnewline"#), "{j}");
        assert_eq!(j.matches("\"actor\"").count(), 1);
    }

    #[test]
    fn a_connection_to_a_port_we_listen_on_is_inbound_not_outbound() {
        // The bug this exists to stop: 38 flows on this host, all hits on
        // :443 and :22 from strangers, were drawn as places we connected
        // OUT to. `leaves_host` is true for all of them — it only asks
        // "is the peer off-box" — so direction must be asked separately.
        let flows = vec![
            at("0.0.0.0", 443, "0.0.0.0", State::Listen),
            at("203.0.113.7", 443, "198.51.100.24", State::Established),
        ];
        let l = Listeners::from_flows(&flows);
        assert_eq!(flows[1].direction(&l), Direction::Inbound);
        assert!(flows[1].leaves_host(), "peer really is off-box");
    }

    #[test]
    fn a_connection_we_dialled_is_outbound() {
        let flows = vec![
            at("0.0.0.0", 443, "0.0.0.0", State::Listen),
            at("203.0.113.7", 55372, "1.1.1.1", State::Established),
        ];
        let l = Listeners::from_flows(&flows);
        assert_eq!(flows[1].direction(&l), Direction::Outbound);
    }

    #[test]
    fn syn_recv_is_inbound_even_with_no_matching_listener() {
        // Half-open connections carry inode 0 and can outlive the view of
        // the listener that produced them. The state alone settles it —
        // nothing we dial is ever in SYN-RECV.
        let f = at("203.0.113.7", 22, "198.51.100.99", State::SynRecv);
        assert_eq!(f.direction(&Listeners::default()), Direction::Inbound);
    }

    #[test]
    fn a_loopback_only_listener_does_not_make_an_outbound_flow_look_inbound() {
        // A listener on 127.0.0.1:8080 accepts nothing from the network.
        // Port-only matching would call this flow inbound and point the
        // arrow at ourselves.
        let flows = vec![
            at("127.0.0.1", 8080, "0.0.0.0", State::Listen),
            at("203.0.113.7", 8080, "1.1.1.1", State::Established),
        ];
        let l = Listeners::from_flows(&flows);
        assert_eq!(flows[1].direction(&l), Direction::Outbound);
        assert!(l.accepts("127.0.0.1".parse().unwrap(), 8080));
    }

    #[test]
    fn a_dual_stack_listener_matches_a_v4_mapped_connection() {
        // Real shape from this host: the listener is `::` in
        // /proc/net/tcp6 and the accepted socket's local address is
        // ::ffff:203.0.113.7. Raw comparison misses it.
        let flows = vec![
            at("::", 443, "::", State::Listen),
            at("::ffff:203.0.113.7", 443, "::ffff:198.51.100.24", State::Established),
        ];
        let l = Listeners::from_flows(&flows);
        assert_eq!(flows[1].direction(&l), Direction::Inbound);
    }

    #[test]
    fn a_local_proxy_hop_is_loopback_not_outbound() {
        // An app into Tor's SOCKS port is the first hop of a path, and
        // must not be counted as traffic that reached the internet.
        let f = flow(sock([127, 0, 0, 1], 9050, State::Established));
        assert_eq!(f.direction(&Listeners::default()), Direction::Loopback);
    }

    #[test]
    fn a_localhost_client_of_a_local_server_is_loopback_not_inbound() {
        // The server side of a redis connection from 127.0.0.1: we do
        // listen on 6379, but nothing crossed an interface, so calling it
        // inbound would report a stranger where there is none. 41 rows on
        // this host land here.
        let flows = vec![
            at("0.0.0.0", 6379, "0.0.0.0", State::Listen),
            at("127.0.0.1", 6379, "127.0.0.1", State::Established),
        ];
        let l = Listeners::from_flows(&flows);
        assert_eq!(flows[1].direction(&l), Direction::Loopback);
        assert!(!flows[1].leaves_host());
    }

    #[test]
    fn a_listener_and_an_idle_socket_are_neither_in_nor_out() {
        let listen = at("0.0.0.0", 443, "0.0.0.0", State::Listen);
        assert_eq!(listen.direction(&Listeners::default()), Direction::Listening);
        let idle = flow(sock([0, 0, 0, 0], 0, State::Close));
        assert_eq!(idle.direction(&Listeners::default()), Direction::Idle);
    }

    #[test]
    fn json_carries_the_direction_and_leaves_means_outbound_only() {
        let flows = vec![
            at("0.0.0.0", 443, "0.0.0.0", State::Listen),
            at("203.0.113.7", 443, "198.51.100.24", State::Established),
            at("203.0.113.7", 55372, "1.1.1.1", State::Established),
        ];
        let j = to_json(&flows);
        assert_eq!(j.matches("\"dir\":\"inbound\"").count(), 1, "{j}");
        assert_eq!(j.matches("\"dir\":\"outbound\"").count(), 1, "{j}");
        assert_eq!(j.matches("\"dir\":\"listening\"").count(), 1, "{j}");
        // The UI's `leaves` flag drives the "what am I connecting to"
        // lane, so it must be true for exactly the outbound row.
        assert_eq!(j.matches("\"leaves\":true").count(), 1, "{j}");
    }

    #[test]
    fn an_empty_snapshot_is_still_valid_json() {
        assert_eq!(to_json(&[]), "{\"flows\":[]}");
    }
}
