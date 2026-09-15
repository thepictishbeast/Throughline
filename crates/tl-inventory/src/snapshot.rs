//! One attributed picture of the host's network activity.
//!
//! Serialised by hand rather than with serde: this crate has no
//! dependencies on purpose, and the shape is small enough that a
//! dependency would cost more than it saves.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::ports::EphemeralPorts;
use crate::proc_net::{Proto, Socket, State, parse_table};
use crate::procs::{Holder, Owner, holders_by_inode};
use crate::services::ServiceNames;
use crate::visibility::Visibility;

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

    /// Whether this socket is somewhere the host accepts connections.
    ///
    /// Not the same as `state == Listen`. UDP never enters LISTEN — a UDP
    /// service is just a bound socket with no peer — so counting only
    /// LISTEN reported 102 listening ports on a host that also had a
    /// resolver, mDNS, NTP and QUIC bound and serving. They were not
    /// merely uncounted; they were absent from the view.
    ///
    /// The same shape describes a UDP client halfway through a query, and
    /// on this host those outnumber the real services twenty to one. The
    /// kernel's ephemeral range separates them: a port the kernel hands
    /// out for outgoing traffic is a client's, anything else was bound
    /// deliberately.
    #[must_use]
    pub fn accepts_connections(&self, ports: EphemeralPorts) -> bool {
        match self.socket.proto {
            Proto::Tcp | Proto::Tcp6 => self.socket.state == State::Listen,
            Proto::Udp | Proto::Udp6 => {
                !self.socket.has_peer() && ports.is_service_port(self.socket.local_port)
            }
        }
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
        // Loopback is decided FIRST, and the order is the meaning. Put
        // the listener check above it and every local client of a local
        // database is reported as "something reached into this machine"
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
        // Last resort, for a socket that outlived the listener that made
        // it. An accepted connection in TIME-WAIT survives its server
        // being stopped; with the LISTEN row gone there is nothing left to
        // match, and it would be announced as a place this machine chose
        // to connect out to — a stranger's address in the destination
        // lane, which is the exact lie this module exists to prevent.
        //
        // Narrow on purpose. It applies only to a socket the kernel holds
        // with no file (inode 0: TIME-WAIT and SYN-RECV), because a live
        // outbound connection has a process holding it. And it asks the
        // kernel's own ephemeral range rather than assuming one: a local
        // port the kernel would never hand out for an outgoing connection
        // was bound deliberately, to serve on.
        if self.socket.inode == 0 && listening.ports.is_service_port(self.socket.local_port) {
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
    /// The kernel's outgoing-connection range, for the orphan rule in
    /// [`Flow::direction`].
    pub ports: EphemeralPorts,
}

impl Listeners {
    /// Build from a snapshot's LISTEN rows.
    #[must_use]
    pub fn from_flows(flows: &[Flow], ports: EphemeralPorts) -> Self {
        let mut by_port: HashMap<u16, Vec<IpAddr>> = HashMap::new();
        for f in flows.iter().filter(|f| f.socket.state == State::Listen) {
            let v = by_port.entry(f.socket.local_port).or_default();
            if !v.contains(&f.socket.local_addr) {
                v.push(f.socket.local_addr);
            }
        }
        Self { by_port, ports }
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

/// A service on this host that other local software connects through.
///
/// Detected, never listed. Earlier this lane was driven by a hardcoded
/// port table — 9050 is Tor, 8118 is Privoxy, and so on. That table is
/// wrong twice over: it covers only the software whoever wrote it thought
/// of, so somebody's dnscrypt-proxy or shadowsocks or stunnel is simply
/// absent; and it is confidently wrong whenever a host uses a port for
/// something else.
///
/// What identifies a local service is that this machine LISTENS on the
/// port. The process holding that listening socket is its name. The
/// system's own `/etc/services` supplies a fallback label, and the port
/// number is the last resort — so an unrecognised service still appears,
/// rather than vanishing for want of an entry in somebody's list.
#[derive(Debug, Clone)]
pub struct LocalService {
    pub port: u16,
    pub proto: &'static str,
    /// The process holding the listening socket, when it is visible.
    pub actor: Option<String>,
    pub kind: &'static str,
    /// The name `/etc/services` gives this port, if any.
    pub service: Option<String>,
    /// Local connections into this port right now.
    pub clients: usize,
    /// Whether this service itself has connections leaving the machine.
    ///
    /// This is what separates a forwarding hop from a terminus, without
    /// naming either: traffic into a proxy continues outward through that
    /// proxy's own sockets, while traffic into a database stops there. A
    /// list of "known proxy ports" cannot tell them apart on a host it
    /// has never seen; this can.
    pub forwards: bool,
}

/// Every port this host listens on, with who holds it and whether it
/// forwards. See [`LocalService`].
#[must_use]
pub fn local_services(
    flows: &[Flow],
    names: &ServiceNames,
    ports: EphemeralPorts,
) -> Vec<LocalService> {
    let mut out: Vec<LocalService> = Vec::new();
    let mut egress: HashMap<String, bool> = HashMap::new();
    let listening = Listeners::from_flows(flows, ports);
    for f in flows {
        if f.direction(&listening) == Direction::Outbound {
            egress.insert(f.actor(), true);
        }
    }
    let mut seen: HashMap<(u16, &'static str), usize> = HashMap::new();
    // UDP never enters LISTEN — a UDP service is just a bound socket with
    // no peer. Without this the single most common local hop of all, the
    // DNS resolver, is absent from the view entirely.
    //
    // The same shape describes a UDP *client* socket mid-query, so this
    // set is deliberately NOT the one `direction` consults: treating an
    // ephemeral source port as a listener would relabel every reply as an
    // inbound connection. Here it is harmless — nothing dials an
    // ephemeral port, so those entries simply have no clients and the
    // view drops them.
    for f in flows
        .iter()
        .filter(|f| f.accepts_connections(listening.ports))
    {
        let key = (f.socket.local_port, f.socket.proto.label());
        if seen.contains_key(&key) {
            continue;
        }
        seen.insert(key, out.len());
        let actor = f.holder.as_ref().map(Holder::label);
        out.push(LocalService {
            port: f.socket.local_port,
            proto: f.socket.proto.label(),
            forwards: actor.as_ref().is_some_and(|a| egress.contains_key(a)),
            kind: f.owner.kind(),
            service: names
                .name(f.socket.local_port, f.socket.proto.transport())
                .map(ToOwned::to_owned),
            actor,
            clients: 0,
        });
    }
    // Count the local software currently connected through each one.
    for f in flows {
        if f.direction(&listening) != Direction::Loopback || !f.socket.has_peer() {
            continue;
        }
        for proto in [f.socket.proto.label()] {
            if let Some(&i) = seen.get(&(f.socket.remote_port, proto)) {
                out[i].clients += 1;
            }
        }
    }
    out
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
            let owner = holder.as_ref().map_or(Owner::Unowned, |h| h.owner.clone());
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
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                o.push_str(&format!("\\u{:04x}", c as u32));
            }
            // Bidirectional and invisible formatting controls. A process
            // names itself, and U+202E reverses everything after it, so a
            // name can render as a different name than the one the kernel
            // holds. For a view whose only claim is that what it shows is
            // true, a character that rewrites its neighbours is not a
            // display detail.
            c if matches!(c as u32,
                          0x200b..=0x200f | 0x202a..=0x202e
                          | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff) =>
            {
                o.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => o.push(c),
        }
    }
    o
}

/// Render flows as JSON for a front end.
///
/// The visibility assessment is a REQUIRED argument rather than an
/// optional extra, because the failure this crate exists to avoid is
/// exactly the one where an empty list is rendered as a fact. A caller
/// that cannot be bothered to check the instrument cannot get the
/// readings either.
#[must_use]
pub fn to_json(
    flows: &[Flow],
    names: &ServiceNames,
    ports: EphemeralPorts,
    sight: &Visibility,
) -> String {
    let listening = &Listeners::from_flows(flows, ports);
    let mut s = format!(
        "{{\"visibility\":{{\"sight\":\"{}\",\"trustworthy\":{},\"headline\":\"{}\",\
         \"evidence\":\"{}\",\"remedy\":{},\"android\":{}}},\"flows\":[",
        sight.sight.tag(),
        sight.sight.can_be_trusted(),
        esc(&sight.headline()),
        esc(&sight.evidence),
        sight
            .remedy
            .as_ref()
            .map_or_else(|| "null".to_owned(), |r| format!("\"{}\"", esc(r))),
        sight.android,
    );
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
            esc(f
                .holder
                .as_ref()
                .and_then(|h| h.exe.as_deref())
                .unwrap_or("")),
            f.direction(listening) == Direction::Outbound,
            f.accepts_connections(ports),
            f.direction(listening).tag(),
        ));
    }
    s.push_str("],\"services\":[");
    for (i, v) in local_services(flows, names, ports).iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"port\":{},\"proto\":\"{}\",\"actor\":\"{}\",\"kind\":\"{}\",\
             \"service\":\"{}\",\"clients\":{},\"forwards\":{}}}",
            v.port,
            v.proto,
            esc(v.actor.as_deref().unwrap_or("")),
            v.kind,
            esc(v.service.as_deref().unwrap_or("")),
            v.clients,
            v.forwards,
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
    use crate::visibility::{Sight, Visibility};
    use std::net::Ipv4Addr;

    /// A "we could see fine" assessment, so a test about flows is about
    /// flows. The cases that care about the instrument say so.
    fn seeing() -> Visibility {
        Visibility {
            sight: Sight::Full,
            evidence: "test fixture".to_owned(),
            remedy: None,
            android: false,
        }
    }

    /// The kernel default, so a test does not depend on the host it runs on.
    const EP: EphemeralPorts = EphemeralPorts {
        low: 32768,
        high: 60999,
    };

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
        Flow {
            socket: s,
            holder: None,
            owner: Owner::Unowned,
        }
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
        let j = to_json(&[f], &ServiceNames::default(), EP, &seeing());
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
        let l = Listeners::from_flows(&flows, EP);
        assert_eq!(flows[1].direction(&l), Direction::Inbound);
        assert!(flows[1].leaves_host(), "peer really is off-box");
    }

    #[test]
    fn a_connection_we_dialled_is_outbound() {
        let flows = vec![
            at("0.0.0.0", 443, "0.0.0.0", State::Listen),
            at("203.0.113.7", 55372, "1.1.1.1", State::Established),
        ];
        let l = Listeners::from_flows(&flows, EP);
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
        let l = Listeners::from_flows(&flows, EP);
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
            at(
                "::ffff:203.0.113.7",
                443,
                "::ffff:198.51.100.24",
                State::Established,
            ),
        ];
        let l = Listeners::from_flows(&flows, EP);
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
        // The server side of a connection from 127.0.0.1 to a local
        // database: the host does listen on that port, but nothing
        // crossed an interface, so calling it inbound would report a
        // stranger where there is none. On a development host, 41 of 113
        // apparently-inbound rows were this.
        let flows = vec![
            at("0.0.0.0", 6379, "0.0.0.0", State::Listen),
            at("127.0.0.1", 6379, "127.0.0.1", State::Established),
        ];
        let l = Listeners::from_flows(&flows, EP);
        assert_eq!(flows[1].direction(&l), Direction::Loopback);
        assert!(!flows[1].leaves_host());
    }

    #[test]
    fn a_listener_and_an_idle_socket_are_neither_in_nor_out() {
        let listen = at("0.0.0.0", 443, "0.0.0.0", State::Listen);
        assert_eq!(
            listen.direction(&Listeners::default()),
            Direction::Listening
        );
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
        let j = to_json(&flows, &ServiceNames::default(), EP, &seeing());
        assert_eq!(j.matches("\"dir\":\"inbound\"").count(), 1, "{j}");
        assert_eq!(j.matches("\"dir\":\"outbound\"").count(), 1, "{j}");
        assert_eq!(j.matches("\"dir\":\"listening\"").count(), 1, "{j}");
        // The UI's `leaves` flag drives the "what am I connecting to"
        // lane, so it must be true for exactly the outbound row.
        assert_eq!(j.matches("\"leaves\":true").count(), 1, "{j}");
    }

    fn held(mut f: Flow, comm: &str, owner: Owner) -> Flow {
        f.holder = Some(Holder {
            pid: 7,
            comm: comm.to_owned(),
            exe: None,
            owner: owner.clone(),
        });
        f.owner = owner;
        f
    }

    #[test]
    fn a_local_service_is_detected_from_the_listener_not_a_port_list() {
        // The port here is deliberately one no hardcoded "well-known
        // proxies" table would contain. What identifies the service is
        // that this host listens on it and a process holds the socket.
        let flows = vec![
            held(
                at("127.0.0.1", 47821, "0.0.0.0", State::Listen),
                "dnscrypt-proxy",
                Owner::Service("dnscrypt-proxy".to_owned()),
            ),
            at("127.0.0.1", 55000, "127.0.0.1", State::Established),
        ];
        let svc = local_services(&flows, &ServiceNames::default(), EP);
        assert_eq!(svc.len(), 1);
        assert_eq!(svc[0].port, 47821);
        assert_eq!(svc[0].actor.as_deref(), Some("dnscrypt-proxy"));
        assert_eq!(svc[0].service, None, "no /etc/services entry, still listed");
    }

    #[test]
    fn a_forwarder_is_told_apart_from_a_terminus_by_its_own_egress() {
        // A proxy has connections leaving the machine; a database does
        // not. Neither is named, and neither needs to be.
        let proxy = held(
            at("127.0.0.1", 9050, "0.0.0.0", State::Listen),
            "tor",
            Owner::Service("tor".to_owned()),
        );
        let proxy_out = held(
            at("10.0.0.1", 51000, "198.51.100.9", State::Established),
            "tor",
            Owner::Service("tor".to_owned()),
        );
        let db = held(
            at("127.0.0.1", 5432, "0.0.0.0", State::Listen),
            "postgres",
            Owner::Service("postgres".to_owned()),
        );
        let svc = local_services(&[proxy, proxy_out, db], &ServiceNames::default(), EP);
        let by_port = |p: u16| svc.iter().find(|s| s.port == p).unwrap();
        assert!(by_port(9050).forwards, "tor's traffic continues outward");
        assert!(!by_port(5432).forwards, "postgres is where traffic stops");
    }

    #[test]
    fn the_system_services_file_supplies_a_label_when_no_process_is_visible() {
        // Running unprivileged, another user's process is invisible, but
        // the listening socket still is. A name from the host's own
        // /etc/services beats showing a bare number.
        let names = ServiceNames::parse("ssh 22/tcp\n");
        let svc = local_services(&[at("0.0.0.0", 22, "0.0.0.0", State::Listen)], &names, EP);
        assert_eq!(svc[0].actor, None);
        assert_eq!(svc[0].service.as_deref(), Some("ssh"));
    }

    #[test]
    fn clients_are_counted_from_the_loopback_connections_into_the_port() {
        let flows = vec![
            held(
                at("127.0.0.1", 9050, "0.0.0.0", State::Listen),
                "tor",
                Owner::Service("tor".to_owned()),
            ),
            at("127.0.0.1", 41000, "127.0.0.1", State::Established),
            at("127.0.0.1", 41001, "127.0.0.1", State::Established),
        ];
        // Both client sockets are dialling 9050.
        let mut flows = flows;
        flows[1].socket.remote_port = 9050;
        flows[2].socket.remote_port = 9050;
        let svc = local_services(&flows, &ServiceNames::default(), EP);
        assert_eq!(svc[0].clients, 2);
    }

    #[test]
    fn a_udp_service_is_found_even_though_udp_never_listens() {
        // /proc/net/udp has no LISTEN state; a resolver's socket is just
        // bound with no peer. Requiring State::Listen hid DNS — the most
        // common local hop there is — from the view completely.
        let mut resolver = at("127.0.0.53", 53, "0.0.0.0", State::Close);
        resolver.socket.proto = Proto::Udp;
        resolver.socket.remote_port = 0;
        let mut client = at("127.0.0.1", 41000, "127.0.0.53", State::Established);
        client.socket.proto = Proto::Udp;
        client.socket.remote_port = 53;
        let names = ServiceNames::parse("domain 53/udp\n");
        let svc = local_services(&[resolver, client], &names, EP);
        let dns = svc
            .iter()
            .find(|s| s.port == 53)
            .expect("resolver detected");
        assert_eq!(dns.service.as_deref(), Some("domain"));
        assert_eq!(dns.clients, 1);
    }

    #[test]
    fn a_udp_client_port_is_never_treated_as_a_listener_for_direction() {
        // The same "bound, no peer" shape describes a client mid-query.
        // It may appear in the service list (harmlessly, with no clients)
        // but it must NOT make the reply look like an inbound connection.
        let mut ephemeral = at("10.0.0.1", 41000, "0.0.0.0", State::Close);
        ephemeral.socket.proto = Proto::Udp;
        ephemeral.socket.remote_port = 0;
        let mut reply = at("10.0.0.1", 41000, "198.51.100.9", State::Established);
        reply.socket.proto = Proto::Udp;
        let flows = vec![ephemeral, reply];
        let l = Listeners::from_flows(&flows, EP);
        assert_eq!(
            flows[1].direction(&l),
            Direction::Outbound,
            "a UDP reply is not somebody connecting in"
        );
        // Better than "listed with no clients": the kernel's own range
        // says 41000 is a port it hands out for outgoing traffic, so it
        // is not a service at all and never reaches the view. On this
        // host that is the difference between 11 services and 216.
        let svc = local_services(&flows, &ServiceNames::default(), EP);
        assert!(
            svc.iter().all(|s| s.port != 41000),
            "client port listed as a service"
        );
        assert!(!flows[0].accepts_connections(EP));
    }

    #[test]
    fn json_carries_the_detected_services() {
        let names = ServiceNames::parse("ssh 22/tcp\n");
        let flows = vec![held(
            at("0.0.0.0", 22, "0.0.0.0", State::Listen),
            "sshd",
            Owner::Service("ssh".to_owned()),
        )];
        let j = to_json(&flows, &names, EP, &seeing());
        assert!(j.contains(r#""service":"ssh""#), "{j}");
        assert!(j.contains(r#""actor":"sshd (ssh)""#), "{j}");
        assert!(j.contains(r#""forwards":false"#), "{j}");
    }

    #[test]
    fn a_name_cannot_rewrite_the_text_around_it() {
        // U+202E (RIGHT-TO-LEFT OVERRIDE) reverses the rendering of what
        // follows, so a process could name itself so that the screen
        // shows something other than what the kernel reports. The tool's
        // only claim is that what it shows is true.
        let f = Flow {
            socket: sock([1, 1, 1, 1], 443, State::Established),
            holder: Some(Holder {
                pid: 1,
                comm: "gpj.\u{202e}exe-erawlam".to_owned(),
                exe: None,
                owner: Owner::Process,
            }),
            owner: Owner::Process,
        };
        let j = to_json(&[f], &ServiceNames::default(), EP, &seeing());
        assert!(!j.contains('\u{202e}'), "raw override reached the UI");
        assert!(j.contains("\\u202e"), "{j}");
        // Zero-width characters hide a difference between two names.
        assert_eq!(esc("a\u{200b}b"), "a\\u200bb");
        assert_eq!(esc("a\u{feff}b"), "a\\ufeffb");
        assert_eq!(esc("plain text"), "plain text", "ordinary names untouched");
    }

    #[test]
    fn an_orphaned_server_socket_is_still_inbound_after_its_listener_stops() {
        // An accepted connection in TIME-WAIT outlives the server being
        // stopped. With no LISTEN row left to match, it would be shown as
        // somewhere this machine chose to connect out to — a stranger's
        // address in the destination lane.
        let mut f = at("10.0.0.1", 443, "198.51.100.9", State::TimeWait);
        f.socket.inode = 0; // the kernel holds it; no process does
        assert_eq!(
            f.direction(&Listeners::from_flows(&[], EP)),
            Direction::Inbound
        );
    }

    #[test]
    fn an_orphan_on_an_ephemeral_port_is_still_outbound() {
        // The mirror case, and the reason the rule is narrow: TIME-WAIT
        // from a connection WE made has a local port the kernel handed
        // out. Treating every orphan as inbound would re-create the bug
        // in the other direction.
        let mut f = at("10.0.0.1", 41000, "198.51.100.9", State::TimeWait);
        f.socket.inode = 0;
        assert!(EP.is_ephemeral(41000));
        assert_eq!(
            f.direction(&Listeners::from_flows(&[], EP)),
            Direction::Outbound
        );
    }

    #[test]
    fn a_live_outbound_connection_is_never_caught_by_the_orphan_rule() {
        // Gated on inode 0 precisely so a real connection held by a real
        // process cannot be reinterpreted, whatever port it bound.
        let mut f = at("10.0.0.1", 443, "198.51.100.9", State::Established);
        f.socket.inode = 4242;
        assert_eq!(
            f.direction(&Listeners::from_flows(&[], EP)),
            Direction::Outbound
        );
    }

    #[test]
    fn a_udp_service_counts_as_accepting_and_a_udp_client_does_not() {
        let mut resolver = at("127.0.0.53", 53, "0.0.0.0", State::Close);
        resolver.socket.proto = Proto::Udp;
        resolver.socket.remote_port = 0;
        let mut client = at("10.0.0.1", 45123, "0.0.0.0", State::Close);
        client.socket.proto = Proto::Udp;
        client.socket.remote_port = 0;
        assert!(resolver.accepts_connections(EP), "a resolver is accepting");
        assert!(!client.accepts_connections(EP), "a query in flight is not");
        // TCP keeps the strict rule: only LISTEN accepts.
        assert!(at("0.0.0.0", 443, "0.0.0.0", State::Listen).accepts_connections(EP));
        assert!(!at("10.0.0.1", 443, "198.51.100.9", State::Established).accepts_connections(EP));
    }

    #[test]
    fn an_empty_snapshot_is_still_valid_json() {
        assert_eq!(
            to_json(&[], &ServiceNames::default(), EP, &seeing()),
            "{\"visibility\":{\"sight\":\"full\",\"trustworthy\":true,\
             \"headline\":\"reading this machine\",\"evidence\":\"test fixture\",\
             \"remedy\":null,\"android\":false},\"flows\":[],\"services\":[]}"
        );
    }

    #[test]
    fn an_empty_snapshot_from_a_blind_process_says_so_in_the_document() {
        // The Termux failure, pinned at the layer a front end reads.
        // Both documents have `"flows":[]`; only one of them means the
        // machine is quiet, and the difference must be in the bytes --
        // not in a log line, not in an exit status a GUI never sees.
        let blind = Visibility {
            sight: Sight::TablesWithheld,
            evidence: "3 interface(s) carried packets".to_owned(),
            remedy: Some("run it as root".to_owned()),
            android: true,
        };
        let j = to_json(&[], &ServiceNames::default(), EP, &blind);
        assert!(j.contains("\"sight\":\"tables-withheld\""), "{j}");
        assert!(j.contains("\"trustworthy\":false"), "{j}");
        assert!(j.contains("CANNOT SEE"), "{j}");
        assert!(j.contains("\"android\":true"), "{j}");
        assert!(j.contains("\"flows\":[]"));
        // And the quiet machine's document differs, at the field that
        // decides it, from the blind one's.
        let quiet = to_json(&[], &ServiceNames::default(), EP, &seeing());
        assert!(quiet.contains("\"trustworthy\":true"));
        assert_ne!(quiet, j, "a blind reading must not render as a quiet one");
    }
}
