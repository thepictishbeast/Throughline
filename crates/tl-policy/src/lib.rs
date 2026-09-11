//! Turning "this app goes through Tor" into rules a kernel will accept.
//!
//! The dangerous part of per-app routing is not the rule you meant to
//! write. It is the four you did not:
//!
//! * **Your own session.** Redirect everything and the SSH connection you
//!   are typing into goes with it. You find out when the prompt stops
//!   coming back and the machine is somewhere else.
//! * **The tunnel's own packets.** Route a VPN client's traffic into the
//!   VPN and it cannot reach its server to build the tunnel.
//! * **Tor's own traffic.** Send Tor's output into Tor and it never
//!   reaches a relay.
//! * **DNS.** Route an app's TCP through Tor and leave its DNS alone, and
//!   every site it visits is still announced in plaintext to the
//!   resolver. The traffic is anonymous; the browsing is not.
//!
//! Each is generated here rather than remembered, and [`Plan::preflight`]
//! refuses a plan that is missing one. A compiler that emits a ruleset
//! which locks you out is not a convenience.
//!
//! Nothing in this crate executes anything. It produces text: an
//! nftables ruleset, `ip` commands, and torrc lines. Applying them is a
//! separate, deliberate step.

pub mod apply;
pub mod probe;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::fmt::Write as _;

/// Where an application's traffic should go.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Path {
    /// Straight out of the default route, as it goes today.
    Direct,
    /// Into a tunnel interface. The interface carries the traffic; this
    /// crate does not bring it up.
    Vpn { interface: String },
    /// Transparently into Tor, TCP and DNS both.
    Tor,
    /// Into Tor, with Tor's own traffic carried by the tunnel first.
    ///
    /// This is the ordering people mean by "Tor over VPN": the ISP sees a
    /// VPN connection, the VPN provider sees Tor traffic, and the Tor
    /// guard sees the VPN's address rather than yours.
    TorViaVpn { interface: String },
}

impl Path {
    /// A short label for a UI.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Direct => "direct".to_owned(),
            Self::Vpn { interface } => format!("vpn:{interface}"),
            Self::Tor => "tor".to_owned(),
            Self::TorViaVpn { interface } => format!("tor-via-{interface}"),
        }
    }

    /// Whether traffic on this path is handed to Tor.
    #[must_use]
    pub const fn uses_tor(&self) -> bool {
        matches!(self, Self::Tor | Self::TorViaVpn { .. })
    }

    /// The tunnel interface this path needs, if any.
    #[must_use]
    pub fn interface(&self) -> Option<&str> {
        match self {
            Self::Vpn { interface } | Self::TorViaVpn { interface } => Some(interface),
            Self::Direct | Self::Tor => None,
        }
    }
}

/// What a rule matches on.
///
/// All three are things the kernel can test on the socket that owns an
/// outgoing packet, which is what makes per-application routing possible
/// at all: the decision is made from the sender, not from the address it
/// is heading to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    /// A cgroup v2 path, as it appears under `/sys/fs/cgroup`.
    Cgroup(String),
    /// A systemd unit, resolved to its cgroup.
    Unit(String),
    /// Everything a user runs.
    User(u32),
}

impl Selector {
    /// The nftables expression that matches this sender.
    ///
    /// `socket cgroupv2 level N` compares the Nth component of the
    /// socket's cgroup path, so the level must match the depth of the
    /// path being tested or the rule matches nothing — silently, which is
    /// the failure mode that makes people think their policy applied.
    #[must_use]
    pub fn nft_match(&self) -> String {
        match self {
            Self::Cgroup(p) => {
                let p = p.trim_matches('/');
                let level = p.split('/').count();
                format!("socket cgroupv2 level {level} \"{p}\"")
            }
            Self::Unit(u) => {
                let p = format!("system.slice/{u}");
                format!("socket cgroupv2 level 2 \"{p}\"")
            }
            Self::User(uid) => format!("meta skuid {uid}"),
        }
    }

    /// How to describe this in a UI.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Cgroup(p) => p.clone(),
            Self::Unit(u) => u.clone(),
            Self::User(uid) => format!("uid {uid}"),
        }
    }
}

/// One "send this through that".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub selector: Selector,
    pub path: Path,
}

/// Facts about the host a policy is being compiled for.
///
/// Passed in rather than read here so the compiler stays pure and the
/// preflight checks can be exercised against hosts this machine is not.
#[derive(Debug, Clone, Default)]
pub struct Host {
    /// Interfaces that exist right now.
    pub interfaces: Vec<String>,
    /// Tor's transparent-proxy port, if it has one configured.
    pub tor_trans_port: Option<u16>,
    /// Tor's DNS port, if it has one configured.
    pub tor_dns_port: Option<u16>,
    /// The uid Tor runs as. Its own traffic must bypass the redirect.
    pub tor_uid: Option<u32>,
    /// Peer addresses of connections that must keep working — in
    /// practice, whoever is administering this machine right now.
    pub admin_peers: Vec<String>,
    /// Addresses that must stay reachable outside any tunnel, such as a
    /// VPN server's own endpoint.
    pub tunnel_endpoints: Vec<String>,
    /// `rp_filter` per interface, as the kernel reports it.
    ///
    /// 1 is strict: a packet is dropped unless the route back to its
    /// source is out the interface it arrived on. Policy routing makes
    /// the return path asymmetric by design, so strict filtering drops
    /// every reply — after the ruleset loaded, after the marks were set,
    /// after the far end answered. Measured, not guessed: sending real
    /// traffic through a generated policy produced
    /// `TcpExtIPReversePathFilter 2` and a connection that simply timed
    /// out, with nothing wrong anywhere in the ruleset.
    pub rp_filter: Vec<(String, u8)>,
    /// cgroup v2 paths that exist right now, relative to the cgroup root.
    ///
    /// nftables resolves a cgroup path to an id when the rule is loaded
    /// and rejects the whole ruleset if it cannot. So a policy naming a
    /// service that is not running is not merely ineffective — it cannot
    /// be applied at all, and it takes every other rule down with it.
    pub cgroups: Vec<String>,
}

/// The nftables match for "destined for this address".
///
/// In an `inet` table `ip daddr` matches IPv4 only — and it does not
/// error on an IPv6 packet, it simply evaluates false, so the packet
/// falls straight through to the redirect. An administrative session over
/// IPv6 excluded with `ip daddr` is not excluded at all, while the rule
/// that captures it is family-agnostic. That is the stranding failure the
/// exclusions exist to prevent, one address family over.
///
/// A hostname is not an address and cannot be matched on; it is emitted
/// as a comment so it is visible rather than silently dropped.
#[must_use]
fn daddr(addr: &str) -> String {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => format!("ip daddr {a}"),
        Ok(IpAddr::V6(a)) => match a.to_ipv4_mapped() {
            // ::ffff:a.b.c.d is carried in v4 packets on the wire.
            Some(v4) => format!("ip daddr {v4}"),
            None => format!("ip6 daddr {a}"),
        },
        Err(_) => format!("# unparseable address {addr:?}, not excluded"),
    }
}

/// A policy: ordered rules, and what happens to everything else.
#[derive(Debug, Clone)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub default_path: Path,
}

impl Default for Policy {
    fn default() -> Self {
        Self { rules: Vec::new(), default_path: Path::Direct }
    }
}

/// Why a plan must not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A path needs an interface the host does not have.
    NoSuchInterface { interface: String, path: String },
    /// A path sends traffic to Tor, but Tor has no transparent port.
    TorNotTransparent { missing: &'static str },
    /// Tor's own uid is unknown, so its traffic cannot be excluded from
    /// its own redirect.
    TorUidUnknown,
    /// Applying this would capture the connection administering the host.
    WouldStrandAdmin { peer: String },
    /// A rule matches nothing that could ever exist.
    EmptySelector { selector: String },
    /// Two rules claim the same sender.
    DuplicateSelector { selector: String },
    /// An address to protect is not an address.
    UnparseablePeer { peer: String },
    /// A rule names a cgroup that does not exist on this host.
    NoSuchCgroup { path: String },
    /// Traffic would be routed out an interface whose reverse-path filter
    /// will drop the replies.
    StrictReversePath { interface: String },
}

impl Refusal {
    /// A sentence a person can act on.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::NoSuchInterface { interface, path } => format!(
                "path {path} needs interface {interface}, which does not exist on this host. \
                 Bring the tunnel up first; this tool does not create interfaces."
            ),
            Self::TorNotTransparent { missing } => format!(
                "traffic is routed to Tor but Tor has no {missing}. Add it to torrc and \
                 reload Tor, otherwise the redirect sends packets to a closed port and \
                 the application simply fails to connect."
            ),
            Self::TorUidUnknown => "Tor's uid is unknown, so its own traffic cannot be \
                 excluded from the redirect. Every packet Tor sent to a relay would be \
                 sent back to Tor."
                .to_owned(),
            Self::WouldStrandAdmin { peer } => format!(
                "this would capture the connection from {peer}, which is administering \
                 this host right now. Applying it ends that session and there is no \
                 second one."
            ),
            Self::EmptySelector { selector } => {
                format!("selector {selector:?} cannot match any socket")
            }
            Self::DuplicateSelector { selector } => format!(
                "{selector} is claimed by two rules; the first would win and the second \
                 would silently do nothing"
            ),
            Self::StrictReversePath { interface } => format!(
                "{interface} has rp_filter=1 (strict), so the kernel will drop every \
                 reply that comes back on it. Policy routing makes the return path \
                 asymmetric on purpose, so this breaks the moment it is applied -- and \
                 it breaks silently: the rules load, the packets leave, the far end \
                 answers, and the connection times out as though the other end were at \
                 fault. Set net.ipv4.conf.{interface}.rp_filter=2 (loose) first."
            ),
            Self::UnparseablePeer { peer } => format!(
                "{peer:?} is not an IP address, so no rule can match it and the session \
                 it names would not be excluded. A hostname will not do: nftables \
                 matches addresses."
            ),
            Self::NoSuchCgroup { path } => format!(
                "no cgroup {path} on this host, so nftables will reject the ruleset -- \
                 and with it every other rule in the policy. Start the service first, \
                 or select it from what is actually running."
            ),
        }
    }
}

/// The concrete thing to apply, as text.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// A complete nftables table, safe to `nft -f`.
    pub nft: String,
    /// `ip rule` / `ip route` invocations, in order.
    pub ip: Vec<String>,
    /// Lines Tor needs in its configuration for this plan to work.
    pub torrc: Vec<String>,
    /// Mark value per path, for display.
    pub marks: BTreeMap<String, u32>,
    /// Exactly how to undo this, in order.
    ///
    /// `nft delete table` is a third of a revert. What it leaves behind is
    /// the half that can misroute traffic on its own: `ip rule` entries
    /// sitting ABOVE `main` that match on a mark, and routing tables with
    /// a default route in them. If anything on the host ever sets that
    /// mark again — another tool, a later run — the traffic silently takes
    /// a table nobody remembers creating.
    pub revert: Vec<String>,
    /// Things that are true and worth knowing, but not refusals.
    pub notes: Vec<String>,
}

/// The first fwmark used. Arbitrary but distinctive, so a rule from this
/// tool is recognisable in someone else's ruleset.
const MARK_BASE: u32 = 0x7401;
/// Routing tables are numbered from here, one per mark.
const TABLE_BASE: u32 = 7401;

/// The table name everything lives in, so the whole policy can be removed
/// with one `nft delete table`.
pub const TABLE: &str = "throughline";
/// Chain names, every one prefixed `tl_`. Not `redirect`, `mark` or
/// `snat`: all three are nftables keywords and a chain cannot be named
/// after one. The prefix is the rule, so the next chain added cannot
/// collide with a keyword nobody remembered. The generator's own tests passed
/// happily while every ruleset it produced was rejected by the parser,
/// which is the argument for checking generated config with the real
/// tool rather than reading it.
pub const NAT_CHAIN: &str = "tl_via_tor";
pub const MARK_CHAIN: &str = "tl_routing";
pub const MASQ_CHAIN: &str = "tl_masquerade";

impl Policy {
    /// Compile to a plan. Does not check it — see [`Plan::preflight`].
    #[must_use]
    pub fn compile(&self, host: &Host) -> Plan {
        let mut plan = Plan::default();
        let mut paths: Vec<Path> = Vec::new();
        for r in &self.rules {
            if !paths.contains(&r.path) {
                paths.push(r.path.clone());
            }
        }
        if !paths.contains(&self.default_path) {
            paths.push(self.default_path.clone());
        }
        // Marks only mean anything for paths that move traffic to another
        // route. Direct is the absence of a mark.
        for (mark, p) in
            (MARK_BASE..).zip(paths.iter().filter(|p| p.interface().is_some()))
        {
            plan.marks.insert(p.label(), mark);
        }

        let uses_tor = paths.iter().any(Path::uses_tor);
        plan.nft = self.nft_ruleset(host, &plan.marks, uses_tor, &paths);

        for (label, mark) in &plan.marks {
            let table = TABLE_BASE + (mark - MARK_BASE);
            let iface = paths
                .iter()
                .find(|p| &p.label() == label)
                .and_then(Path::interface)
                .unwrap_or_default();
            plan.ip.push(format!(
                "ip rule add fwmark {mark:#x} lookup {table} priority {}",
                1000 + (mark - MARK_BASE)
            ));
            plan.ip.push(format!("ip route add default dev {iface} table {table}"));
            // Built alongside, so the undo cannot drift from the do.
            plan.revert.push(format!("ip route flush table {table}"));
            plan.revert.push(format!(
                "ip rule del fwmark {mark:#x} lookup {table} priority {}",
                1000 + (mark - MARK_BASE)
            ));
        }
        plan.revert.insert(0, format!("nft delete table inet {TABLE}"));

        if uses_tor {
            let trans = host.tor_trans_port.unwrap_or(9040);
            let dns = host.tor_dns_port.unwrap_or(9053);
            plan.torrc.push(format!("TransPort 127.0.0.1:{trans}"));
            plan.torrc.push(format!("DNSPort 127.0.0.1:{dns}"));
            plan.torrc.push("AutomapHostsOnResolve 1".to_owned());
            plan.torrc.push("AutomapHostsSuffixes .onion,.exit".to_owned());
            plan.notes.push(
                "DNS is redirected to Tor's DNSPort as well as TCP. Routing TCP alone \
                 leaves every hostname the application looks up in plaintext, which \
                 defeats the point while looking like it worked."
                    .to_owned(),
            );
        }
        if let Path::TorViaVpn { interface } = &self.default_path {
            plan.notes.push(format!(
                "Tor's own traffic is routed through {interface}, so the Tor guard sees \
                 the tunnel's address. Everything else about Tor is unchanged."
            ));
        }
        plan
    }

    fn nft_ruleset(
        &self,
        host: &Host,
        marks: &BTreeMap<String, u32>,
        uses_tor: bool,
        paths: &[Path],
    ) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "# generated by throughline");
        // `nft -f` MERGES into an existing table: it appends to the
        // existing chains and leaves every old rule in front of the new
        // ones. Since the chains are first-match with `return`, the STALE
        // rules win. So a second apply that moves a program from Tor to
        // Direct leaves the Tor redirect in place and quietly produces a
        // kernel state matching no plan anyone has seen.
        //
        // The bare `table` line creates it if absent, which makes the
        // delete always valid, so this is safe on a first apply too.
        let _ = writeln!(s, "table inet {TABLE}");
        let _ = writeln!(s, "delete table inet {TABLE}");
        let _ = writeln!(s, "table inet {TABLE} {{");

        if uses_tor {
            let trans = host.tor_trans_port.unwrap_or(9040);
            let dns = host.tor_dns_port.unwrap_or(9053);
            let _ = writeln!(s, "  chain {NAT_CHAIN} {{");
            let _ = writeln!(s, "    type nat hook output priority dstnat; policy accept;");
            let _ = writeln!(s, "{}", Self::exclusions(host, "    "));
            if let Some(uid) = host.tor_uid {
                let _ = writeln!(s, "    # Tor's own packets, or they never reach a relay.");
                let _ = writeln!(s, "    meta skuid {uid} return");
            }
            for r in self.rules.iter().filter(|r| r.path.uses_tor()) {
                let _ = writeln!(
                    s,
                    "    {} meta l4proto tcp redirect to :{trans}",
                    r.selector.nft_match()
                );
                let _ = writeln!(
                    s,
                    "    {} udp dport 53 redirect to :{dns}",
                    r.selector.nft_match()
                );
            }
            if self.default_path.uses_tor() {
                let _ = writeln!(s, "    meta l4proto tcp redirect to :{trans}");
                let _ = writeln!(s, "    udp dport 53 redirect to :{dns}");
            }
            let _ = writeln!(s, "  }}");
        }

        let _ = writeln!(s, "  chain {MARK_CHAIN} {{");
        let _ = writeln!(s, "    type route hook output priority mangle; policy accept;");
        let _ = writeln!(s, "{}", Self::exclusions(host, "    "));
        for r in &self.rules {
            if let Some(mark) = marks.get(&r.path.label()) {
                let _ = writeln!(
                    s,
                    "    {} meta mark set {mark:#x}",
                    r.selector.nft_match()
                );
            }
        }
        // Tor-via-VPN: it is Tor's OWN socket that must take the tunnel.
        // Marking the application here would send it round the tunnel
        // before Tor ever saw it, which is a different topology wearing
        // the same name.
        if let Path::TorViaVpn { interface } = &self.default_path
            && let (Some(uid), Some(mark)) = (
                host.tor_uid,
                marks.get(&Path::TorViaVpn { interface: interface.clone() }.label()),
            )
        {
            let _ = writeln!(s, "    # Tor itself takes the tunnel; apps take Tor.");
            let _ = writeln!(s, "    meta skuid {uid} meta mark set {mark:#x}");
        }
        if let Some(mark) = marks.get(&self.default_path.label()) {
            let _ = writeln!(s, "    meta mark set {mark:#x}   # default for everything else");
        }
        if !marks.is_empty() {
            // Save the decision onto the connection.
            //
            // Without this the policy leaks. Only the first packet of a
            // connection is NEW; every packet after it is ESTABLISHED and
            // hits the "leave existing connections alone" rule above, so
            // it is never marked and takes the ordinary route. The
            // connection dies, and the part of it that does get sent goes
            // out the interface the policy was meant to keep it off.
            //
            // Found by sending real traffic through a generated ruleset in
            // a namespace: the SYN went through the tunnel, everything
            // after it went direct.
            let _ = writeln!(s, "    # Remember it, so the rest of the connection follows.");
            let _ = writeln!(s, "    meta mark != 0x0 ct mark set meta mark");
        }
        let _ = writeln!(s, "  }}");

        // Source addresses are chosen BEFORE the mark is set.
        //
        // The output hook picks a route, and therefore a source address,
        // from the main table. Only then does the mark rule run and the
        // packet get re-routed out a different interface — still carrying
        // the first interface's address. The far end has no route back to
        // it, so nothing returns.
        //
        // Measured, not reasoned: a marked connection in a test namespace
        // reached the far end and was answered, and the reply went
        // nowhere. Masquerading on the new egress is what makes the
        // source match the interface the packet is actually leaving by.
        let egress: Vec<&str> = marks
            .keys()
            .filter_map(|label| {
                paths
                    .iter()
                    .find(|p| &p.label() == label)
                    .and_then(Path::interface)
            })
            .collect();
        if !egress.is_empty() {
            let _ = writeln!(s, "  chain {MASQ_CHAIN} {{");
            let _ = writeln!(s, "    type nat hook postrouting priority srcnat; policy accept;");
            for iface in egress {
                let _ = writeln!(s, "    oifname \"{iface}\" masquerade");
            }
            let _ = writeln!(s, "  }}");
        }
        let _ = writeln!(s, "}}");
        s
    }

    /// Rules that must come before anything else, in every chain.
    ///
    /// The order is not decoration. `ct mark` is consulted FIRST so that a
    /// decision already made for a connection is reapplied to the rest of
    /// it; only then does the "leave existing connections alone" rule get
    /// a look, and by that point it can only be reached by a connection
    /// this policy never claimed.
    fn exclusions(host: &Host, indent: &str) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{indent}# Exclusions first. Order is the safety.");
        let _ = writeln!(
            s,
            "{indent}# A connection this policy already decided about keeps that decision."
        );
        let _ = writeln!(s, "{indent}ct mark != 0x0 meta mark set ct mark return");
        let _ = writeln!(s, "{indent}oif lo return");
        let _ = writeln!(
            s,
            "{indent}ct state established,related return   # a connection that predates this policy"
        );
        for peer in &host.admin_peers {
            let _ = writeln!(
                s,
                "{indent}{} return   # the session administering this host",
                daddr(peer)
            );
        }
        for ep in &host.tunnel_endpoints {
            let _ = writeln!(s, "{indent}{} return   # a tunnel's own endpoint", daddr(ep));
        }
        s.trim_end().to_owned()
    }
}

impl Plan {
    /// Everything wrong with this plan, worst first. Empty means it can
    /// be applied.
    #[must_use]
    pub fn preflight(&self, policy: &Policy, host: &Host) -> Vec<Refusal> {
        let mut out = Vec::new();
        let mut seen: Vec<String> = Vec::new();

        for r in &policy.rules {
            let label = r.selector.label();
            if label.trim().is_empty() {
                out.push(Refusal::EmptySelector { selector: label.clone() });
            } else if seen.contains(&label) {
                out.push(Refusal::DuplicateSelector { selector: label.clone() });
            } else {
                seen.push(label);
            }
        }

        // nft resolves a cgroup path at load time. One that is not there
        // fails the ENTIRE ruleset, so this is checked before anything is
        // offered for applying.
        for r in &policy.rules {
            let wanted = match &r.selector {
                Selector::Cgroup(p) => Some(p.trim_matches('/').to_owned()),
                Selector::Unit(u) => Some(format!("system.slice/{u}")),
                Selector::User(_) => None,
            };
            if let Some(w) = wanted
                && !host.cgroups.is_empty()
                && !host.cgroups.iter().any(|c| c.trim_matches('/') == w)
            {
                out.push(Refusal::NoSuchCgroup { path: w });
            }
        }

        let mut paths: Vec<&Path> = policy.rules.iter().map(|r| &r.path).collect();
        paths.push(&policy.default_path);
        for p in &paths {
            if let Some(i) = p.interface()
                && !host.interfaces.iter().any(|h| h == i)
            {
                out.push(Refusal::NoSuchInterface {
                    interface: i.to_owned(),
                    path: p.label(),
                });
            }
        }
        if paths.iter().any(|p| p.uses_tor()) {
            if host.tor_trans_port.is_none() {
                out.push(Refusal::TorNotTransparent { missing: "TransPort" });
            }
            if host.tor_dns_port.is_none() {
                out.push(Refusal::TorNotTransparent { missing: "DNSPort" });
            }
            if host.tor_uid.is_none() {
                out.push(Refusal::TorUidUnknown);
            }
        }

        // Strict reverse-path filtering on any interface this policy
        // routes traffic out of. See `Refusal::StrictReversePath`.
        for p in &paths {
            if let Some(i) = p.interface() {
                // The kernel uses max(all, interface), and the values are
                // 0=off, 1=strict, 2=loose. So `all=2` with the interface
                // at 1 is LOOSE, not strict — treating either value of 1
                // as strict refuses a plan that would work. Strict is
                // exactly max == 1.
                let get = |n: &str| host.rp_filter.iter().find(|(k, _)| k == n).map(|(_, v)| *v);
                let strict = get("all").unwrap_or(0).max(get(i).unwrap_or(0)) == 1;
                if strict
                    && !out.iter().any(|r| {
                        matches!(r, Refusal::StrictReversePath { interface } if interface == i)
                    })
                {
                    out.push(Refusal::StrictReversePath { interface: i.to_owned() });
                }
            }
        }

        // The check that matters most: an admin peer is only safe if the
        // ruleset actually excludes it. Read the generated text rather
        // than trusting that the generator did its job.
        for peer in host.admin_peers.iter().chain(&host.tunnel_endpoints) {
            if peer.parse::<IpAddr>().is_err() {
                out.push(Refusal::UnparseablePeer { peer: peer.clone() });
            }
        }
        for peer in &host.admin_peers {
            if peer.parse::<IpAddr>().is_ok()
                && !self.nft.contains(&format!("{} return", daddr(peer)))
            {
                out.push(Refusal::WouldStrandAdmin { peer: peer.clone() });
            }
        }
        out
    }

    /// The whole plan as something to read before applying it.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{}", self.nft);
        if !self.ip.is_empty() {
            let _ = writeln!(s, "# routing");
            for c in &self.ip {
                let _ = writeln!(s, "{c}");
            }
        }
        if !self.torrc.is_empty() {
            let _ = writeln!(s, "\n# /etc/tor/torrc must contain");
            for c in &self.torrc {
                let _ = writeln!(s, "{c}");
            }
        }
        for n in &self.notes {
            let _ = writeln!(s, "\n# note: {n}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            interfaces: vec!["eth0".into(), "wg0".into()],
            tor_trans_port: Some(9040),
            tor_dns_port: Some(9053),
            tor_uid: Some(107),
            admin_peers: vec!["198.51.100.7".into()],
            tunnel_endpoints: vec!["203.0.113.9".into()],
            rp_filter: vec![("all".into(), 2), ("wg0".into(), 2), ("eth0".into(), 2)],
            cgroups: vec![
                "system.slice/nginx.service".into(),
                "system.slice/tor.service".into(),
            ],
        }
    }

    #[test]
    fn the_session_administering_the_host_is_excluded_before_anything_else() {
        // The failure this prevents is not subtle: you apply the policy,
        // your own connection is captured, and the machine is somewhere
        // else. There is no undo over a connection that is gone.
        let p = Policy {
            rules: vec![Rule {
                selector: Selector::Unit("nginx.service".into()),
                path: Path::Tor,
            }],
            default_path: Path::Direct,
        };
        let plan = p.compile(&host());
        assert!(plan.nft.contains("ip daddr 198.51.100.7 return"));
        let admin = plan.nft.find("198.51.100.7").unwrap();
        let first_rule = plan.nft.find("redirect to :9040").unwrap();
        assert!(admin < first_rule, "exclusion must precede the redirect:\n{}", plan.nft);
        assert!(plan.preflight(&p, &host()).is_empty());
    }

    #[test]
    fn a_plan_that_would_strand_the_admin_is_refused() {
        // Same policy, but compiled without knowing about the session.
        // Applying it to a host that does have one must be refused.
        let blind = Host { admin_peers: vec![], ..host() };
        let p = Policy {
            rules: vec![Rule { selector: Selector::Unit("nginx.service".into()), path: Path::Tor }],
            default_path: Path::Direct,
        };
        let plan = p.compile(&blind);
        let refusals = plan.preflight(&p, &host());
        assert_eq!(
            refusals,
            vec![Refusal::WouldStrandAdmin { peer: "198.51.100.7".into() }]
        );
        assert!(refusals[0].explain().contains("no second one"));
    }

    #[test]
    fn tor_traffic_is_excluded_from_its_own_redirect() {
        // Without this, every packet Tor sends to a relay is sent back to
        // Tor. Nothing reaches the network and the cause is invisible.
        let p = Policy {
            rules: vec![Rule { selector: Selector::User(1000), path: Path::Tor }],
            default_path: Path::Direct,
        };
        let plan = p.compile(&host());
        assert!(plan.nft.contains("meta skuid 107 return"), "{}", plan.nft);
        let tor_return = plan.nft.find("meta skuid 107 return").unwrap();
        let redirect = plan.nft.find("redirect to :9040").unwrap();
        assert!(tor_return < redirect);
    }

    #[test]
    fn dns_is_routed_with_the_tcp_it_belongs_to() {
        // Routing TCP through Tor and leaving DNS alone announces every
        // hostname to the local resolver in plaintext. The traffic is
        // anonymous and the browsing is not, which is worse than either
        // honest alternative because it looks like it worked.
        let p = Policy {
            rules: vec![Rule { selector: Selector::User(1000), path: Path::Tor }],
            default_path: Path::Direct,
        };
        let plan = p.compile(&host());
        assert!(plan.nft.contains("udp dport 53 redirect to :9053"), "{}", plan.nft);
        assert!(plan.torrc.iter().any(|l| l.starts_with("DNSPort")));
        assert!(plan.notes.iter().any(|n| n.contains("plaintext")));
    }

    #[test]
    fn tor_via_vpn_puts_tor_in_the_tunnel_not_the_application() {
        // "Tor over VPN" means Tor's own connection to its guard rides
        // the tunnel. Marking the application instead sends it round the
        // tunnel before Tor ever sees it — a different topology with the
        // same name.
        let p = Policy {
            rules: vec![],
            default_path: Path::TorViaVpn { interface: "wg0".into() },
        };
        let plan = p.compile(&host());
        assert!(
            plan.nft.contains("meta skuid 107 meta mark set"),
            "Tor's own socket must be the marked one:\n{}",
            plan.nft
        );
        assert!(plan.ip.iter().any(|c| c.contains("dev wg0")));
        assert!(plan.notes.iter().any(|n| n.contains("guard sees the tunnel")));
    }

    #[test]
    fn a_tunnels_own_endpoint_stays_outside_the_tunnel() {
        // Route a VPN client's packets into the VPN and it can never
        // reach its server to build the tunnel in the first place.
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let plan = p.compile(&host());
        assert!(plan.nft.contains("ip daddr 203.0.113.9 return"), "{}", plan.nft);
    }

    #[test]
    fn a_missing_interface_is_refused_rather_than_emitted() {
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "tun9".into() } };
        let plan = p.compile(&host());
        let r = plan.preflight(&p, &host());
        assert!(r.contains(&Refusal::NoSuchInterface {
            interface: "tun9".into(),
            path: "vpn:tun9".into()
        }));
        assert!(r[0].explain().contains("does not create interfaces"));
    }

    #[test]
    fn tor_without_a_transparent_port_is_refused_with_the_lines_to_add() {
        let bare = Host { tor_trans_port: None, tor_dns_port: None, ..host() };
        let p = Policy { rules: vec![], default_path: Path::Tor };
        let plan = p.compile(&bare);
        let r = plan.preflight(&p, &bare);
        assert!(r.contains(&Refusal::TorNotTransparent { missing: "TransPort" }));
        assert!(r.contains(&Refusal::TorNotTransparent { missing: "DNSPort" }));
        // The plan still says what torrc needs, so the refusal is fixable.
        assert!(plan.torrc.iter().any(|l| l.contains("TransPort")));
    }

    #[test]
    fn a_rule_for_a_cgroup_that_is_not_there_is_refused_before_it_breaks_everything() {
        // nft resolves the path when the ruleset loads. A missing cgroup
        // does not make one rule inert -- it makes `nft -f` reject the
        // file, so the policy that WAS fine never gets applied either.
        // Found by feeding generated output to the real parser; every
        // unit test here passed while this was broken.
        let p = Policy {
            rules: vec![Rule {
                selector: Selector::Unit("firefox.service".into()),
                path: Path::Tor,
            }],
            default_path: Path::Direct,
        };
        let plan = p.compile(&host());
        assert!(plan.preflight(&p, &host()).contains(&Refusal::NoSuchCgroup {
            path: "system.slice/firefox.service".into()
        }));
        // One that IS running passes.
        let ok = Policy {
            rules: vec![Rule {
                selector: Selector::Unit("nginx.service".into()),
                path: Path::Tor,
            }],
            default_path: Path::Direct,
        };
        assert!(ok.compile(&host()).preflight(&ok, &host()).is_empty());
    }

    #[test]
    fn a_cgroup_selector_matches_at_its_own_depth() {
        // `socket cgroupv2 level N` compares the Nth path component. Get
        // the level wrong and the rule matches nothing, silently, which
        // reads exactly like a policy that applied and did nothing.
        assert_eq!(
            Selector::Cgroup("system.slice/tor.service".into()).nft_match(),
            "socket cgroupv2 level 2 \"system.slice/tor.service\""
        );
        assert_eq!(
            Selector::Cgroup("/user.slice/user-1000.slice/session-3.scope".into()).nft_match(),
            "socket cgroupv2 level 3 \"user.slice/user-1000.slice/session-3.scope\""
        );
        assert_eq!(
            Selector::Unit("nginx.service".into()).nft_match(),
            "socket cgroupv2 level 2 \"system.slice/nginx.service\""
        );
    }

    #[test]
    fn two_rules_for_one_sender_are_refused_not_silently_ordered() {
        let p = Policy {
            rules: vec![
                Rule { selector: Selector::User(1000), path: Path::Tor },
                Rule { selector: Selector::User(1000), path: Path::Direct },
            ],
            default_path: Path::Direct,
        };
        let plan = p.compile(&host());
        let r = plan.preflight(&p, &host());
        assert!(r.contains(&Refusal::DuplicateSelector { selector: "uid 1000".into() }));
    }

    #[test]
    fn established_connections_are_never_captured() {
        // A policy change must not tear down what is already open. That
        // is also what keeps an inbound session alive when the rule is
        // about outbound traffic.
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let plan = p.compile(&host());
        assert!(plan.nft.contains("ct state established,related return"));
    }

    #[test]
    fn the_undo_removes_the_routing_half_as_well_as_the_ruleset() {
        // Deleting the table leaves `ip rule` entries above `main` that
        // match on a mark, and routing tables with a default route in
        // them. Both survive, both can misroute traffic the next time
        // anything sets that mark, and neither is visible in `nft list`.
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let plan = p.compile(&host());
        assert_eq!(plan.revert[0], format!("nft delete table inet {TABLE}"));
        assert!(plan.revert.iter().any(|c| c.starts_with("ip rule del fwmark")), "{:?}", plan.revert);
        assert!(plan.revert.iter().any(|c| c.starts_with("ip route flush table")), "{:?}", plan.revert);
        // One undo per thing done.
        assert_eq!(plan.revert.len(), plan.ip.len() + 1, "{:?}", plan.revert);
    }

    #[test]
    fn a_policy_that_changes_nothing_has_nothing_to_undo_but_the_table() {
        let p = Policy { rules: vec![], default_path: Path::Direct };
        assert_eq!(p.compile(&host()).revert, vec![format!("nft delete table inet {TABLE}")]);
    }

    #[test]
    fn the_source_address_is_made_to_match_the_interface_it_leaves_by() {
        // The output hook picks a route, and a source address, from the
        // main table. The mark rule runs AFTER that and re-routes the
        // packet out a different interface, still carrying the first
        // one's address. In a test namespace the far end received the
        // connection and answered, and the reply went nowhere.
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let plan = p.compile(&host());
        assert!(plan.nft.contains("type nat hook postrouting priority srcnat"), "{}", plan.nft);
        assert!(plan.nft.contains("oifname \"wg0\" masquerade"), "{}", plan.nft);
    }

    #[test]
    fn no_masquerade_chain_when_nothing_is_rerouted() {
        let p = Policy { rules: vec![], default_path: Path::Direct };
        let plan = p.compile(&host());
        assert!(!plan.nft.contains("masquerade"), "{}", plan.nft);
    }

    #[test]
    fn strict_reverse_path_filtering_is_refused_before_it_breaks_everything() {
        // Applying over rp_filter=1 breaks in the worst possible way: the
        // ruleset loads, the packets leave, the far end answers, and the
        // connection times out as though the remote end were at fault.
        let strict = Host {
            rp_filter: vec![("all".into(), 1), ("wg0".into(), 1)],
            ..host()
        };
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let r = p.compile(&strict).preflight(&p, &strict);
        assert!(r.contains(&Refusal::StrictReversePath { interface: "wg0".into() }), "{r:?}");
        assert!(r[0].explain().contains("rp_filter=2"));
    }

    #[test]
    fn loose_on_all_beats_strict_on_the_interface() {
        // max(all, interface) with 0=off 1=strict 2=loose, so all=2 makes
        // the interface loose whatever its own value says. Refusing here
        // would block a plan that works.
        let h = Host { rp_filter: vec![("all".into(), 2), ("wg0".into(), 1)], ..host() };
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        assert!(
            !p.compile(&h).preflight(&p, &h).iter().any(|r|
                matches!(r, Refusal::StrictReversePath { .. })),
            "refused a plan that the kernel would route fine"
        );
    }

    #[test]
    fn all_equals_one_makes_every_interface_strict() {
        // The kernel takes the maximum of `all` and the interface, so a
        // host with all=1 drops replies however the interface is set.
        let strict = Host {
            rp_filter: vec![("all".into(), 1), ("wg0".into(), 1)],
            ..host()
        };
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let r = p.compile(&strict).preflight(&p, &strict);
        assert!(r.contains(&Refusal::StrictReversePath { interface: "wg0".into() }), "{r:?}");
    }

    #[test]
    fn every_generated_chain_name_is_prefixed_so_it_cannot_be_a_keyword() {
        // `redirect`, `mark` and `snat` are all nftables keywords, and a
        // chain named after one makes the whole ruleset unloadable. Three
        // separate times the unit tests passed while nft rejected the
        // output. The prefix is the rule.
        for name in [NAT_CHAIN, MARK_CHAIN, MASQ_CHAIN] {
            assert!(name.starts_with("tl_"), "{name} is not prefixed");
        }
        let p = Policy {
            rules: vec![Rule {
                selector: Selector::Unit("nginx.service".into()),
                path: Path::Tor,
            }],
            default_path: Path::Vpn { interface: "wg0".into() },
        };
        let nft = p.compile(&host()).nft;
        for line in nft.lines().filter(|l| l.trim_start().starts_with("chain ")) {
            let name = line.split_whitespace().nth(1).unwrap();
            assert!(name.starts_with("tl_"), "chain {name} is not prefixed: {line}");
        }
    }

    #[test]
    fn a_connections_route_survives_past_its_first_packet() {
        // Only the first packet of a connection is NEW. If the decision is
        // not saved onto the connection, every packet after the SYN hits
        // the "leave existing connections alone" rule, goes unmarked, and
        // takes the ordinary route — so the connection breaks AND the part
        // that is sent leaks out the interface the policy exists to avoid.
        //
        // Measured: with real traffic in a namespace, marking by cgroup
        // alone reached the tunnel; adding the exclusions broke it
        // entirely until the connection mark was carried.
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let nft = p.compile(&host()).nft;
        let restore = nft.find("ct mark != 0x0 meta mark set ct mark return")
            .expect("connection mark is not restored");
        let leave_alone = nft.find("ct state established,related return")
            .expect("no established rule");
        let save = nft.find("ct mark set meta mark").expect("decision is never saved");
        assert!(
            restore < leave_alone,
            "restoring must come first, or an established packet returns before it is \
             recognised:\n{nft}"
        );
        assert!(save > leave_alone, "the save must come after the selectors:\n{nft}");
    }

    #[test]
    fn nothing_is_saved_onto_a_connection_when_nothing_is_rerouted() {
        let p = Policy { rules: vec![], default_path: Path::Direct };
        let nft = p.compile(&host()).nft;
        assert!(!nft.contains("ct mark set meta mark"), "{nft}");
    }

    #[test]
    fn an_ipv6_session_is_excluded_in_a_way_that_can_actually_match() {
        // `ip daddr` in an inet table evaluates FALSE for an IPv6 packet —
        // it does not error — so an exclusion written that way leaves the
        // session it names completely unprotected, while the rule that
        // captures it matches both families.
        let h = Host {
            admin_peers: vec!["2001:db8::7".into(), "198.51.100.7".into()],
            ..host()
        };
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let nft = p.compile(&h).nft;
        assert!(nft.contains("ip6 daddr 2001:db8::7 return"), "{nft}");
        assert!(nft.contains("ip daddr 198.51.100.7 return"), "{nft}");
        assert!(p.compile(&h).preflight(&p, &h).is_empty());
    }

    #[test]
    fn a_v4_mapped_peer_is_matched_as_the_v4_it_is_on_the_wire() {
        // An inbound session on a dual-stack listener is reported as
        // ::ffff:a.b.c.d, but the packets are IPv4 and only `ip daddr`
        // will ever match them.
        let h = Host { admin_peers: vec!["::ffff:198.51.100.7".into()], ..host() };
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let nft = p.compile(&h).nft;
        assert!(nft.contains("ip daddr 198.51.100.7 return"), "{nft}");
        assert!(!nft.contains("ip6 daddr"), "{nft}");
    }

    #[test]
    fn an_address_that_is_not_an_address_is_visible_not_silently_dropped() {
        let h = Host { admin_peers: vec!["my-laptop.local".into()], ..host() };
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let plan = p.compile(&h);
        assert!(plan.nft.contains("unparseable address"), "{}", plan.nft);
        // And the plan is refused, rather than quietly applying with one
        // fewer protection than the operator asked for.
        let r = plan.preflight(&p, &h);
        assert!(
            r.contains(&Refusal::UnparseablePeer { peer: "my-laptop.local".into() }),
            "must not pass silently: {r:?}"
        );
        assert!(r[0].explain().contains("nftables matches addresses"));
    }

    #[test]
    fn re_applying_replaces_the_table_instead_of_stacking_onto_it() {
        let p = Policy { rules: vec![], default_path: Path::Vpn { interface: "wg0".into() } };
        let nft = p.compile(&host()).nft;
        let create = nft.find(&format!("table inet {TABLE}\n")).expect("no bare create");
        let delete = nft.find(&format!("delete table inet {TABLE}")).expect("no delete");
        let body = nft.find(&format!("table inet {TABLE} {{")).expect("no body");
        assert!(create < delete && delete < body, "{nft}");
    }

    #[test]
    fn direct_is_the_absence_of_a_mark_not_a_mark_of_its_own() {
        let p = Policy { rules: vec![], default_path: Path::Direct };
        let plan = p.compile(&host());
        assert!(plan.marks.is_empty(), "{:?}", plan.marks);
        assert!(plan.ip.is_empty(), "nothing to route");
    }
}
