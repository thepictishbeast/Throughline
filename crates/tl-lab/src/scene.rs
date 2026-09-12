//! The topology on the canvas: what is on it, where, and joined to what.
//!
//! This is a lab bench, not a diagram. Every node stands for something
//! that exists — a program that is running, an interface that is up, a
//! tunnel that is configured — or for something the person is proposing
//! to add. The difference between those two is the whole point of the
//! screen, so it is a property of the node rather than a mode of the
//! application.
//!
//! No drawing here, and no egui: this is the model, and it is tested
//! without a renderer.

use std::collections::BTreeMap;

/// What a node stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The machine itself. There is exactly one, and it cannot be deleted.
    Host,
    /// A program, service or container that opens connections.
    Program,
    /// A network interface: ethernet, wifi, a bridge.
    Interface,
    /// A tunnel interface — WireGuard, OpenVPN, anything point-to-point.
    Tunnel,
    /// Tor, running on this machine.
    Tor,
    /// A local service traffic passes through: a resolver, a proxy.
    LocalService,
    /// Somewhere off the machine.
    Destination,
    /// The internet at large, as one node.
    Internet,
}

impl Kind {
    /// The word a person would use.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Host => "this machine",
            Self::Program => "program",
            Self::Interface => "interface",
            Self::Tunnel => "tunnel",
            Self::Tor => "Tor",
            Self::LocalService => "local service",
            Self::Destination => "destination",
            Self::Internet => "internet",
        }
    }

    /// Which column this kind belongs in when the canvas is tidied.
    ///
    /// Traffic reads left to right, so a tidy is a stable sort by how far
    /// along the path a thing sits. Without it, "arrange" would be an
    /// opinion; with it, position carries meaning.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Host => 0,
            Self::Program => 1,
            Self::LocalService | Self::Tor => 2,
            Self::Interface | Self::Tunnel => 3,
            Self::Destination | Self::Internet => 4,
        }
    }

    /// Whether a person may add one of these by hand.
    ///
    /// You cannot invent a second machine, and you cannot invent a
    /// program that is not running — those come from the host. You can
    /// propose a tunnel that does not exist yet, which is the main thing
    /// anyone comes here to do.
    #[must_use]
    pub const fn can_be_added(self) -> bool {
        // Internet is NOT here. There is one internet, it is always
        // there because it really is, and a second deletable copy of it
        // on the canvas would be a drawing rather than a description.
        matches!(self, Self::Tunnel | Self::Tor | Self::Destination)
    }
}

/// Whether a node describes the machine as it is, or as it is proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Read from the machine. Cannot be deleted; deleting it would be a
    /// claim about reality rather than a change to the plan.
    Observed,
    /// Put there by a person. This is the part that can be applied.
    Proposed,
}

/// A thing on the canvas.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    pub label: String,
    /// A second line: a pid, an address, a port.
    pub detail: String,
    pub origin: Origin,
    /// Canvas coordinates, not screen coordinates. Panning and zooming
    /// must not change the topology.
    pub pos: (f32, f32),
    /// True when this program has a connection open right now.
    pub live: bool,
}

/// A join between two nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub from: String,
    pub to: String,
    pub origin: Origin,
    /// Connections currently riding this link, for width and for the
    /// label. Zero for a link that is only proposed.
    pub weight: usize,
}

/// The whole bench.
#[derive(Debug, Clone, Default)]
pub struct Scene {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
}

impl Scene {
    #[must_use]
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    #[must_use]
    pub fn node_mut(&mut self, id: &str) -> Option<&mut Node> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    /// Add a node, or move an existing one with the same id.
    ///
    /// Re-reading the machine must not scatter the layout a person has
    /// arranged, so a node that is already on the canvas keeps its
    /// position and only its facts are refreshed.
    pub fn upsert(&mut self, node: Node) {
        if let Some(existing) = self.node_mut(&node.id) {
            let pos = existing.pos;
            *existing = node;
            existing.pos = pos;
        } else {
            self.nodes.push(node);
        }
    }

    /// Join two nodes, if they are not joined already.
    ///
    /// Returns whether anything changed, so a caller can tell a new link
    /// from a repeated gesture.
    pub fn connect(&mut self, from: &str, to: &str, origin: Origin) -> bool {
        if from == to || self.node(from).is_none() || self.node(to).is_none() {
            return false;
        }
        if self.linked(from, to) {
            return false;
        }
        self.links.push(Link {
            from: from.to_owned(),
            to: to.to_owned(),
            origin,
            weight: 0,
        });
        true
    }

    /// Whether two nodes are joined, in either direction.
    #[must_use]
    pub fn linked(&self, a: &str, b: &str) -> bool {
        self.links
            .iter()
            .any(|l| (l.from == a && l.to == b) || (l.from == b && l.to == a))
    }

    /// Remove a node a person put there, and everything joined to it.
    ///
    /// Observed nodes are refused: the canvas describes a real machine,
    /// and removing a running program from the picture would not stop it
    /// running. Returns whether anything was removed.
    pub fn remove(&mut self, id: &str) -> bool {
        let Some(n) = self.node(id) else { return false };
        if n.origin == Origin::Observed {
            return false;
        }
        self.nodes.retain(|n| n.id != id);
        self.links.retain(|l| l.from != id && l.to != id);
        true
    }

    /// Remove a link a person drew.
    pub fn disconnect(&mut self, from: &str, to: &str) -> bool {
        let before = self.links.len();
        self.links.retain(|l| {
            let matches = (l.from == from && l.to == to) || (l.from == to && l.to == from);
            !(matches && l.origin == Origin::Proposed)
        });
        self.links.len() != before
    }

    /// Lay the nodes out left to right by how far along a path they sit.
    ///
    /// Deliberately deterministic: the same topology tidies to the same
    /// picture every time, so "arrange" is something a person can rely on
    /// rather than a shuffle.
    pub fn tidy(&mut self, column: f32, row: f32) {
        let mut by_rank: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            by_rank.entry(n.kind.rank()).or_default().push(i);
        }
        for (rank, idxs) in by_rank {
            // Sort within a column by label, so the order does not depend
            // on the order the machine happened to report things in.
            let mut idxs = idxs;
            idxs.sort_by(|a, b| self.nodes[*a].label.cmp(&self.nodes[*b].label));
            for (slot, i) in idxs.into_iter().enumerate() {
                #[allow(clippy::cast_precision_loss)]
                let y = slot as f32 * row;
                #[allow(clippy::cast_precision_loss)]
                let x = f32::from(rank) * column;
                self.nodes[i].pos = (x, y);
            }
        }
    }

    /// Everything a person has proposed, which is what an apply would
    /// have to carry out.
    #[must_use]
    pub fn proposed(&self) -> (Vec<&Node>, Vec<&Link>) {
        (
            self.nodes
                .iter()
                .filter(|n| n.origin == Origin::Proposed)
                .collect(),
            self.links
                .iter()
                .filter(|l| l.origin == Origin::Proposed)
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: &str, kind: Kind, origin: Origin) -> Node {
        Node {
            id: id.to_owned(),
            kind,
            label: id.to_owned(),
            detail: String::new(),
            origin,
            pos: (0.0, 0.0),
            live: false,
        }
    }

    fn scene() -> Scene {
        let mut s = Scene::default();
        s.upsert(n("host", Kind::Host, Origin::Observed));
        s.upsert(n("firefox", Kind::Program, Origin::Observed));
        s.upsert(n("eth0", Kind::Interface, Origin::Observed));
        s
    }

    #[test]
    fn re_reading_the_machine_does_not_scatter_a_layout() {
        // Someone arranges the canvas, the poll refreshes, and everything
        // they moved jumps back. That would make the canvas unusable for
        // its main purpose.
        let mut s = scene();
        s.node_mut("firefox").unwrap().pos = (400.0, 120.0);
        let mut fresh = n("firefox", Kind::Program, Origin::Observed);
        fresh.detail = "pid 4321".to_owned();
        fresh.live = true;
        s.upsert(fresh);
        let f = s.node("firefox").unwrap();
        assert_eq!(f.pos, (400.0, 120.0), "position must survive a refresh");
        assert_eq!(f.detail, "pid 4321", "but the facts must update");
        assert!(f.live);
        assert_eq!(s.nodes.len(), 3, "and it must not be duplicated");
    }

    #[test]
    fn a_running_program_cannot_be_deleted_from_the_picture() {
        // Deleting it would be a claim about the machine rather than a
        // change to the plan, and the program would carry on regardless.
        let mut s = scene();
        assert!(!s.remove("firefox"));
        assert!(s.node("firefox").is_some());
        s.upsert(n("wg0", Kind::Tunnel, Origin::Proposed));
        assert!(s.remove("wg0"), "something proposed can be taken back");
    }

    #[test]
    fn removing_a_node_takes_its_links_with_it() {
        let mut s = scene();
        s.upsert(n("wg0", Kind::Tunnel, Origin::Proposed));
        assert!(s.connect("firefox", "wg0", Origin::Proposed));
        assert!(s.remove("wg0"));
        assert!(s.links.is_empty(), "a link to nothing is not a link");
    }

    #[test]
    fn a_node_cannot_be_joined_to_itself_or_joined_twice() {
        let mut s = scene();
        assert!(!s.connect("firefox", "firefox", Origin::Proposed));
        assert!(s.connect("firefox", "eth0", Origin::Proposed));
        assert!(
            !s.connect("firefox", "eth0", Origin::Proposed),
            "already joined"
        );
        assert!(
            !s.connect("eth0", "firefox", Origin::Proposed),
            "the other way round too"
        );
        assert_eq!(s.links.len(), 1);
        assert!(!s.connect("firefox", "nowhere", Origin::Proposed));
    }

    #[test]
    fn a_link_the_machine_reported_cannot_be_drawn_away() {
        // The same reasoning as deleting a program: a link that is there
        // because traffic is flowing does not stop flowing because
        // somebody deleted the line.
        let mut s = scene();
        s.connect("firefox", "eth0", Origin::Observed);
        assert!(!s.disconnect("firefox", "eth0"));
        assert_eq!(s.links.len(), 1);
    }

    #[test]
    fn tidying_is_left_to_right_along_the_path_and_repeatable() {
        let mut s = scene();
        s.upsert(n("wg0", Kind::Tunnel, Origin::Proposed));
        s.upsert(n("1.1.1.1", Kind::Destination, Origin::Observed));
        s.tidy(200.0, 90.0);
        let x = |id: &str| s.node(id).unwrap().pos.0;
        assert!(x("host") < x("firefox"));
        assert!(x("firefox") < x("wg0"));
        assert!(x("wg0") <= x("eth0"), "a tunnel sits with the interfaces");
        assert!(x("eth0") < x("1.1.1.1"));
        let once: Vec<_> = s.nodes.iter().map(|n| (n.id.clone(), n.pos)).collect();
        s.tidy(200.0, 90.0);
        let twice: Vec<_> = s.nodes.iter().map(|n| (n.id.clone(), n.pos)).collect();
        assert_eq!(once, twice, "tidying twice must not move anything");
    }

    #[test]
    fn only_things_that_could_exist_can_be_added_by_hand() {
        assert!(Kind::Tunnel.can_be_added());
        assert!(Kind::Destination.can_be_added());
        assert!(!Kind::Host.can_be_added(), "there is one machine");
        assert!(!Kind::Internet.can_be_added(), "and one internet");
        assert!(
            !Kind::Program.can_be_added(),
            "you cannot invent a running program"
        );
        assert!(!Kind::Interface.can_be_added());
    }

    #[test]
    fn the_proposal_is_separable_from_the_observation() {
        // An apply carries out the proposal and nothing else, so the two
        // have to be distinguishable without guessing.
        let mut s = scene();
        s.upsert(n("wg0", Kind::Tunnel, Origin::Proposed));
        s.connect("firefox", "eth0", Origin::Observed);
        s.connect("firefox", "wg0", Origin::Proposed);
        let (nodes, links) = s.proposed();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "wg0");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].to, "wg0");
    }
}
