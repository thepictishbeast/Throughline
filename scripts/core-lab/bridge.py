"""Draw a real machine on CORE's canvas.

This is the proof that the fork is worth making. CORE draws imaginary
labs; every node on its canvas is something somebody invented. This
script takes `tl-observe` output — an actual machine's actual
connections, each attributed to the process that opened it — and makes
CORE draw that instead.

Nothing here is a mock. The JSON comes from reading /proc on a real
host, and the nodes are created through the same gRPC API CORE's own
GUI uses, so whatever this produces is something the GUI can open,
rearrange and save.

Two things are being tested, and they are the two that decide whether
the fork is a fork or a rewrite:

1. Can CORE's canvas hold nodes that stand for real programs rather than
   emulated ones? (It can: a node is an id, a name, a type and a
   position, and nothing forces it to be instantiated.)
2. Can Throughline's facts ride along without patching CORE's protobuf?
   (They can: `Session.metadata` is a persisted `map<string, string>`,
   so every node's evidence is stored under a `tl:` key and comes back
   when the session is reopened.)

Usage, inside the container:

    tl-observe > observed.json          # on the machine being read
    python bridge.py observed.json      # here, next to core-daemon
"""

import json
import re
import sys
from collections import defaultdict

from core.api.grpc import client, wrappers
from core.api.grpc.wrappers import NodeType, Position

# CORE names become interface and namespace names, so they have to be
# short and boring. A program called "claude (tmux-spawn-8bb3f2de-...)"
# is a perfectly good thing for a person to read and a terrible thing to
# hand to `ip link`.
SAFE = re.compile(r"[^A-Za-z0-9]+")


def short(actor: str, used: set) -> str:
    base = SAFE.sub("_", actor).strip("_")[:18] or "unknown"
    name, n = base, 1
    while name in used:
        n += 1
        name = f"{base}_{n}"
    used.add(name)
    return name


def main(path: str) -> None:
    with open(path) as f:
        observed = json.load(f)

    # The first thing read, and the first thing said. An empty flow list
    # from a machine that is withholding its socket tables must never be
    # drawn as an empty network -- that is the exact failure this whole
    # project exists to refuse.
    vis = observed["visibility"]
    print(f"visibility: {vis['sight']} -- {vis['headline']}")
    if not vis["trustworthy"]:
        print("REFUSING to draw: the reading cannot be believed.")
        print(vis["evidence"])
        sys.exit(2)

    outbound = [f for f in observed["flows"] if f["dir"] == "outbound"]
    if not outbound:
        print("nothing is talking off this machine; nothing to draw")
        sys.exit(0)

    # One node per program that is talking off the machine, with its
    # peers gathered behind it. Drawing one node per socket would be
    # honest and unreadable; drawing one per program is what a person
    # actually asked about.
    by_actor = defaultdict(list)
    for f in outbound:
        by_actor[f["actor"]].append(f)
    talkers = sorted(by_actor.items(), key=lambda kv: -len(kv[1]))

    # Every link needs addresses because CORE links are real links. A /16
    # is plenty and keeps each one distinct.
    ifaces = client.InterfaceHelper(ip4_prefix="10.83.0.0/16", ip6_prefix="2001:83::/64")
    core = client.CoreGrpcClient()
    core.connect()
    session = core.create_session()
    print(f"session {session.id}")

    used = set()
    # This machine, in the middle, because everything else is defined by
    # its relationship to it.
    host = session.add_node(
        1, name="thismachine", _type=NodeType.DEFAULT, position=Position(x=560, y=430)
    )
    core.add_node(session.id, host)

    # The internet as one node: it really is one thing from here, and a
    # canvas that draws every peer separately stops being readable at
    # about six.
    net = session.add_node(
        2, name="internet", _type=NodeType.SWITCH, position=Position(x=830, y=430)
    )
    core.add_node(session.id, net)

    meta = {
        "tl:visibility": json.dumps(vis),
        "tl:node:1": json.dumps({"kind": "host", "origin": "observed"}),
        "tl:node:2": json.dumps({"kind": "internet", "origin": "observed"}),
    }

    # And the machine's own way out.
    core.add_link(
        session.id,
        wrappers.Link(
            node1_id=host.id,
            node2_id=net.id,
            iface1=ifaces.create_iface(host.id, 0),
            iface2=wrappers.Interface(0),
        ),
    )

    node_id = 3
    top = talkers[:10]
    for i, (actor, flows) in enumerate(top):
        peers = sorted({f["remote"] for f in flows})
        ports = sorted({f["rport"] for f in flows})
        y = 110 + i * 78
        n = session.add_node(
            node_id,
            name=short(actor, used),
            _type=NodeType.DEFAULT,
            position=Position(x=160, y=y),
        )
        core.add_node(session.id, n)
        # The link is the claim: this program's traffic leaves through
        # this machine. Drawing the node without it would be a list with
        # extra steps.
        link = wrappers.Link(
            node1_id=n.id,
            node2_id=host.id,
            iface1=ifaces.create_iface(n.id, 0),
            iface2=ifaces.create_iface(host.id, i + 1),
        )
        core.add_link(session.id, link)
        # The evidence, kept with the node rather than in a side file, so
        # that saving the topology saves why it looks like that.
        meta[f"tl:node:{node_id}"] = json.dumps(
            {
                "kind": "program",
                "origin": "observed",
                "actor": actor,
                "pid": flows[0]["pid"],
                "exe": flows[0]["exe"],
                "connections": len(flows),
                "peers": peers[:12],
                "ports": ports[:12],
            }
        )
        node_id += 1

    # The client exposes no set-metadata call; metadata travels with the
    # session, which is why it survives a save and comes back with the
    # file. Putting it on the wrapper is how the GUI does it too.
    session.metadata.update(meta)
    print(f"drew {len(top)} talkers, {len(outbound)} outbound connections")
    for actor, flows in top:
        peers = sorted({f["remote"] for f in flows})
        print(f"  {len(flows):3d} conn  {actor[:44]:44s} -> {len(peers)} peer(s)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/out/observed.json")
