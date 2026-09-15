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

## How Throughline's facts get stored, and why it took finding

A node on CORE's canvas has no free-form field: `Node` is id, name,
type, model, position, icon, image, server, services. There is nowhere
to put a pid, a peer list, or a grade.

`Session.metadata` IS a `map<string, string>`, but there is no
set-metadata RPC — searching the proto for one finds nothing, and the
client has no such method. Which makes it look like the facts can only
be stored by STARTING the session, i.e. by actually instantiating
namespaces, which is the opposite of what a drawing wants.

The answer is in how CORE's own GUI does it (`gui/coreclient.py:428`):
it assigns `session.metadata` and calls `start_session(session,
definition=True)`. `definition=True` leaves the session in DEFINITION
state — metadata and nodes are stored, and **nothing is instantiated.**
That one flag is the difference between a drawing and an emulation, and
it is what lets Throughline keep its evidence in CORE's own save format
without patching the protobuf.

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

ICONS = "/opt/core/daemon/core/gui/data/icons"
# CORE ships no icon for an anonymity network, so Tor borrows the tunnel.
# `wlan.png` is the cloud CORE already draws for a wireless network, and a
# cloud is what everyone means by the internet.
ICON = {
    "host": f"{ICONS}/host.png",
    "internet": f"{ICONS}/wlan.png",
    "tor": f"{ICONS}/tunnel.png",
    "container": f"{ICONS}/docker.png",
    "program": f"{ICONS}/pc.png",
}

# A CORE name can become an interface name, so it stays short and plain.
SAFE = re.compile(r"[^A-Za-z0-9]+")


def classify(actor: str, exe: str) -> str:
    """What kind of thing this is, for its icon.

    Deliberately shallow: it reads the unit name and the executable
    path, both of which came from the kernel. Guessing from port numbers
    would be a different kind of claim and is the job of tl-detect.
    """
    a, e = actor.lower(), (exe or "").lower()
    if a.startswith("tor ") or a == "tor" or "/tor" in e:
        return "tor"
    if "docker" in a or "containerd" in a or "/docker" in e:
        return "container"
    return "program"


def label(actor: str, used: set) -> str:
    """The program's own name, not its unit's.

    `claude (tmux-spawn-8bb3f2de-550f-...)` is precise and unreadable.
    The canvas gets `claude`; the unit stays in the metadata, where it
    can be read without being in the way.
    """
    base = SAFE.sub("_", actor.split(" (")[0]).strip("_")[:14] or "unknown"
    name, n = base, 1
    while name in used:
        n += 1
        name = f"{base}{n}"
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
    talkers = sorted(by_actor.items(), key=lambda kv: -len(kv[1]))[:10]

    ifaces = client.InterfaceHelper(ip4_prefix="10.83.0.0/16", ip6_prefix="2001:83::/64")
    core = client.CoreGrpcClient()
    core.connect()
    session = core.create_session()

    # Node carries an `icon` field, but Session.add_node does not accept
    # one -- it builds the Node and drops it. Setting it afterwards works
    # because the wrapper keeps the object, and start_session serialises
    # whatever is on it.
    host = session.add_node(
        1, name="thismachine", _type=NodeType.DEFAULT, position=Position(x=560, y=430)
    )
    host.icon = ICON["host"]
    net = session.add_node(
        2, name="internet", _type=NodeType.SWITCH, position=Position(x=840, y=430)
    )
    net.icon = ICON["internet"]
    session.add_link(
        node1=host, node2=net,
        iface1=ifaces.create_iface(host.id, 0), iface2=wrappers.Interface(0),
    )

    meta = {
        "tl:visibility": json.dumps(vis),
        "tl:node:1": json.dumps({"kind": "host", "origin": "observed"}),
        "tl:node:2": json.dumps({"kind": "internet", "origin": "observed"}),
    }

    used, rows = set(), []
    for i, (actor, flows) in enumerate(talkers):
        kind = classify(actor, flows[0].get("exe", ""))
        name = label(actor, used)
        n = session.add_node(
            i + 3, name=name, _type=NodeType.DEFAULT,
            position=Position(x=170, y=110 + i * 78),
        )
        n.icon = ICON[kind]
        # The link is the claim: this program's traffic leaves through
        # this machine. Drawing the node without it would be a list with
        # extra steps.
        session.add_link(
            node1=n, node2=host,
            iface1=ifaces.create_iface(n.id, 0),
            iface2=ifaces.create_iface(host.id, i + 1),
        )
        # The evidence, kept with the node rather than in a side file, so
        # that saving the topology saves why it looks like that.
        meta[f"tl:node:{i + 3}"] = json.dumps({
            "kind": kind,
            "origin": "observed",
            "actor": actor,
            "pid": flows[0]["pid"],
            "exe": flows[0]["exe"],
            "connections": len(flows),
            "peers": sorted({f["remote"] for f in flows})[:12],
            "ports": sorted({f["rport"] for f in flows})[:12],
        })
        rows.append((len(flows), name, kind, actor))

    session.metadata.update(meta)
    # definition=True: store the nodes, links and metadata, instantiate
    # NOTHING. See the module docstring -- this is the whole trick.
    started, exceptions = core.start_session(session, definition=True)
    if not started:
        print(f"daemon refused the session: {exceptions}")
        sys.exit(1)

    print(f"session {session.id}: {len(talkers)} talkers, {len(outbound)} outbound connections")
    for conns, name, kind, actor in rows:
        print(f"  {conns:3d} conn  {name:14s} {kind:10s} {actor[:40]}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/out/observed.json")
