# Throughline

Every connection this Linux machine has, attributed to the thing that
opened it, drawn as the path the traffic actually takes.

Today it **observes**. It does not change a route, start a tunnel, or
touch a firewall rule, and the UI says so on every screen. Routing
control is the next phase and is deliberately not half-built here.

```
cargo run --release -p tl-serve        # http://127.0.0.1:7644
sudo cargo run --release -p tl-serve   # see other users' processes too
```

It binds loopback by construction — there is no flag to make it listen on
an interface. A screen that enumerates every process on the host and
everything it talks to is a reconnaissance report.

## What it shows

Five lanes, left to right, wired together by real edges from the
snapshot:

| Lane | What's in it |
| --- | --- |
| Device | this host |
| Software | the process/service/container that opened each connection |
| Local hop | Tor SOCKS, DNS, Privoxy — the first hop of a path, not a destination |
| Interface | the local address traffic is actually egressing from |
| Destination | the remote peers |

Click any node to follow one path; everything not upstream or downstream
of it dims. Wire thickness is the number of connections on that link, on
a log scale — one link on this host carries 96 DNS lookups and another
carries 1.

Two tables sit alongside: **connections this machine opened**, and
**reaching in from the network**, kept separate on purpose.

## Direction is reconstructed, not read

`/proc/net/tcp` records a socket's *state*. It does not record who
dialled. Two things recover it, in `snapshot.rs`:

* `SYN-RECV` is unambiguous — it is the state of a connection we are
  *accepting*. Nothing we dial is ever in it.
* otherwise, a connection whose local socket matches one of this host's
  listeners was accepted on that listener.

This matters more than it sounds. Before it existed, 38 inbound hits on
`:443` and `:22` were drawn in the "what is my machine connecting out to"
lane — strangers' addresses presented as destinations we had chosen. The
whole claim of the tool is that the arrows are right.

Three details that are easy to get wrong and are each pinned by a test:

* **Loopback is decided first.** Put the listener check above it and the
  41 localhost clients of a local database report as "something reached
  into this machine". Nothing crossed an interface, so nothing is inbound.
* **Listeners are matched on address, not just port.** A listener on
  `127.0.0.1:8080` accepts nothing from the network, so an outbound
  connection assigned local port 8080 must not read as inbound.
* **v4-mapped addresses are flattened before comparing.** A dual-stack
  listener is `::` while the accepted socket is `::ffff:203.0.113.7`;
  raw equality misses every one of them.

## Attribution

A socket inode is the join key: every process's `/proc/<pid>/fd/*` that is
a socket symlinks to `socket:[<inode>]`, so one pass over `/proc` builds
inode → pid.

A pid alone is `3231998`, which answers nothing, so `/proc/<pid>/cgroup`
is read as well — it distinguishes a daemon you installed from the
browser you have open from a container. Containers are checked **first**,
because a docker scope also lives under `system.slice` and checking
systemd first labels every container a service.

`unowned` is a real answer and is displayed as one: inode 0 (kernel-side
sockets with no file, such as TIME-WAIT and SYN-RECV), or a live inode
whose process belongs to another user while running unprivileged. Showing
those blank would under-report what is connected, which is the one thing
this tool must not do.

## Known blind spots

Stated rather than discovered later:

* **UDP has no LISTEN state**, so `Listeners` and the "listening" count are
  TCP-only. A bound UDP socket — `:53`, WireGuard's `:51820` — is not
  counted, and a UDP flow's direction falls back to loopback-or-outbound.
* **Kernel-side traffic is invisible.** WireGuard moves packets inside the
  kernel with no socket and no process, so a WireGuard tunnel does not
  appear at all. This matters for the VPN phase and is the first thing it
  has to solve.
* **Each lane shows at most 20 nodes** and says `+ N more not shown` when
  it trims. Wires to trimmed nodes are not drawn.
* **A snapshot is a moment.** Short-lived connections between two 3-second
  polls are never seen. This is a picture of what is open, not a log of
  what happened.

## Verifying the UI

```
node scripts/verify-gui.mjs http://127.0.0.1:7644/ /tmp/shot
```

Drives a real browser and asserts what a person would see, at three
widths: no sideways scroll, no cell past the panel edge, every lane
populated, no console errors, and — the one that matters — that clicking
a node lights **exactly** the destinations that node's flows actually
reached, checked against `/api/snapshot`.

That last check is not decoration. An earlier version followed graph
edges forward from the shared interface node, so clicking one editor
session lit 16 destinations when it had touched 3, two of them Tor guard
relays that only `tor` talks to. A check against the page's own data
structures would have passed while the screen lied; this one reads the
rendered DOM.

Playwright is not vendored (this repo has no dependencies). Point
`TL_PLAYWRIGHT` at any `package.json` whose tree has it.

## Layout

```
crates/tl-inventory   parsing and attribution, no dependencies
  proc_net.rs         /proc/net/{tcp,tcp6,udp,udp6} → Socket
  procs.rs            inode → process → Owner (service / app / container)
  snapshot.rs         Flow, Direction, Listeners, JSON
crates/tl-serve       std-only HTTP on loopback + the UI
```

No third-party crates anywhere. A program that reads every socket on the
machine should be auditable without first auditing a dependency tree.

## Not built yet

* drag-and-drop topology editing
* Tor-over-VPN configuration, and per-app routing control
* RiseupVPN / ProtonVPN integration
* the hops beyond the NIC — ISP, VPN egress, Tor exit — which cannot be
  read from `/proc` and need active probing
* a leak-audit module: OpenVPN bound only to SOCKS ports, no plaintext
  DNS on the physical adapter, egress IP ≠ home IP, `IsTor` confirmed
