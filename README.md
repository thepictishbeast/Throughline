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

## Nothing here is a list of known software

There is no table of well-known ports, no set of proxy names, no
assumption about which services a host runs. Every such table is wrong
twice: it covers only the software whoever wrote it thought of, so your
dnscrypt-proxy or shadowsocks or stunnel is simply missing, and it is
confidently wrong whenever a host uses a port for something else.

So each fact is taken from the machine:

| Question | Where the answer comes from |
| --- | --- |
| What services does this host run? | the ports it listens on, and the process holding each socket |
| What is this port called? | the host's own `/etc/services` |
| Is this bound socket a server or a client mid-query? | the kernel's `ip_local_port_range` |
| Is this a daemon, a desktop app, or a container? | `/proc/<pid>/cgroup` |
| Does traffic into this service go any further? | whether that service has egress of its own |

That last one is what separates a proxy from a database without naming
either. Traffic into a forwarding service continues out through its
sockets; traffic into a terminus stops there. A list of "known proxy
ports" cannot tell them apart on a host it has never seen.

Where `/etc/services` and the process disagree, the process wins — it is
what actually holds the socket — and the disagreement is worth seeing.

## What it shows

Five lanes, left to right, wired together by real flows:

| Lane | What's in it |
| --- | --- |
| Device | this host |
| Software | the process, service or container that opened each connection |
| Local service | a local port something connected through, named by its holder |
| Interface | the local address traffic is egressing from |
| Destination | the remote peers |

Click any node to follow one path; everything not upstream or downstream
of it dims. Wire thickness is the number of connections on that link, log
scaled, so a link carrying one connection stays visible beside one
carrying a hundred.

Two tables sit alongside — **connections this machine opened** and
**reaching in from the network** — kept apart on purpose. A stranger
hitting your `:443` is not somewhere you chose to connect.

## Direction is reconstructed, not read

`/proc/net/tcp` records a socket's *state*. It does not record who
dialled. Three things recover it:

* `SYN-RECV` is unambiguous — the state of a connection being *accepted*.
  Nothing you dial is ever in it.
* otherwise, a connection whose local socket matches one of this host's
  listeners was accepted on that listener.
* failing both, a socket the kernel holds with no file (inode 0:
  TIME-WAIT) whose local port is outside the ephemeral range was a server
  socket that outlived its listener.

Before any of this existed, inbound hits on `:443` and `:22` were drawn
in the "what is my machine connecting out to" lane — strangers' addresses
presented as destinations the machine had chosen. The whole claim of the
tool is that the arrows are right.

Four details that are easy to get wrong, each pinned by a test:

* **Loopback is decided first.** Put the listener check above it and
  every local client of a local database is reported as "something
  reached into this machine". Nothing crossed an interface, so nothing is
  inbound.
* **Listeners are matched on address, not just port.** A listener on
  `127.0.0.1:8080` accepts nothing from the network, so an outbound
  connection assigned local port 8080 must not read as inbound.
* **v4-mapped addresses are flattened before comparing.** A dual-stack
  listener is `::` while the accepted socket is `::ffff:a.b.c.d`; raw
  equality misses every one of them.
* **The orphan rule is narrow.** It applies only to sockets with no
  process and no listener, because treating every orphan as inbound
  re-creates the same bug pointing the other way.

## UDP is not TCP

UDP never enters LISTEN. A UDP service is just a bound socket with no
peer — and so is a client halfway through a query. Counting only LISTEN
hid the resolver, mDNS, NTP and QUIC entirely; counting every peerless
UDP socket would have invented hundreds of services out of client
sockets. On one development host that is 11 real services against 205
clients.

The kernel's own `ip_local_port_range` separates them: a port the kernel
hands out for outgoing traffic belongs to a client, anything else was
bound deliberately. It is read, not assumed, because it is tunable.

## Attribution

A socket inode is the join key: every `/proc/<pid>/fd/*` that is a socket
symlinks to `socket:[<inode>]`, so one pass over `/proc` builds
inode → pid.

A pid alone answers nothing, so `/proc/<pid>/cgroup` is read too — it
distinguishes a daemon from a desktop app from a container. Containers
are checked **first**, because a docker scope also lives under
`system.slice` and checking systemd first labels every container a
service.

When several processes hold one socket — a forking server's master and
its workers — the lowest pid wins. Letting directory order decide made
the displayed owner change between two scans of an unchanged machine.

`unowned` is a real answer and is displayed as one: inode 0, or a live
inode whose process belongs to another user while running unprivileged.
Showing those blank would under-report what is connected, which is the
one thing this tool must not do.

## Exposure

It binds loopback by construction — no flag makes it listen on an
interface. That is necessary and not sufficient, so two more things are
handled rather than assumed away:

* **DNS rebinding.** An attacker who controls a domain can point it at
  `127.0.0.1`; a browser then treats their page and this server as one
  origin and can read the whole inventory. The request still carries
  their `Host`, which is checked. A foreign `Host` gets `421`.
* **A client that never finishes.** The accept loop is serial, so one
  silent connection denied the tool to everyone. Read and write timeouts,
  a line-length cap and a header count bound it.

Process names are attacker-controlled — a process names itself — so the
JSON escapes bidirectional and zero-width controls. A name containing
`U+202E` would otherwise render as a different name than the kernel
holds.

## Blind spots

Stated here rather than discovered later:

* **Kernel-side traffic is invisible.** WireGuard moves packets inside
  the kernel with no socket and no process, so a WireGuard tunnel does
  not appear at all. This is the first thing the VPN phase has to solve.
* **Lanes show at most 20 nodes and tables 200 rows**, each saying
  `+ N more not shown`. Wires to trimmed nodes are not drawn.
* **A snapshot is a moment.** Connections that open and close between two
  three-second polls are never seen. This is a picture of what is open,
  not a log of what happened.
* **The ephemeral-range rule is an inference**, not a fact the kernel
  records. A service that binds a low source port for outgoing traffic
  would be misread.

## Verifying the UI

```
node scripts/verify-gui.mjs http://127.0.0.1:7644/ /tmp/shot
```

Drives a real browser and asserts what a person would see, at three
widths: no sideways scroll, no cell past the panel edge, no truncated
detail, every lane populated, no console errors — and, the one that
matters, that clicking a node lights **exactly** the destinations that
node's flows actually reached, checked against `/api/snapshot`.

That last check is not decoration. An earlier version followed graph
edges forward from the shared interface node, so clicking one process lit
16 destinations when it had touched 3, two of them Tor relays that only
`tor` talks to. A check against the page's own data structures would have
passed while the screen lied; this one reads the rendered DOM.

Playwright is not vendored (this repo has no dependencies). Run from a
directory whose `node_modules` has it, or set `TL_PLAYWRIGHT` to any
`package.json` whose tree does.

## Layout

```
crates/tl-inventory   parsing and attribution, no dependencies
  proc_net.rs         /proc/net/{tcp,tcp6,udp,udp6} → Socket
  procs.rs            inode → process → Owner (service / app / container)
  ports.rs            the kernel's ephemeral range
  services.rs         the host's /etc/services
  snapshot.rs         Flow, Direction, Listeners, LocalService, JSON
crates/tl-serve       std-only HTTP on loopback + the UI
```

No third-party crates anywhere. A program that reads every socket on the
machine should be auditable without first auditing a dependency tree.

`TL_PROC` and `TL_SERVICES` override where those are read from, so the
tool also works against a container's bound `/proc` or a captured tree.

## Changing where traffic goes

The second tab is a policy editor. Drag a program into a box — Straight
out, Through the VPN, Through Tor, Tor through the VPN — or click the
program and then the box, which is the same thing without a mouse. The
screen says what each choice means in a sentence, and an expander shows
the exact ruleset for anyone who wants to read it before believing it.

Nothing is applied. The editor produces text: an nftables ruleset, `ip`
commands, and the torrc lines Tor would need.

### What it refuses to produce

The dangerous part of per-application routing is not the rule you meant
to write, it is the four you did not, and each of these is generated
rather than remembered:

* **Your own session.** Capture it and the connection you are typing into
  ends, with no second one. Detected sessions are listed for you to
  confirm, with the evidence for each — not assumed, see below.
* **A tunnel's own packets.** Route a VPN client into its own VPN and it
  can never reach its server.
* **Tor's own traffic.** Send Tor's output into Tor and nothing reaches a
  relay.
* **DNS.** Route an app's TCP through Tor and leave DNS alone, and every
  hostname is still announced in plaintext. The traffic is anonymous and
  the browsing is not, which is worse than either honest alternative
  because it looks like it worked.

It also refuses a cgroup that does not exist. nftables resolves the path
when the ruleset loads and rejects the whole file if it cannot — so a
rule naming a stopped service is not merely inert, it takes every other
rule down with it.

### Why sessions are confirmed rather than detected

There is no reliable way to ask Linux "is this connection authenticated".
Checked on a current Debian host: `/run/utmp` no longer exists,
`/run/systemd/sessions/*` recorded `REMOTE=0` for a session that had
arrived over SSH, and every `sshd-session` process stayed under
`system.slice/ssh.service` whether authenticated or not.

What remains is that sshd drops to the logged-in user's uid once
authentication succeeds. That is good evidence and not a guarantee, so
the editor shows candidates with their evidence and a person ticks them.

This is not fussiness. A TCP connection to port 22 reaches ESTABLISHED
before any password is offered, so every brute-force attempt looks like a
session — and this host had a scanner's address sitting in the list next
to the real one.

## Not built yet

* applying a plan (this build only produces it)
* drag-and-drop editing of the topology diagram itself
* RiseupVPN / ProtonVPN integration
* the hops beyond the NIC — ISP, VPN egress, Tor exit — which cannot be
  read from `/proc` and need active probing
* a leak-audit module: VPN bound only to the expected ports, no plaintext
  DNS on the physical adapter, egress address ≠ home address, Tor
  confirmed
