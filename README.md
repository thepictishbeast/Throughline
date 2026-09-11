# Throughline

**See everything your Linux machine is talking to, and change where it
goes — by dragging.**

Two screens. The first shows every network connection on the machine and
which program opened it. The second lets you drag a program into a box —
*Straight out*, *Through the VPN*, *Through Tor* — and shows you exactly
what that would do before anything happens.

---

## Try it in two minutes

You need Rust. If you do not have it: <https://rustup.rs>

```bash
git clone https://github.com/thepictishbeast/Throughline
cd Throughline
cargo run --release -p tl-serve
```

Open <http://127.0.0.1:7644>. That is the whole install — no packages, no
config file, no daemon.

Run it with `sudo` to see other users' processes too:

```bash
sudo -E cargo run --release -p tl-serve
```

It listens on your own machine only. There is no flag to change that, on
purpose: a screen listing every program on your computer and everywhere
it connects is a map of your machine, and it does not get a port on the
network.

### Requirements

| | |
| --- | --- |
| Linux | any kernel with cgroup v2 — anything from 2019 onward |
| Rust | 1.85 or newer |
| Everything else | nothing. Zero third-party crates. |

To *change* routing you also need `nftables` and `iproute2`, which nearly
every distribution already has, and a VPN interface or Tor if you want to
use those paths. Throughline does not install or configure either — it
uses what is already there.

## What you will see

**Tab one — what is connected.** Five columns, left to right: this
device, the programs, any local service traffic passes through, the
network interface it leaves by, and where it ends up. Click a program to
light up only its path. Thicker lines carry more connections.

**Tab two — change where it goes.** Drag a program into a box. The page
says in one sentence what the box means, shows the path the traffic would
take in plain words, and lists anything that would stop it working. If
you want the exact firewall rules, there is an expander for that.

The page does not apply it for you — it gives you the command to run. See
**[Applying it](#applying-it)**.

## Applying it

```
sudo tl-plan --default direct \
    --rule cgroup:system.slice/firefox.service=tor \
    --admin 203.0.113.7 \
    --apply --deadman 120
```

Then, within two minutes:

```
sudo tl-plan --confirm     # keep it
sudo tl-plan --revert      # take it back out
sudo tl-plan --status      # what is actually in the kernel right now
```

**If you do not confirm, it undoes itself.** The countdown is held by
systemd, not by the program that applied it — a timer inside that process
would be killed by the very event it exists to detect, because breaking
your own connection tears down your session and everything in it.

**Before you confirm, open a NEW connection and check it works.** Your
existing SSH session still working proves nothing at all: every
connection that was already open is excluded on purpose, so it survives
whether the policy is right or catastrophic. `--verify host:port` makes
the tool do this for you and undo immediately if it fails.

The page does not apply anything itself. This server reads every
process's sockets, so it runs as root; a routing change reachable from a
web request is a different proposition, and a browser can be induced to
treat a loopback server as same-origin. Reading earns that risk behind a
`Host` check. Rewriting the machine's routing does not.

## Is this safe to run?

Reading is always safe: it opens no sockets, writes nothing, and sends
nothing anywhere. The whole first tab is `/proc`.

Changing routes is where care is needed, which is why the tool refuses
more than it accepts. See **[What it refuses to
produce](#what-it-refuses-to-produce)** below.

## Command line

The same compiler the browser uses:

```bash
cargo build --release -p tl-policy --bin tl-plan

./target/release/tl-plan \
    --default direct \
    --rule cgroup:system.slice/firefox.service=tor \
    --admin 203.0.113.7            # the address you are connected from
```

It prints an nftables ruleset on stdout and everything else on stderr, so
`tl-plan ... | nft -f -` does what it looks like. It exits non-zero and
prints nothing if the plan must not be applied.

`tl-plan --help` lists the rest.

---

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

## Proving it actually routes

A rule being present in a ruleset is not evidence that traffic follows
it. A rule can be present, load cleanly, and never match — that is the
most common way per-application routing goes wrong, and it looks exactly
like success.

```bash
cargo build --release -p tl-policy --bin tl-plan
sudo scripts/netns-test.sh
```

This builds three network namespaces and puts the **same destination
address at the far end of both paths**. Whichever listener answers says
which way the packet actually went; there is nothing to interpret. 19
cases: a selected program is rerouted and an unselected one is not, a
cgroup selector does not match its sibling, the exclusions genuinely
exclude, applying twice does not stack rules, revert leaves nothing
behind.

Your own machine is never touched. Each namespace has its own nftables,
ip rules and routing tables, and destroying it destroys them.

Running real traffic through generated rulesets is how three bugs were
found that every unit test had passed — see the commit history for
`ct mark`, `masquerade` and `rp_filter`.

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

* drag-and-drop editing of the topology diagram itself
* applying from the browser (deliberate — see above)
* anything about the far side of a tunnel: whether your provider leaks,
  what a real Tor guard sees, whether the egress address is what you
  think. The namespace suite proves the kernel does what the generated
  text says; it cannot prove the text says the right thing about a
  network it has never seen.
* RiseupVPN / ProtonVPN integration
* the hops beyond the NIC — ISP, VPN egress, Tor exit — which cannot be
  read from `/proc` and need active probing
* a leak-audit module: VPN bound only to the expected ports, no plaintext
  DNS on the physical adapter, egress address ≠ home address, Tor
  confirmed
