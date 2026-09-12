# What Throughline is meant to be

Paul's brief, written down so it can be argued with rather than
remembered. Everything here is a requirement unless it says otherwise.

## The shape of the thing

A network lab for **one real machine**. You see your actual host, its
actual programs, its actual interfaces and everything they talk to, laid
out on a canvas like GNS3 or EVE-NG. You rearrange it, add things that do
not exist yet, **run it for real**, and then apply it to the machine if
you want to.

It is a desktop application. Not a browser, not a web page in a window.

## Fixed elements

Some things are always on the canvas because they are always there in
reality:

* **the hardware** — this machine, its NICs
* **the internet** itself

Fixed means "cannot be deleted", not "cannot be moved". Both can be
dragged anywhere, and both can be hidden with an eye icon. Hiding is a
view state; it never changes what is true.

## The element list

A panel down one side listing **every** node in the environment. Each row
has:

* an **eye** — hide/show on the canvas
* a **delete** — where deleting is allowed at all
* room for more per-row controls

Clicking a row **highlights** the thing it names on the canvas. Rows can
be **dragged to reorder**. The list is the authoritative index of what
exists; the canvas is one view of it.

## What can be in the environment

**Anonymity networks**, modelled as networks rather than as single
boxes: Tor and onion routing, I2P, Freenet, GNUnet.

**VPNs**, with the free and open ones first: WireGuard, OpenVPN,
RiseupVPN, ProtonVPN, Bitmask.

**Infrastructure**: servers, routers, switches, the ISP, any VPS.

**Software that is part of the path**: DNS, DHCP, and the transports
themselves — TCP, UDP.

**Target devices** — the things at the far end.

Everything is clickable, inspectable, and configurable. You can change
how any two things interact, and add or remove anything mid-session.

## Prebuilt topologies

A ribbon or toolbar of ready-made arrangements you expand and pick from:
plain VPN, Tor, **Tor over VPN**, **VPN over Tor**, WireGuard, and so on.
One click puts a correct, working arrangement on the canvas.

## Templates that remember

Details are collected automatically where that is possible, and typed in
where it is not. Either way they can be **saved as a template and reused**:

* an ISP — "Verizon", with everything that goes with it — reusable on any
  future topology
* a machine — a laptop or a server, with its OS, hostname, MAC, addresses

Templates live in the box for the kind of thing they describe. A
searchable device library window lists everything you can place, with
**saved templates at the top, starred**, and you click or drag one onto
the canvas.

## Application chrome

File, Edit, Tools, View — the ordinary menus. Topologies **save to
files**.

## Detection

Firewall configuration, IDS, and the rest of the host's real security
posture should be **detected**, not asked for, wherever it can be read.

## Grading

A **ranking and grade for anonymity, privacy and security**, which flags
the parts of a topology that are insecure, that leak identity, or that
are not private. This is the part that makes the tool worth using rather
than pretty: a person should be able to look at a grade and know where
the hole is.

## The standard to hold

Simple enough that somebody with no technical knowledge can use it.
Advanced enough to genuinely configure and administer a network securely.
Both, not a compromise between them.

## Reuse before building: the field, measured

Paul's suggestion, and his standing "reuse before building" rule, both
point at forking an existing FOSS simulator rather than writing a canvas.
Every candidate, measured against the GitHub API on **2026-09-12** —
commits in the preceding 90 days, because a project's own README is not
evidence that anyone is still there:

| Project | Commits/90d | Licence | Language | GUI | Engine |
| --- | --- | --- | --- | --- | --- |
| containerlab | 100+ | BSD-3 | Go | no (a VS Code extension has one) | containers + veth |
| Shadow | 100+ | unclear | Rust | no | deterministic sim; runs real Tor |
| GNS3 | 49 + 19 | **GPL-3** | Python/Qt5 | yes, 208k lines | VMs, dynamips, docker |
| imunes | 58 | unclear | Tcl/Tk | yes, 59k lines | netns + docker |
| vscode-containerlab | 30 | Apache-2 | TypeScript | yes, drag-drop | containerlab |
| **CORE** | **0** | **BSD-2** | Python/tk | yes, 12k lines | **netns — exact match** |
| Kathará | 1 | GPL-3 | Python | no | docker |
| mininet | 0 (since 2024) | BSD-3 | Python | MiniEdit, ancient | netns |
| cloonix | 0 (since 2025) | unclear | C | yes | KVM |

Two more that nobody names in this category but that solve *our* half —
per-application connection visibility and rules, with a GUI —
**OpenSnitch** (39 commits/90d) and **Portmaster** (45). Neither draws a
topology. Both are worth reading for how they attribute a connection to a
process: eBPF, not polling `/proc`, which is also the answer to the
Android blindness above.

Note for anyone reading Paul's original reference list: **netlab
("ipspace") has no GUI at all.** If a look is being pictured from there,
it comes from the blog's diagrams, not from the tool.

The thing none of them do, and which is the whole point here, is **apply
the topology to the real host afterwards**. That part stays ours
whichever way the decision goes.

---

# Two failures found by running it, and what they change

## 1. Termux: nothing appears

Run under Termux on Android with SSH sessions open, and the screen is
empty.

Android restricts `/proc/net/tcp` and `/proc/net/tcp6` for unprivileged
processes — from Android 10 they read back header-only. That is why `ss`
and `netstat` show nothing there either. `snapshot::collect()` returns
zero flows, and the UI faithfully reports zero.

The code is correct. **The product is not.** "Nothing is connected" and
"this platform will not let me look" render identically, and that is the
one failure this tool exists not to commit: `lib.rs` says in as many
words that a view which silently drops rows is worse than no view,
because it is trusted.

## 2. The page cannot be reached from the phone

`127.0.0.1:7644` on a phone is the phone. The server binds loopback only
with no flag to change it.

**This one dies with the browser.** It is a property of shipping a web
server, and the tool is not going to be a web server. Noted and then
dropped.

## The one that does NOT go away

Failure 1 is not about the browser at all. It is about `/proc`, and a
native binary reading `/proc` without privilege on Android — or in a
container, or as an ordinary user — goes exactly as blind. The front end
does not enter into it.

Underneath it: **the tool does not verify its own instrument.** It
reports what it managed to read without ever asking whether reading
worked. That flaw travels intact into the native app unless it is fixed
in the core, which is where the fix belongs.

- If the socket tables parse to zero rows while `/proc/net/dev` shows
  interfaces that have carried packets, they are being withheld, not
  empty. Say so.
- If no `/proc/<pid>/fd` outside our own is readable, we are
  unprivileged. That is the difference between "nothing is connected" and
  "I can only see myself". Say which.
- Name Android when it is Android, because the remedy there is different
  and a person will otherwise assume the tool is broken.
- *Cannot see* is a first-class state on screen, never an empty list.

# The plain summary

What exists today does not work for the person it was built for. It
cannot be reached from the device he administers from, and where it can
be reached it reports an empty machine without saying it is blind. The
rewrite is not polish.

# The question this forces: where does it run? — ANSWERED

Paul administers this machine from a phone, over SSH. A native desktop
GUI needs a display. A headless server has none. So "make it native" and
"use it on the server" pulled in opposite directions, and the Termux
session that found failure 1 looked like a requirement.

It was not. Paul, asked directly: *"i was just testing it, we need a GUI
primarily but we can also make a TUI also."*

So:

1. **The GUI is the product.** It runs where there is a display — a
   laptop — and reads the host it is pointed at, which may be this one
   over SSH. That also gives "plan another machine from this one" for
   free.
2. **A TUI comes after it**, for a server over SSH with no display. Not
   a fallback for a failed GUI: a second front end on the same core.
3. X forwarding is not a plan.

Both share everything below the front end, which is the whole argument
for keeping `tl-inventory`, `tl-detect`, `tl-policy`, `tl-sim` and
`tl-grade` free of any UI at all. A core crate that cannot be driven by
a TUI has a bug, not a feature.

# What this host actually has, that the tool says nothing about

Measured, not assumed:

| Thing | State |
| --- | --- |
| WireGuard `wg0` | present |
| Tor | active |
| CrowdSec | active |
| Suricata | active |
| systemd-resolved | holds `127.0.0.53` |
| IPv4 edge | `default via 37.27.100.1 dev eth0` |
| IPv6 edge | `default via fe80::1 dev eth0` |
| Snort, fail2ban | absent |

Every row is something a person would want on the canvas, and none of it
is detected today. This is the concrete content of "it does not detect
any networks".

---

# Decisions taken

## Engine AND front end: fork CORE

[CORE](https://github.com/coreemu/core) (Common Open Research Emulator),
BSD-2-Clause, Python + C.

It already does the entire "actually simulate" half of the brief:
topologies built from Linux network namespaces, link impairment
(bandwidth, delay, loss, jitter), real applications running inside nodes,
and an **RJ45 node that bridges the emulated topology to a real host
interface**. Its own GUI drives all of it through a gRPC API.

### ⚠ Correction: CORE is not actively maintained

An earlier version of this file said "actively maintained". **That was
false, and the decision to build on CORE was taken on the strength of
it.** Measured on 2026-09-12 against the GitHub API:

* last commit on the default branch **2025-05-19** — 16 months
* **0** commits in the preceding 90 days
* 12,240 lines of Python/tkinter GUI, 37,156 lines of Python daemon,
  plus C helpers

The decision survives the correction, because Paul asked three times to
fork an existing simulator rather than write one, and among the
permissively-licensed candidates CORE is the only one whose execution
model (network namespaces) is the one this tool needs. But the cost is
now stated honestly: **forking a dormant project means owning it.**

### What was verified before committing to the fork

Not assumed — run, read, and measured:

* **The GUI is a client, not a canvas.** `CanvasNode.__init__` takes a
  `core.api.grpc.wrappers.Node`; the thing on the screen *is* a gRPC
  object. Started without a daemon it renders an empty grid, a menu bar
  containing only *Help*, and a `Setup Error` dialog. There is no
  "borrow the canvas and leave the rest" option: a fork ships the
  daemon.
* **Our facts fit without patching its protobuf.** `Node` has no
  free-form field, but `Session.metadata` is a persisted
  `map<string, string>`, and `CustomNodesDialog` defines node types by
  name and icon. So a pid, a live flow, a grade, and node kinds like
  Tor / WireGuard / ISP all ride in its own save format.
* **Its build does not work against current dependencies.** Generating
  its gRPC stubs today produces gencode 7.35.1 against a 5.29.3 runtime
  and the GUI dies on import. Their own pins are required
  (`grpcio 1.69.0`, `protobuf 5.29.3`). This is the first thing 16
  dormant months costs you, and it will not be the last.
* **The daemon needs C helpers.** `vnoded` and `vcmd`, built with
  autotools from `netns/`, are hard requirements, alongside `ip`, `nft`,
  `tc`, `ethtool`, `mount` and `sysctl`.

### Where each piece runs

The GUI and `core-daemon` run together on the machine with a display —
a laptop — with the daemon in a container or VM. The host being read and
configured is reached over SSH by the Rust binaries, which need no
daemon and no display.

This keeps CORE's networking entirely away from any production machine
while still letting the canvas plan one.

What stays ours: reading the real host, detecting its networks, grading a
topology, and applying it. CORE does none of that and is not trying to.

**The cost, stated:** Throughline stops being one static binary. It gains
a Python daemon, C helpers, and a dormant upstream.

## Front end: CORE's, modified

Not our own canvas. The conventions worth keeping from GNS3 are still
the target — per-link-END status in **colour and shape** (green round up,
red square down, so it survives colourblindness), marquee select,
middle-drag pan, Ctrl+wheel zoom — but they get implemented inside the
forked GUI rather than in a canvas written from scratch.

Everything below the front end stays UI-free, so the TUI can sit on the
same core. A core crate that cannot be driven by a TUI has a bug.

## ⚠ CORE must not be installed on this host as-is

From CORE's own install documentation:

> If Docker is installed, the default iptable rules will block CORE
> traffic — `sudo iptables --policy FORWARD ACCEPT`

This machine runs ~50 containers behind an nftables baseline whose
FORWARD chain is **default DROP with explicit per-container accepts**,
and it has already lost docker's chains silently for 32 days once.
Setting FORWARD to ACCEPT on a production mail and web server to run an
emulator is not an acceptable trade.

CORE also installs a **root systemd daemon** and manipulates host
networking.

So:

* Develop against CORE's `.proto` definitions, which need no
  installation.
* Run `core-daemon` in a **container or a VM**, never on the host, and
  never on this one.
* The shipped tool must **detect** whether a daemon is reachable and say
  so plainly rather than failing obscurely — and must never instruct a
  user to open their FORWARD policy.
