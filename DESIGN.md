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

## Open question, deliberately

Paul's suggestion, and his standing "reuse before building" rule, both
point at forking or extending an existing FOSS network simulator rather
than writing a canvas from scratch — taking its GUI conventions, its icon
set, and possibly its whole editor.

This is being evaluated before more of the canvas is written. The
candidates worth weighing are GNS3 (Qt, GPLv3, the interaction model
everyone knows), CORE (already uses Linux network namespaces, which is
exactly the execution model here), Kathará, Containerlab, imunes,
mininet's MiniEdit, and Shadow (which simulates Tor specifically).

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

# The question this forces: where does it run?

Paul administers this machine from a phone, over SSH. A native desktop
GUI needs a display. A headless server has none. So "make it native"
and "use it on the server" pull in opposite directions, and the design
has to answer it rather than pick one and hope.

The honest options:

1. **The GUI runs on the laptop and reads a remote host over SSH.** The
   canvas is local; the machine under inspection is wherever you point
   it. This also gives the "import a topology from another host" feature
   for free, and means one tool can plan several machines.
2. **A TUI for servers.** Works over SSH from Termux, needs no display,
   no X forwarding. The same core crates underneath, a different front
   end. This is the thing that would actually have worked tonight.
3. **X forwarding.** Works, heavy, and poor over a phone.

1 and 2 are complementary and share everything below the front end,
which is the argument for keeping `tl-inventory`, `tl-detect`,
`tl-policy`, `tl-sim` and `tl-grade` free of any UI at all.

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

## Simulation engine: CORE, over gRPC

[CORE](https://github.com/coreemu/core) (Common Open Research Emulator),
BSD-2-Clause, actively maintained, Python + C.

It already does the entire "actually simulate" half of the brief:
topologies built from Linux network namespaces, link impairment
(bandwidth, delay, loss, jitter), real applications running inside nodes,
and an **RJ45 node that bridges the emulated topology to a real host
interface**. Its own GUI drives all of it through a gRPC API, which means
any front end can.

What stays ours: reading the real host, detecting its networks, grading a
topology, and applying it. CORE does none of that and is not trying to.

**The cost, stated:** Throughline stops being one static binary. It gains
a Python daemon that must be installed and running.

## Front end: our own canvas

Rust + egui, borrowing the conventions that GNS3 has already proven —
a named-port picker for links rather than drag-from-handle, per-link-END
status shown in **colour and shape** (green round up, red square down, so
it survives colourblindness), marquee select, Ship/middle-drag pan,
Ctrl+wheel zoom, Delete to delete, explicit align rather than grid snap.

Not CORE's tkinter GUI, which has the right interaction model and the
wrong decade, and is built around imaginary labs rather than a real host.

Everything below the front end stays UI-free, so a TUI for servers can
sit on the same core later.

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
