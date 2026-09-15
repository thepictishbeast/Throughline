# CORE in a container, and why it is in a container

Throughline's canvas is a fork of [CORE](https://github.com/coreemu/core).
CORE's GUI is not a drawing widget that can be lifted out — started with
no daemon it renders an empty grid, a menu bar containing only *Help*,
and a `Setup Error` dialog. The canvas node *is* a gRPC object. So the
fork ships CORE's daemon, and the daemon has to run somewhere.

**It does not run on a host you care about.** From CORE's own install
documentation, on what to do when docker is installed:

> `sudo iptables --policy FORWARD ACCEPT`

That is the opposite of what a machine running containers behind a
default-DROP FORWARD chain needs, and CORE also installs a root systemd
daemon that manipulates host networking. This recipe exists so that
nobody ever has to weigh that trade: the whole stack lives in a
container with **no network of its own** and two capabilities.

```sh
docker build -t tl-corelab scripts/core-lab
docker run --rm --network none \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  -v "$PWD/out:/out" tl-corelab
```

`--network none` gives the container its own empty network namespace, so
every bridge, veth and nftables rule CORE creates is created inside it.
Nothing it does is visible to the host's networking. `NET_ADMIN` and
`SYS_ADMIN` are what `vnoded` needs to make namespaces; `--privileged`
is not required and is not used, because a privileged container can load
modules into the host kernel.

The run script starts Xvfb, the daemon, and the GUI, and writes a
screenshot to `/out`. That is how the GUI gets looked at without a
display attached, and it is the same method the Rust side uses to assert
on rendered pixels rather than on a widget tree.

## Drawing a real machine on it

`bridge.py` takes `tl-observe` output and creates CORE nodes from it over
the same gRPC API the GUI uses. This is the thing no other simulator
does: every node on the canvas stands for a program that is running on a
real machine right now, and the link to `thismachine` is the claim that
its traffic leaves that way.

```sh
tl-observe > out/observed.json                 # on the machine being read
docker run --rm --network none \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  -v "$PWD/out:/out" tl-corelab /run-bridge.sh # here
```

It refuses to draw anything if `visibility.trustworthy` is false. A
machine that is withholding its socket tables must never be rendered as
a machine with nothing running — that is the Termux failure, and it is
refused here as well as in the core.

### The first change to CORE, and what it cost to find

CORE labels both ends of every link with the addresses it invented for
the lab. When the nodes are real programs those addresses are fiction,
and they cover the one label that is true. The Dockerfile turns them off.

It takes **two** edits, not one: `graph/manager.py` sets the defaults in
its constructor and then sets them **back to `True`** in the reset that
runs when a session is joined. Changing only the constructor looks
correct, applies cleanly, and does nothing at all — which is worth
knowing before a larger change is attempted on this codebase.

## What this build had to work around, all of it upstream

CORE's last commit on its default branch is 2025-05-19. None of the
following is in its documentation; each was found by running it:

| Symptom | Cause |
| --- | --- |
| GUI exits silently, empty log | `core.gui.app` has no `__main__`; the entry point is `core.scripts.gui` |
| `ImportError: common_pb2` | gRPC stubs are generated at build time, not shipped |
| `VersionError: gencode 7.35.1 / runtime 5.29.3` | current `grpcio-tools` outruns its pinned `protobuf`; their pins are required |
| `configure: error: grpc tools must be setup in venv` | `configure.ac:83` hard-codes `./venv/bin/python` |
| `ModuleNotFoundError: pyproj` | a hard dependency of `core.location.geo`, pulled in by every session |
| `FileNotFoundError: /opt/core/etc/logging.conf` | the daemon requires a config that only the packaged install puts there |

Each is one line to fix and none is discoverable without hitting it.
That is the standing cost of forking a dormant project, written down
once so the next person does not pay it again.
