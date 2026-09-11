#!/usr/bin/env bash
# ============================================================================
# Prove, with real traffic and the real kernel, that a compiled policy routes
# where it says it does.
#
# A rule being present in a ruleset is not evidence that traffic follows it.
# A rule can be present, load cleanly, and never match — that is the single
# most common way per-application routing goes wrong, and it looks exactly
# like success. So every assertion here observes behaviour: which of two
# listeners answered, or a kernel counter.
#
# The trick that makes the answer unambiguous: the SAME destination address
# exists at the far end of both paths, in two separate namespaces. Whoever
# replies tells you which way the packet went. There is nothing to interpret.
#
#   [ tl-app ] --tl-e0---tl-e1-- [ tl-isp ]  10.9.9.9  "ISP"
#        |
#        +------tl-w0---tl-w1-- [ tl-vpn ]  10.9.9.9  "VPN"
#
# Everything happens inside network namespaces. The host's own nftables,
# ip rules and routing tables are never touched — verified: each namespace
# has its own, and destroying the namespace destroys them with it.
#
#   sudo scripts/netns-test.sh          # run every case
#   sudo scripts/netns-test.sh -k mark  # only cases whose name matches
# ============================================================================
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Enter ONLY the network namespace. `ip netns exec` also unshares the mount
# namespace and remounts /sys, which hides /sys/fs/cgroup -- and nft resolves
# cgroup paths when the ruleset loads, so every cgroup rule fails with
# "No such file or directory" while the rule itself is perfectly correct.
netns(){ local n="$1"; shift; nsenter --net="/var/run/netns/$n" "$@"; }
PLAN="${TL_PLAN:-$REPO/target/release/tl-plan}"
CG_ROOT=/sys/fs/cgroup/tl-test
FILTER="${2:-}"
PASS=0; FAIL=0; SKIP=0

die(){ echo "netns-test: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "needs root: it creates network namespaces"
[ -x "$PLAN" ] || die "no tl-plan at $PLAN (cargo build --release -p tl-policy --bin tl-plan)"
command -v ip >/dev/null || die "no ip(8)"
command -v nft >/dev/null || die "no nft(8)"

# ---------------------------------------------------------------- teardown
teardown(){
  for n in tl-app tl-isp tl-vpn; do ip netns del "$n" 2>/dev/null; done
  for d in "$CG_ROOT"/app "$CG_ROOT"/other "$CG_ROOT"; do rmdir "$d" 2>/dev/null; done
}
trap teardown EXIT

# ------------------------------------------------------------------- setup
setup(){
  teardown
  ip netns add tl-app; ip netns add tl-isp; ip netns add tl-vpn
  ip link add tl-e0 netns tl-app type veth peer name tl-e1 netns tl-isp
  ip link add tl-w0 netns tl-app type veth peer name tl-w1 netns tl-vpn
  local n
  for n in tl-app tl-isp tl-vpn; do ip netns exec "$n" ip link set lo up; done
  ip netns exec tl-app ip addr add 10.9.1.1/24 dev tl-e0
  ip netns exec tl-isp ip addr add 10.9.1.2/24 dev tl-e1
  ip netns exec tl-app ip addr add 10.9.2.1/24 dev tl-w0
  ip netns exec tl-vpn ip addr add 10.9.2.2/24 dev tl-w1
  ip netns exec tl-app ip link set tl-e0 up
  ip netns exec tl-isp ip link set tl-e1 up
  ip netns exec tl-app ip link set tl-w0 up
  ip netns exec tl-vpn ip link set tl-w1 up
  # One address, two places. The reply identifies the path.
  ip netns exec tl-isp ip addr add 10.9.9.9/32 dev lo
  ip netns exec tl-vpn ip addr add 10.9.9.9/32 dev lo
  ip netns exec tl-app ip route add 10.9.9.9/32 via 10.9.1.2 dev tl-e0
  ip netns exec tl-app ip route add 10.9.9.9/32 via 10.9.2.2 dev tl-w0 table 7401
  # Policy routing makes the return path asymmetric on purpose, which
  # strict reverse-path filtering drops. The test for THAT is a case of its
  # own; every other case needs it out of the way.
  ip netns exec tl-app sysctl -qw net.ipv4.conf.all.rp_filter=2
  ip netns exec tl-app sysctl -qw net.ipv4.conf.tl-w0.rp_filter=2
  ip netns exec tl-app sysctl -qw net.ipv4.conf.tl-e0.rp_filter=2

  mkdir -p "$CG_ROOT"/app "$CG_ROOT"/other

  # Detach the listeners from stdout. Inheriting it makes any pipe on this
  # script (`| tail`) wait for EOF that never comes, which reads exactly
  # like the test suite hanging.
  ip netns exec tl-isp python3 -c "$SERVER" ISP >/dev/null 2>&1 &
  ip netns exec tl-vpn python3 -c "$SERVER" VPN >/dev/null 2>&1 &
  sleep 0.6
}

SERVER='
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.9.9.9", 9999)); s.listen(16)
while True:
    c, _ = s.accept(); c.sendall(sys.argv[1].encode()); c.close()
'
CLIENT='
import socket, sys
try:
    s = socket.create_connection(("10.9.9.9", 9999), 2)
    sys.stdout.write(s.recv(16).decode())
except Exception as e:
    sys.stdout.write("UNREACHABLE")
'

# Run a client inside tl-app, in a named cgroup.
#
# ORDER MATTERS, and not in the obvious direction. `ip netns exec` unshares
# the mount namespace and remounts /sys so that /sys/class/net reflects the
# network namespace — which takes the cgroup tree with it. Writing to
# cgroup.procs from inside the netns fails with "Directory nonexistent",
# and every test then reports a timeout it never reached.
#
# So: join the cgroup FIRST, then enter the namespace. cgroup membership is
# inherited across the netns entry, so the socket is opened by a process the
# kernel already accounts to that cgroup — which is what `socket cgroupv2`
# matches on.
ask(){ # $1 = cgroup leaf name
  local out
  out=$(sh -c "echo \$\$ > $CG_ROOT/$1/cgroup.procs" 2>&1) || {
    echo "CGROUP-FAILED: $out"; return
  }
  out=$(timeout 8 sh -c \
    "echo \$\$ > $CG_ROOT/$1/cgroup.procs && exec nsenter --net=/var/run/netns/tl-app python3 -c '$CLIENT'" \
    2>&1) || { echo "RAN-FAILED: $out"; return; }
  echo "$out"
}

apply_plan(){ # remaining args -> tl-plan
  local nft
  nft="$("$PLAN" "$@" 2>/tank/scratch/tl-plan.err)" || {
    echo "    tl-plan refused:"; sed 's/^/      /' /tank/scratch/tl-plan.err; return 1
  }
  # `nft -f` MERGES into an existing table rather than replacing it, so a
  # second apply would stack duplicate rules. Recreate it every time: the
  # bare `table` line creates it if absent, making the delete always valid.
  { printf 'table inet throughline\ndelete table inet throughline\n'; printf '%s' "$nft"; } \
    | netns tl-app nft -f - || return 1
  ip netns exec tl-app ip rule add fwmark 0x7401 lookup 7401 priority 1000 2>/dev/null
  return 0
}

clear_plan(){
  netns tl-app nft delete table inet throughline 2>/dev/null
  ip netns exec tl-app ip rule del fwmark 0x7401 lookup 7401 priority 1000 2>/dev/null
}

check(){ # name, expected, actual
  if [ -n "$FILTER" ] && [[ "$1" != *"$FILTER"* ]]; then SKIP=$((SKIP+1)); return; fi
  if [ "$2" = "$3" ]; then
    PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"
  else
    FAIL=$((FAIL+1)); printf '  FAIL  %s\n        expected %-12s got %s\n' "$1" "$2" "$3"
  fi
}

echo "=== Throughline: routing proven by traffic, in network namespaces"
setup

# -------------------------------------------------------------------------
echo
echo "-- baseline"
check "no policy: traffic takes the default route" ISP "$(ask app)"

# -------------------------------------------------------------------------
echo
echo "-- a selected program is rerouted, an unselected one is not"
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --cgroup tl-test/other \
           --rule cgroup:tl-test/app=vpn:tl-w0 --default direct
check "selected cgroup leaves by the tunnel"      VPN "$(ask app)"
check "unselected cgroup is untouched"            ISP "$(ask other)"
clear_plan
check "after revert, the selected one is normal"  ISP "$(ask app)"

# -------------------------------------------------------------------------
echo
echo "-- a cgroup selector must not match a sibling or the parent"
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/other \
           --rule cgroup:tl-test/other=vpn:tl-w0 --default direct
check "the named sibling is rerouted"             VPN "$(ask other)"
check "the other sibling is not"                  ISP "$(ask app)"
clear_plan

# -------------------------------------------------------------------------
echo
echo "-- everything goes by the tunnel except what is excluded"
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --default vpn:tl-w0
check "the default path applies to any program"   VPN "$(ask app)"
clear_plan

# -------------------------------------------------------------------------
echo
echo "-- an excluded address stays on the normal route"
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --admin 10.9.9.9 --default vpn:tl-w0
check "an excluded destination is not rerouted"   ISP "$(ask app)"
clear_plan

# -------------------------------------------------------------------------
echo
echo "-- strict reverse-path filtering breaks policy routing silently"
ip netns exec tl-app sysctl -qw net.ipv4.conf.all.rp_filter=1
ip netns exec tl-app sysctl -qw net.ipv4.conf.tl-w0.rp_filter=1
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --default vpn:tl-w0
check "with rp_filter strict the reply is dropped" UNREACHABLE "$(ask app)"
ip netns exec tl-app sysctl -qw net.ipv4.conf.all.rp_filter=2
ip netns exec tl-app sysctl -qw net.ipv4.conf.tl-w0.rp_filter=2
check "with rp_filter loose the same plan works"   VPN "$(ask app)"
clear_plan

echo
echo "-- and the compiler refuses to emit that plan in the first place"
if "$PLAN" --bare --iface tl-w0 --rp-filter all=1 --rp-filter tl-w0=1 \
           --default vpn:tl-w0 >/dev/null 2>&1; then
  got=allowed; else got=refused; fi
check "a strict-rp_filter plan is refused"         refused "$got"

# -------------------------------------------------------------------------
echo
echo "-- a rule naming a cgroup that is not there is refused"
if "$PLAN" --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --rule cgroup:tl-test/ghost=vpn:tl-w0 \
           --default direct >/dev/null 2>&1; then
  got=allowed; else got=refused; fi
check "a missing cgroup is refused"                refused "$got"

# -------------------------------------------------------------------------
echo
echo "-- applying twice must not stack duplicate rules"
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --rule cgroup:tl-test/app=vpn:tl-w0 --default direct
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --rule cgroup:tl-test/app=vpn:tl-w0 --default direct
n=$(ip netns exec tl-app nft list table inet throughline | grep -cE 'meta mark set 0x')
check "one mark rule after two applies"           1 "$n"
check "and it still routes correctly"             VPN "$(ask app)"
clear_plan

# -------------------------------------------------------------------------
echo
echo "-- revert leaves nothing behind"
apply_plan --bare --iface tl-w0 --rp-filter all=2 --rp-filter tl-w0=2 \
           --cgroup tl-test/app --rule cgroup:tl-test/app=vpn:tl-w0 --default direct
clear_plan
t=$(netns tl-app nft list tables | wc -l)
r=$(ip netns exec tl-app ip rule show | grep -c fwmark)
check "no tables left"                            0 "$t"
check "no fwmark rules left"                      0 "$r"
check "traffic is back to normal"                 ISP "$(ask app)"

# -------------------------------------------------------------------------
echo
echo "-- the host itself was never touched"
check "host has no throughline table" 0 \
  "$(nft list tables 2>/dev/null | grep -c throughline)"
check "host has no fwmark rules"      0 "$(ip rule show | grep -c fwmark)"

echo
echo "=== $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
