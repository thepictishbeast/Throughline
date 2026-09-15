#!/bin/bash
# Draw a real machine on CORE's canvas and photograph the result.
#
# Expects /out/observed.json -- the output of `tl-observe` run on the
# machine being read, which is deliberately NOT this container.
PY=/opt/core/venv/bin/python
export PYTHONPATH=/opt/core/daemon
mkdir -p /opt/core/etc /etc/core
cp -n /opt/core/package/etc/logging.conf /opt/core/package/etc/core.conf /opt/core/etc/ 2>/dev/null
cp -n /opt/core/package/etc/core.conf /etc/core/ 2>/dev/null
Xvfb :99 -screen 0 1600x1000x24 >/tmp/x.log 2>&1 &
export DISPLAY=:99
cd /opt/core/daemon
$PY -m core.scripts.daemon >/tmp/daemon.log 2>&1 &
sleep 12
grep -q "listening on" /tmp/daemon.log || { echo "daemon did not start"; tail -5 /tmp/daemon.log; exit 1; }

echo "=== bridge"
$PY /bridge.py /out/observed.json 2>&1 | tail -20
SID=$($PY - <<'PYEOF'
from core.api.grpc import client
c = client.CoreGrpcClient(); c.connect()
print(max(s.id for s in c.get_sessions()))
PYEOF
)
echo "=== round-trip: save the topology and read the facts back out of the FILE"
$PY - "$SID" <<'PYEOF'
import sys, json
from pathlib import Path
from core.api.grpc import client
sid = int(sys.argv[1])
c = client.CoreGrpcClient(); c.connect()
c.save_xml(sid, "/out/observed.xml")
# Read the saved file, not the daemon's memory. The claim being tested
# is that Throughline's evidence survives a save and comes back with the
# topology -- so the test has to go through the file.
xml = open("/out/observed.xml").read()
keys = [l for l in xml.splitlines() if "tl:node:" in l or "tl:visibility" in l]
print(f"  tl: keys found in the saved XML: {len(keys)}")
ok, sid2 = c.open_xml(Path("/out/observed.xml"))
s2 = c.get_session(sid2)
back = {k: v for k, v in s2.metadata.items() if k.startswith("tl:")}
print(f"  reopened session {sid2}: {len(back)} tl: keys came back")
n3 = json.loads(back["tl:node:3"]) if "tl:node:3" in back else {}
print(f"  node 3 evidence survived: actor={n3.get('actor','MISSING')[:38]!r} "
      f"pid={n3.get('pid')} connections={n3.get('connections')}")
assert len(back) >= 3, "metadata did NOT survive the round trip"
print("  ROUND TRIP OK")
PYEOF

echo "=== GUI joining session $SID"
$PY -m core.scripts.gui -s "$SID" >/tmp/gui.log 2>&1 &
sleep 22
import -display :99 -window root /out/core-observed.png
tail -3 /tmp/gui.log
