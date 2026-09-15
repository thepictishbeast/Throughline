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
echo "=== GUI joining session $SID"
$PY -m core.scripts.gui -s "$SID" >/tmp/gui.log 2>&1 &
sleep 22
import -display :99 -window root /out/core-observed.png
tail -3 /tmp/gui.log
