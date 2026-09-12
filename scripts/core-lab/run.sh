#!/bin/bash
PY=/opt/core/venv/bin/python
export PYTHONPATH=/opt/core/daemon
mkdir -p /etc/core /var/log/core
mkdir -p /opt/core/etc
cp -n /opt/core/package/etc/logging.conf /opt/core/package/etc/core.conf /opt/core/etc/ 2>/dev/null
cp -n /opt/core/package/etc/core.conf /etc/core/ 2>/dev/null
Xvfb :99 -screen 0 1600x1000x24 >/tmp/x.log 2>&1 &
export DISPLAY=:99
cd /opt/core/daemon
$PY -m core.scripts.daemon >/tmp/daemon.log 2>&1 &
sleep 12
echo "=== daemon listening on 50051?"; ss -ltn 2>/dev/null | grep 50051 || echo "NOT LISTENING"
echo "=== daemon.log:"; tail -12 /tmp/daemon.log
$PY -m core.scripts.gui >/tmp/gui.log 2>&1 &
sleep 20
import -display :99 -window root /out/core-live.png
echo "=== gui.log:"; tail -6 /tmp/gui.log
