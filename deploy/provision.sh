#!/bin/sh
# Provision a fresh Debian 12/13 host (VPS or LXC) to run preflight402.
# Idempotent — safe to re-run for upgrades.
#
# Usage (from the repo root, against a host with root SSH access). Build ONE
# wheel and pass its path explicitly so a rebuilt-but-same-version wheel still
# deploys and stale wheels in /tmp can never be picked by mistake:
#   rm -rf dist && uv build
#   scp dist/preflight402-*.whl deploy/preflight402*.service deploy/preflight402-healthping.timer deploy/provision.sh root@HOST:/tmp/
#   ssh root@HOST 'sh /tmp/provision.sh /tmp/'"$(basename dist/preflight402-*.whl)"
# With no argument it picks the highest-version wheel in /tmp (version-sorted).
set -eu

if [ $# -ge 1 ]; then
    WHEEL=$1
    [ -f "$WHEEL" ] || { echo "wheel not found: $WHEEL" >&2; exit 1; }
else
    # sort -V: 0.10.0 > 0.9.0 (plain sort gets this lexicographically wrong).
    WHEEL=$(ls /tmp/preflight402-*.whl 2>/dev/null | sort -V | tail -1)
    [ -n "$WHEEL" ] || { echo "no /tmp/preflight402-*.whl found" >&2; exit 1; }
fi
echo "== installing $WHEEL"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -qy --no-install-recommends python3-venv curl ca-certificates

id preflight402 >/dev/null 2>&1 || \
    useradd --system --home-dir /var/lib/preflight402 --shell /usr/sbin/nologin preflight402
install -d -o preflight402 -g preflight402 -m 0750 /var/lib/preflight402
install -d -m 0755 /opt/preflight402

[ -x /opt/preflight402/venv/bin/pip ] || python3 -m venv /opt/preflight402/venv
# --force-reinstall: pip skips an equal-version wheel, so a rebuilt 0.1.0 with
# fixed code would otherwise be a silent no-op (deps still resolve normally).
/opt/preflight402/venv/bin/pip install --quiet --upgrade --force-reinstall "$WHEEL"

if [ ! -f /etc/default/preflight402 ]; then
    cat > /etc/default/preflight402 <<'ENV'
PREFLIGHT402_ENVIRONMENT=prod
PREFLIGHT402_DB_PATH=/var/lib/preflight402/preflight402.db
# Create a free check at https://healthchecks.io and paste its ping URL to
# activate uptime monitoring (the healthping timer is a no-op until then):
HEALTHCHECK_PING_URL=
ENV
    chmod 0640 /etc/default/preflight402
    chgrp preflight402 /etc/default/preflight402
fi

install -m 0644 /tmp/preflight402.service /etc/systemd/system/
install -m 0644 /tmp/preflight402-healthping.service /etc/systemd/system/
install -m 0644 /tmp/preflight402-healthping.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now preflight402.service preflight402-healthping.timer
systemctl restart preflight402.service

sleep 2
curl -fsS -m 10 http://127.0.0.1:8402/healthz && echo && echo "== preflight402 is up on :8402"
