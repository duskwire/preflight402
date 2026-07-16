# Deploy

One process serves everything on port **8402**: REST (`/healthz`, `/preflight`)
and MCP streamable-http (`/mcp`), via `preflight402.api.app:app`.

## Current production: Proxmox LXC

Runs in an unprivileged Debian 13 container (`preflight402`, VMID 104,
2 cores / 2 GB / 8 GB, `onboot=1`) on the home Proxmox node, as a hardened
systemd service under a dedicated `preflight402` user. SQLite lives in
`/var/lib/preflight402/`.

Deploy or upgrade from a repo checkout:

```sh
uv build
scp dist/preflight402-*.whl deploy/preflight402*.service \
    deploy/preflight402-healthping.timer deploy/provision.sh root@<ct-ip>:/tmp/
ssh root@<ct-ip> 'sh /tmp/provision.sh'
```

`provision.sh` is idempotent: first run installs python3-venv, creates the
user/venv/env-file/units; later runs just upgrade the wheel and restart.

Recreating the container from scratch (Proxmox shell or API):

```sh
pveam download local debian-13-standard_13.6-1_amd64.tar.zst
pct create <vmid> local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst \
  --hostname preflight402 --cores 2 --memory 2048 --swap 512 \
  --rootfs local-lvm:8 --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --unprivileged 1 --features nesting=1 --onboot 1 \
  --ssh-public-keys ~/.ssh/id_ed25519.pub
pct start <vmid>
```

## Uptime monitoring

Create a free check at [healthchecks.io](https://healthchecks.io), paste its
ping URL into `HEALTHCHECK_PING_URL=` in `/etc/default/preflight402`. The
`preflight402-healthping.timer` (every 5 min) pings the check only when the
local `/healthz` answers, so a dead server = a missed ping = an alert.
Until the URL is set the timer is a silent no-op.

## Public exposure (required before the M2.3 directory listings)

The LXC sits on a home LAN. Do **not** port-forward — that publishes the home
IP. Use an outbound tunnel:

- **Cloudflare Tunnel** (recommended): `cloudflared` in the container maps
  `https://preflight402.<your-domain>` → `http://127.0.0.1:8402` with
  automatic TLS, no open ports. Needs the domain on a (free) Cloudflare zone:
  `cloudflared tunnel create preflight402 && cloudflared tunnel route dns ...`
  then run `cloudflared` as a systemd service.
- Alternative: Tailscale Funnel (fastest to try, tailnet-branded URL).

⚠️ **SSRF once exposed:** `/preflight?url=` (and the MCP tool) probe any URL
the caller supplies and return liveness/headers/body-derived signals. Tunneled
onto the home LAN, a public caller could point it at `http://192.168.x.x/` or
cloud metadata IPs to reconnoitre internal services. Before exposing publicly,
add a private/loopback/link-local/metadata-IP blocklist to the prober (tracked
separately). Until then, expose only if you accept that risk.

Also note: from M3 the scheduler makes ~1,000s of outbound probes per cycle
**from this container's home IP**. Before enabling M3 probing at scale, either
move the instance to a VPS (Hetzner CX, the plan's original target — reuse
`provision.sh` unchanged) or route probe egress elsewhere. Preflight-only
traffic (on-demand, low volume) is fine from home.

## Docker (VPS / Fly.io path)

The container image serves the same combined app:

```sh
docker build -f deploy/Dockerfile -t preflight402 .
docker run --rm -p 8402:8402 -v preflight402-data:/data preflight402
curl http://localhost:8402/healthz
```

The image ships `/data` (owned by the `app` user, `PREFLIGHT402_DB_PATH`
defaulted there) so a named volume works out of the box. A **bind** mount
(`-v /host/dir:/data`) does not inherit that ownership — `chown` the host dir
to the image's `app` uid first, or run with `--user`.
