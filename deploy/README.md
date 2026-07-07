# Deploy notes

## Build the image

From the repo root (the Dockerfile lives in `deploy/`, but the build context is the root):

```sh
docker build -f deploy/Dockerfile -t preflight402 .
```

## Run

```sh
docker run --rm -p 8000:8000 preflight402
curl http://localhost:8000/healthz
```

## Target (per build plan M2.2)

Hetzner CX (primary) via compose/systemd, one Fly.io machine as a second probe
region later. Uptime monitoring via healthchecks.io free tier.
