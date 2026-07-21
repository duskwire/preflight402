# Directory listing checklist (M2.3)

Status as of 2026-07-21 — several steps are DONE; the rest are website forms
that need an interactive login, written to hand off.

## 0. GitHub — ✅ DONE

Public at <https://github.com/duskwire/preflight402> (duskwire org, maintainer
account `sodadsmc`).

## 1. Official MCP Registry — ✅ DONE

Published as **`io.ironshell/preflight402`** via DNS-verified domain auth
(`ironshell.io` TXT record `v=MCPv1; k=ed25519; …`, added through the
Cloudflare API). Verify:

```sh
curl "https://registry.modelcontextprotocol.io/v0/servers?search=preflight402"
```

To publish a new version later: bump `version` in `server.json`, then from a
box with the DNS-auth Ed25519 private key (kept out of the repo):

```sh
mcp-publisher login dns --domain ironshell.io --private-key <hex>
mcp-publisher publish
```

## 2. PyPI — ⏳ built, needs a token

Both wheels build and pass `twine check`:
- `preflight402` (the MCP server; enables `uvx --from preflight402 preflight402-mcp`)
- `preflight402-guard` (the client-side payment guard; `pip install preflight402-guard`)

To publish, from a checkout with a PyPI API token in `~/.pypirc` or `TWINE_*`:

```sh
uv build                              # server -> dist/
(cd guard && uv build)                # guard  -> dist/ (workspace shares dist/)
uv run --with twine python -m twine upload dist/*
```

(The README's `uvx`/`pip install` instructions assume this is done.)

## 3. awesome-agentic-commerce — ✅ PR OPEN

PR <https://github.com/Merit-Systems/awesome-agentic-commerce/pull/492> — two
entries (Open Source & SDKs + Security & Ops). Awaiting maintainer merge.

## 4. Glama — automatic (claim optional)

Glama crawls public GitHub MCP repos within minutes of a push; `glama.json`
(maintainer `sodadsmc`) lets you claim + customize the auto-created listing at
glama.ai — authenticate with GitHub and edit there. Adding an `mcp-server`
GitHub topic to the repo helps discovery.

## 5. Smithery — website, paste the URL (user step)

1. <https://smithery.ai/new>
2. Paste `https://preflight402.ironshell.io/mcp`
3. Smithery auto-scans the endpoint and extracts the `preflight` tool.

## 6. PulseMCP — automatic (or form)

Ingests the official registry (step 1 covers it, weekly). To list immediately:
<https://www.pulsemcp.com/submit> → repo URL, select **Server**.

---

Acceptance (build plan M2.2/2.3): listed in ≥3 directories. Registry (done) +
Glama (auto) + the awesome PR already clear it; Smithery + PulseMCP add more.
