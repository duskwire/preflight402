# Directory listing checklist (M2.3)

The repo artifacts are in place: [`server.json`](../server.json) (official MCP
Registry manifest) and [`glama.json`](../glama.json) (Glama). The steps below
need your accounts, so they're written to hand off. Formats verified 2026-07-16.

**Do the official registry first** — PulseMCP auto-ingests from it and Glama/
Smithery increasingly reference it, so one publish cascades.

## 0. Prerequisite: publish the repo to GitHub

Directories crawl/link the repo. `gh`'s token here is invalid, so from a machine
where you're authed:

```sh
gh repo create <you>/preflight402 --public --source . --push
```

Home resolved 2026-07-21: the repo lives under the `duskwire` org
(maintainer account `sodadsmc`); `server.json`, `glama.json`,
`pyproject.toml`, and both `USER_AGENT` strings already point there.

## 1. Official MCP Registry  →  `server.json` is ready

We namespaced under your domain (`io.ironshell/preflight402`) so you can use DNS
auth — no dependence on the GitHub handle.

```sh
brew install mcp-publisher          # or grab the release binary
mcp-publisher login dns --domain ironshell.io   # add the TXT record it prints
mcp-publisher publish                # pushes server.json
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=preflight402"
```

(You control `ironshell.io` DNS in Cloudflare now, so the TXT record is a
one-liner. Prefer GitHub auth instead? Change `name` to
`io.github.<you>/preflight402` and run `mcp-publisher login github`.)

## 2. Glama  →  automatic

Glama crawls public GitHub MCP repos within minutes of a push. `glama.json`
(with your GitHub username in `maintainers`) lets you **claim + customize** the
auto-created listing at glama.ai — authenticate with GitHub and edit the display
name/description/category there. Adding an `mcp-server` GitHub topic helps
discovery.

## 3. Smithery  →  website, paste the URL

No repo file needed for a hosted server:

1. Go to <https://smithery.ai/new>
2. Paste `https://preflight402.ironshell.io/mcp`
3. Smithery auto-scans the endpoint and extracts the `preflight` tool.

## 4. PulseMCP  →  automatic (or form)

Ingests the official registry daily (weekly processing), so step 1 covers it.
To list immediately: <https://www.pulsemcp.com/submit> → provide the repo URL,
select **Server**.

## 5. awesome-agentic-commerce  →  one-line PR

Repo: <https://github.com/Merit-Systems/awesome-agentic-commerce> (CC0). Add
under the `### Open Source & SDKs` heading:

```
- [preflight402](https://github.com/<you>/preflight402) - MCP server exposing a `preflight(url)` tool that returns a trust/health verdict for x402 payment endpoints. Python, stdio + streamable-http. MIT.
```

Their contributing rule: concise PR description, group under an existing
section. (Secondary fit: the `### Ecosystem` section, which holds other
monitoring/trust tools like x402Scan — lead with Open Source & SDKs since this
is an OSS MCP repo.)

---

Acceptance (build plan M2.2/2.3): listed in ≥3 directories. Registry + Glama +
Smithery + PulseMCP + the PR clears that comfortably once the repo is public.
