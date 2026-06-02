# MCP Live Smoke — GitHub proxy leg (founder-run)

**W38-S729 · DEV-TOOLING · not an automated gate.**

This recipe proves the one leg that cannot be unit-tested: that the proxy
`/mcp/github` route forwards a real MCP JSON-RPC call to the **live**
`api.githubcopilot.com`, that live GitHub accepts a user PAT (rebuilt from the
`X-Bishop-Upstream-Key` header), and that a real result returns — exercised
against a **throwaway repo (`friday-site`)** through a local `wrangler dev`, with
the PAT never leaving the founder's shell.

What is already covered by CI and so is **not** re-proven here:

- Daemon transport shape (proxy URL + `X-Bishop-Upstream-Key` + no-direct-egress)
  → `test_transport_routes_through_proxy_not_direct` (★3, mocked opener).
- Route auth/quota/SSRF-safe host, token verify, header strip, default-deny
  → proxy vitest suite (`npm test`, green @ CI).
- Gateway gating / per-call approval → daemon unit/structural (§1.18.2a/.2b/.3).

**Only the live proxy → real-GitHub round-trip is unproven** — that is all this
smoke proves. The full daemon → proxy → GitHub live **★4** (through
`gateway.execute`, cert-pinned, real device-token enroll, harness built once for
all 82 servers) is **W13.16**, not this doc.

---

## Prerequisites

1. A **GitHub Personal Access Token** scoped only to the throwaway repo
   (`repo` / issues write is enough), loaded into the founder's shell so it is
   never pasted, echoed, or written to disk:
   ```bash
   read -rs BISHOP_GITHUB_MCP_PAT && export BISHOP_GITHUB_MCP_PAT
   ```
2. A **throwaway repo** named `friday-site` under your GitHub account (any repo
   you don't mind a test issue landing in).
3. `node` ≥ 20 and the proxy deps installed (`npm ci` at the repo root).

`api.githubcopilot.com` is already on `ALLOWED_OUTBOUND_HOSTS`
([src/lib/outbound-allowlist.ts:56](../src/lib/outbound-allowlist.ts#L56)), so a
**local** `wrangler dev` is allowed to make the real outbound call — no allowlist
change, no `wrangler deploy`.

### Local bindings (confirmed against `wrangler.toml`)

`wrangler dev` brings up everything the challenge/enroll/mcp routes need from
`wrangler.toml`, all simulated locally — **no extra setup**:

| Binding | Type | Local-dev behaviour |
|---|---|---|
| `ENROLL_KV` | KV namespace | simulated locally (nonce store) |
| `AUTH_STORE` | Durable Object (`AuthStoreDO`) | local (token issue / verify) |
| `QUOTA_STORE` | Durable Object (`QuotaStoreDO`) | local (flat abuse-quota `/check`) |
| `TIER_CACHE` | Durable Object (`TierCacheDO`) | local (tier read) |
| `AI` | Workers AI | connects to remote, but the challenge/enroll/`/mcp` routes never call it (the classifier is the `/v1/messages` leg only) — the "usage charges" warning is benign for this smoke. |

The only var you must override is **`TARGET_ZERO_BITS`** (the production default is
`10`; set `8` for a fast dev PoW). Put it in `.dev.vars` (gitignored —
[.gitignore:3](../.gitignore#L3)):

```bash
cd <repo-root>            # the bishop-proxy-oss checkout
printf 'TARGET_ZERO_BITS=8\n' > .dev.vars
```

> **PoW speed.** argon2id at the default `TARGET_MEMORY_KIB=65536` (64 MiB) is
> ~0.75 s/hash, so an 8-bit solve (1/256) averages ~1–3 minutes. To make it
> near-instant, lower the memory on **both** sides together — they must match or
> enroll rejects the proof:
> ```bash
> printf 'TARGET_ZERO_BITS=8\nTARGET_MEMORY_KIB=512\n' > .dev.vars
> # then pass the SAME value to the minter: --mem 512   (see step 2)
> ```
> (Locally verified: `TARGET_MEMORY_KIB=512` solves 8 bits in ~2 s / ~370
> attempts.)

---

## The recipe

> The PAT is loaded in the founder's shell as `$BISHOP_GITHUB_MCP_PAT` (via
> `read -rs`); it must never be pasted anywhere or echoed.

**1.** `cd` to the repo, create `.dev.vars` with `TARGET_ZERO_BITS=8` (see above),
then start the local proxy (allows real outbound to `api.githubcopilot.com`,
already on `ALLOWED_OUTBOUND_HOSTS`):
```bash
npx wrangler dev --port 8787
```

**2.** New shell — mint a real device token (challenge → argon2id PoW → enroll).
Add `--mem 512` only if you set `TARGET_MEMORY_KIB=512` in `.dev.vars`:
```bash
export DEVTOKEN=$(node scripts/dev-mint-token.mjs --url http://127.0.0.1:8787 --bits 8 | jq -r .token)
```

**3. Proof-of-life (read):**
```bash
curl -sS -X POST http://127.0.0.1:8787/mcp/github \
  -H "Authorization: Bearer $DEVTOKEN" \
  -H "X-Bishop-Upstream-Key: $BISHOP_GITHUB_MCP_PAT" \
  -H "content-type: application/json" \
  -H "accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```
→ expect a **real** GitHub tool list (e.g. `create_issue`, `get_me`,
`list_issues`).
- `401 token_*` = enroll/token problem (re-mint in step 2).
- `400 mcp_upstream_key_missing` = the `X-Bishop-Upstream-Key` header is missing.
- an upstream error from GitHub = the PAT or its scope.

**4. Write proof (on the throwaway repo):**
```bash
curl -sS -X POST http://127.0.0.1:8787/mcp/github \
  -H "Authorization: Bearer $DEVTOKEN" \
  -H "X-Bishop-Upstream-Key: $BISHOP_GITHUB_MCP_PAT" \
  -H "content-type: application/json" \
  -H "accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"owner":"<your-gh-username>","repo":"friday-site","title":"bishop live-confirm"}}}'
```
→ expect a **real** issue (URL + number). **Eyeball it on GitHub** — that is the
end-to-end proof.

**5. Teardown:**
- close the test issue;
- `unset BISHOP_GITHUB_MCP_PAT`;
- revoke the PAT in GitHub settings when finished (least-lifetime);
- stop `wrangler dev` and remove the dev file: `rm -f .dev.vars`.

---

## What the route does with the call (for reference)

`/mcp/github` ([src/routes/mcp.ts](../src/routes/mcp.ts)):

1. parse Bearer → `AuthStoreDO /verify-token` (the `$DEVTOKEN` from step 2);
2. `server_id` (`github`) → `MCP_SERVER_SPECS` spec
   ([src/lib/mcp-specs.ts](../src/lib/mcp-specs.ts)); host = `spec.host`
   **server-side**, never from the request (SSRF-safe);
3. rebuild upstream `Authorization: Bearer <PAT>` from `X-Bishop-Upstream-Key`;
   every client identifier stripped — only `content-type` + `accept` survive
   (Pillar 1);
4. flat abuse-quota `/check` (no tier-cost — MCP is not model inference);
5. forward the raw JSON-RPC body to `https://api.githubcopilot.com/mcp/`,
   SSE-passthrough; metadata-only audit (no PAT, no body logged).

The minter (`scripts/dev-mint-token.mjs`) is **dev-only** and never imported by
`src/`. The PAT lives only in the founder's shell and the
`X-Bishop-Upstream-Key` header the route already strips from logs.
