# bishop-proxy

Bishop's inference proxy. Forwards inference to upstream providers using
Bishop-held credentials, enforces server-side per-user quotas, runs
runtime content classification, surfaces tier verification.

## Status

Public source-available. Production deployment is operated by Bishop AI LLC
at proxy.mybishop.ai.

## Endpoints

- `GET /v1/tier` — server-side tier verification for daemon clients
- `POST /stripe/webhook` — Stripe subscription state updates
- `POST /v1/challenge` — issues an Argon2id proof-of-work challenge for enrollment
- `POST /v1/enroll` — device enrollment with Argon2id PoW
- `POST /v1/messages` — inference forwarding with quota enforcement
- `POST /v1/tier/bind` — bind a Stripe-known user to a device token
- `GET /v1/quota` — daemon-facing quota and usage readback

## Outbound fetch allowlist

`src/lib/outbound-allowlist.ts` installs a `globalThis.fetch` interceptor at
Worker startup (called from the top of `src/index.ts`). Any fetch to a host
not in `ALLOWED_OUTBOUND_HOSTS` (`["api.anthropic.com"]`) throws
`OutboundHostNotAllowed` before the request leaves the Worker.

`ALLOWED_OUTBOUND_HOSTS` is a fixed constant — there is no runtime widening
mechanism. If `ANTHROPIC_BASE_URL` is set to a hostname outside the allowlist,
the first request fails immediately with HTTP 500 and `AnthropicBaseUrlNotAllowed`
(naming the misconfigured hostname) rather than silently routing traffic to an
unintended host.

This is the runtime enforcement of the claim: "bishop-proxy's Worker only
fetches api.anthropic.com — there is no exfiltration surface." A future code
regression that adds an unintended fetch, or a misconfigured env var that points
upstream elsewhere, fails closed before any request body leaves the Worker.

`tests/outbound-allowlist.test.ts` covers: positive (allowed host passes
through), negative-control (disallowed host throws with named error),
misconfigured-base-url (`AnthropicBaseUrlNotAllowed` on first request),
code-path (every fetch call site exercised under wrapper), and idempotence
(double-install does not double-wrap). Modifications require explicit security
review.

## Log content discipline

`src/lib/log.ts` defines the `ProxyLogEvent` type — a typed allowlist for
every log line emitted by the Worker. The shape enumerates fields like
`request_id`, `token_id`, `response_status`, `token_count_in/out`, and
`classification_decision`/`classification_category`. It does **not** include
prompt content, response bodies, or auth headers, and there is no permitted
log path that carries them.

The runtime type guard `isProxyLogEvent` enforces the shape on every emission;
emission outside the typed-allowlist surface is a type error at compile time
and a runtime guard failure at execution. No `console.log` call may be added
outside `log.ts`; all log emissions go through the typed surface.

This is the runtime enforcement of the claim: "bishop-proxy logs operational
metadata only — no prompt content, no response bodies, no auth headers in any
log line."

`test/integration/log-discipline.test.ts` is the audit artifact: it exercises
the request → classification → upstream → response path and asserts that no
log line emitted in that path carries any of the disallowed fields.

## License

The bishop-proxy software in this repository is licensed under the Business
Source License 1.1 (see [LICENSE.md](LICENSE.md)). On the Change Date
(April 16, 2030), it converts to Apache License 2.0.

The outbound-allowlist enforcement file (`src/lib/outbound-allowlist.ts` and
its test suite) is licensed under the Apache License 2.0 (see
[LICENSE-APACHE.md](LICENSE-APACHE.md)), regardless of the Change Date.

> Note: License counsel review pending pre-Wave-1.
