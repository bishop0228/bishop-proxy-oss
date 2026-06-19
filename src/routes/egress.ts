/**
 * POST /egress/<server_id> — server_id-keyed generic forward egress route
 * (W38-S822-FIX, S5b-1). §3.2-aligned: the upstream host is derived SERVER-SIDE
 * from a frozen spec, NEVER from the request.
 *
 * The §3.2-preserving channel a Bishop worker-microVM reaches the outside world
 * through: the (separate) vsock host-relay (S5b-2) forwards a guest's outbound
 * request here, and the proxy forwards it on — but ONLY to the host bound to the
 * server_id in the path, exactly like the W9.7 /mcp/<server_id> leg. All worker
 * egress still flows through proxy.mybishop.ai, and the frozen
 * CLASS_B_EGRESS_SPECS table is the host boundary.
 *
 * The worker NEVER names the host. The server_id (the path) determines it: a
 * (compromised) worker can reach ONLY its own spec's host, not any other
 * allowlisted host — the cross-server egress / SSRF pattern §3.2 deliberately
 * avoids. Unlike the per-provider inference legs, this is a GENERIC forward — the
 * body is an opaque byte pass-through (no parse, no classifier, no cost meter),
 * so quota is a flat abuse-bound weight of 1.
 *
 *   1. server_id → CLASS_B_EGRESS_SPECS spec (unknown → 404, NO forward — the
 *      fast-fail happens BEFORE any fetch, so no retry-budget delay).
 *   2. Bearer parse + AuthStoreDO /verify-token            (mirror chat-completions).
 *   3. host derive (SSRF-safe):
 *        • FIXED-host spec: host = spec.host — SERVER-SIDE, never from the
 *          request; defense-in-depth asserts host ∈ ALLOWED_OUTBOUND_HOSTS (the
 *          fetch interceptor is the backstop) → 500 if it ever drifts.
 *        • PER-ACCOUNT spec: host = X-Bishop-Upstream-Host (daemon-supplied),
 *          admitted ONLY when it matches THIS spec's OWN anchored hostPattern
 *          (spec-bind). Missing → 400; mismatch → 400 (fail-closed, NO forward).
 *   3b. per-account UPSTREAM HEADER (W38-S888) — a spec MAY declare ONE forwardable
 *       upstream header (xero's Xero-tenant-id, headerTenantFromUpstream). The relay
 *       carries it Bishop-namespaced (X-Bishop-Egress-Header-*); the route reads +
 *       VALIDATES it (anchored pattern) + injects it server-side. Missing → 400;
 *       invalid → 400 (fail-closed, NO forward). The header-target analog of /mcp's
 *       per-tenant PATH substitution. Servers without one are unaffected.
 *   4. flat-weight quota /check (abuse-bound, weight 1, cost 0 — not inference).
 *   5. forward — fetchWithRetry(<host from spec + path>, { method, headers: <Bishop
 *      auth + ALL X-Bishop-* control headers STRIPPED, Pillar 1>, body }). The
 *      installed installFetchAllowlist() is the runtime backstop.
 *   6. emitResponse — metadata-only ProxyLogEvent (request_id + token_id +
 *      status). The daemon Bearer and the body are NEVER logged (Pillar 1).
 *
 * NO real Class B host is added here — the per-worker host-adds are S5c
 * (founder-reviewed, like the W9.7 per-account/fixed-host arcs). Mechanism first.
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import { CLASS_B_EGRESS_SPECS } from "../lib/class-b-egress-specs";
import { ALLOWED_OUTBOUND_HOSTS } from "../lib/outbound-allowlist";
import type { AuthRecord } from "../durable-objects/auth-store";
import {
  ip24From,
  jsonError,
  readTier,
  fetchWithRetry,
  capTypeFromReason,
  capTypeHeaderValue,
  emitError,
  emitRateLimit,
  emitResponse,
} from "./messages";

interface VerifyTokenResult {
  valid: boolean;
  record: AuthRecord | null;
  reason: "not_found" | "revoked" | "expired" | null;
}

/**
 * Rebuild upstream headers for the generic forward. STRIP (Pillar 1):
 *   • authorization — the daemon Bearer (verified here; NEVER leaked upstream),
 *   • every x-bishop-* control header (incl. X-Bishop-Upstream-Host), and
 *   • the hop-by-hop host/content-length (recomputed by the runtime fetch).
 * Everything else survives byte-for-byte.
 *
 * UPSTREAM AUTH (W38-S831 S6b): a net_egress worker's OWN upstream credential
 * (its connected-service OAuth bearer — §3.2 leg 3 "services you connected via
 * your own credential") rides in the daemon-supplied X-Bishop-Egress-Authorization
 * control header, NOT in `authorization` (which carries the daemon Bearer this
 * route verifies + strips — the two would otherwise collide). It is the ONE
 * x-bishop-* header NOT merely dropped: it is TRANSLATED to the upstream
 * Authorization (set AFTER the strip loop so the loop never removes it). A worker
 * that instead carries a non-Bishop auth header (e.g. its own x-api-key) still
 * passes through untouched.
 */
function rebuildEgressHeaders(
  incoming: Headers,
  injectHeader?: { name: string; value: string } | null,
): Headers {
  const out = new Headers();
  const egressAuth = (incoming.get("x-bishop-egress-authorization") ?? "").trim();
  for (const [k, v] of incoming.entries()) {
    const lk = k.toLowerCase();
    if (lk === "authorization") continue; // daemon Bearer — never forwarded
    if (lk.startsWith("x-bishop-")) continue; // ALL Bishop control headers stripped
    if (lk === "host" || lk === "content-length") continue; // recomputed by fetch
    out.set(k, v);
  }
  // The worker's upstream credential → upstream Authorization (set last so the
  // x-bishop-* strip above cannot drop it). Absent → no Authorization forwarded.
  if (egressAuth) out.set("Authorization", egressAuth);
  // W38-S888 — the spec-declared, route-VALIDATED per-account header (xero's
  // Xero-tenant-id) → upstream. Set last for the same reason: the relay carried it
  // as X-Bishop-Egress-Header-*, which the x-bishop-* strip above drops, so the
  // ONLY way it reaches the upstream is this validated server-side injection.
  if (injectHeader) out.set(injectHeader.name, injectHeader.value);
  return out;
}

export async function handleEgress(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  // Step 1 — server_id → frozen spec. The host comes from the spec, NEVER the
  // request (SSRF-safe). Unknown server_id → 404, NO forward — and the fast-fail
  // happens BEFORE any fetch, so there is no fetchWithRetry retry-budget delay.
  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "egress", "<server_id>", ...]
  const serverId = parts[2] ?? "";
  const spec = CLASS_B_EGRESS_SPECS[serverId];
  if (!spec) {
    emitError(requestId, ip, requestSize, 404, "unknown_egress_server", startedAt);
    return jsonError(404, "unknown_egress_server");
  }
  const derivedPath = "/" + parts.slice(3).join("/");

  // Step 2 — Bearer parsing.
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    emitError(requestId, ip, requestSize, 401, "missing_bearer", startedAt);
    return jsonError(401, "missing_bearer");
  }
  const token = auth.slice(7).trim();
  if (token.length < 16) {
    emitError(requestId, ip, requestSize, 401, "malformed_bearer", startedAt);
    return jsonError(401, "malformed_bearer");
  }

  // Step 2b — token verification via AuthStoreDO /verify-token.
  const authStub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const verifyResp = await authStub.fetch("https://internal/verify-token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  const verify = (await verifyResp.json()) as VerifyTokenResult;
  if (!verify.valid || !verify.record) {
    const reason = verify.reason ?? "not_found";
    emitError(requestId, ip, requestSize, 401, `token_${reason}`, startedAt);
    return jsonError(401, `token_${reason}`);
  }
  const tokenId = verify.record.token_id;

  // Step 3 — SSRF-safe host derive (mirror /mcp step 3).
  //  • FIXED-host spec: spec.host is the SOLE source — never the request.
  //    Defense-in-depth: assert it ∈ the static allowlist (the fetch interceptor
  //    is the runtime backstop). A spec whose host is not allow-listed is a config
  //    error and fails closed (500), NOT a silent forward.
  //  • PER-ACCOUNT spec: the host arrives in X-Bishop-Upstream-Host (daemon-
  //    supplied) and is admitted ONLY when it matches THIS spec's OWN anchored
  //    pattern (spec.hostPattern — spec-bind). Missing → 400; mismatch → 400
  //    (fail-closed, NO forward). §3.2: per-account host — anchored-pattern-
  //    validated, see strongest_claims_security.md §3.2.
  let upstreamHost: string;
  if (spec.hostFromUpstream) {
    const suppliedHost = (request.headers.get("x-bishop-upstream-host") ?? "").trim();
    if (!suppliedHost) {
      emitError(requestId, ip, requestSize, 400, "egress_upstream_host_missing", startedAt, tokenId);
      return jsonError(400, "egress_upstream_host_missing");
    }
    const patterns = spec.hostPattern ?? [];
    if (!patterns.some((re) => re.test(suppliedHost))) {
      emitError(requestId, ip, requestSize, 400, "egress_host_not_allowed", startedAt, tokenId);
      return jsonError(400, "egress_host_not_allowed");
    }
    upstreamHost = suppliedHost;
  } else {
    if (!spec.host || !(ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(spec.host)) {
      emitError(requestId, ip, requestSize, 500, "egress_host_not_allowed", startedAt, tokenId);
      return jsonError(500, "egress_host_not_allowed");
    }
    upstreamHost = spec.host;
  }

  // Step 3b — per-account UPSTREAM HEADER injection (W38-S888, the header-target
  // analog of /mcp's per-tenant PATH substitution). A spec MAY declare ONE
  // forwardable upstream header (xero's Xero-tenant-id). The daemon relay carries
  // it Bishop-namespaced (X-Bishop-Egress-Header-<header>); here we read it,
  // VALIDATE the value against the frozen spec pattern (anchored — blocks header
  // injection), and inject it server-side as the named upstream header. Fail-closed:
  // missing → 400 egress_upstream_header_missing; invalid → 400 egress_header_not_allowed
  // (NO forward). The host stays frozen/server-side; the value is the worker's own
  // already-resolved per-account cred (no privilege gain). §3.2 — see
  // strongest_claims_security.md.
  let injectHeader: { name: string; value: string } | null = null;
  if (spec.headerTenantFromUpstream) {
    const { header, pattern } = spec.headerTenantFromUpstream;
    const relayName = `x-bishop-egress-header-${header.toLowerCase()}`;
    const supplied = (request.headers.get(relayName) ?? "").trim();
    if (!supplied) {
      emitError(requestId, ip, requestSize, 400, "egress_upstream_header_missing", startedAt, tokenId);
      return jsonError(400, "egress_upstream_header_missing");
    }
    if (!pattern.test(supplied)) {
      emitError(requestId, ip, requestSize, 400, "egress_header_not_allowed", startedAt, tokenId);
      return jsonError(400, "egress_header_not_allowed");
    }
    injectHeader = { name: header, value: supplied };
  }

  // Step 4 — tier read + flat-weight quota /check (abuse-bound; no cost meter —
  // generic egress is not model inference).
  const tier = await readTier(env, tokenId);
  const quotaStub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
  const checkResp = await quotaStub.fetch("https://internal/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tier, weight: 1, cost_cents_estimate: 0 }),
  });
  if (checkResp.status === 429) {
    const cr = (await checkResp.json()) as { reason?: string };
    const cap = capTypeFromReason(cr.reason);
    emitRateLimit(requestId, ip, requestSize, tokenId, cap, startedAt);
    return new Response(
      JSON.stringify({ error: "quota_exceeded", reason: cr.reason ?? null }),
      {
        status: 429,
        headers: {
          "content-type": "application/json",
          "X-Bishop-Cap-Type": capTypeHeaderValue(cap),
        },
      },
    );
  }

  // Step 5 — forward. The body is buffered opaquely (no parse) so fetchWithRetry
  // may re-send it; headers are rebuilt with the Bishop auth + control headers
  // stripped. The upstream URL is built from the SPEC host (Step 3) + the spec's
  // pathPrefix + the remaining path segments + the query string — the worker
  // never supplies the host. The installed allowlist interceptor is the runtime
  // backstop.
  const rawBody = await request.arrayBuffer();
  const upstreamHeaders = rebuildEgressHeaders(request.headers, injectHeader);
  const baseUrl = envVar(env, spec.baseUrlVar) ?? `https://${upstreamHost}`;
  const searchSuffix = url.search || "";
  // The worker's LOGICAL upstream method (GET list / POST create / …) rides in
  // X-Bishop-Egress-Method (W38-S831 S6b): the daemon→proxy hop is always a POST
  // carrying the worker's intent, so the route must honor the logical method here.
  // Default to the incoming method (back-compat with the pre-S6b POST-only fixtures).
  const egressMethod = (request.headers.get("x-bishop-egress-method") || request.method).toUpperCase();
  const bodyless = egressMethod === "GET" || egressMethod === "HEAD";
  const upstream = await fetchWithRetry(
    `${baseUrl}${spec.pathPrefix}${derivedPath.replace(/^\//, "")}${searchSuffix}`,
    {
      method: egressMethod,
      headers: upstreamHeaders,
      body: !bodyless && rawBody.byteLength > 0 ? rawBody : undefined,
    },
  );

  // Step 6 — metadata-only audit (Pillar 1 — no token, no body).
  emitResponse({
    request_id: requestId,
    token_id: tokenId,
    ip,
    request_size_bytes: requestSize,
    response_status: upstream.status,
    response_size_bytes: 0,
    input_tokens: 0,
    output_tokens: 0,
    cached_tokens: 0,
    cache_creation_input_tokens: 0,
    classification_decision: null,
    classification_category: null,
    classifier_error_reason: null,
    duration_ms: Date.now() - startedAt,
    upstream_status: upstream.status,
  });

  // Stream the upstream response straight back (status + content-type preserved).
  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}

// Re-export so callers/tests can read the leg's audit event type if needed.
export type { ProxyLogEvent } from "../lib/log";
