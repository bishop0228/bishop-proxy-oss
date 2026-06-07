/**
 * POST /mcp/<server_id> — governed MCP-forward route (§1.18.15).
 *
 * The §3.2 operational-egress path: Bishop's daemon routes every outbound MCP
 * connection through this proxy. MCP is NOT model inference, so this leg shares
 * the byok auth/quota choke but drops the classifier and cost-meter:
 *
 *   1. Bearer parse + AuthStoreDO /verify-token        (mirror byok step 1-2)
 *   2. server_id → MCP_SERVER_SPECS spec               (unknown → 404, no forward)
 *   3. host derive (SSRF-safe):
 *        • FIXED-host spec: host = spec.host — SERVER-SIDE, never from the
 *          request; defense-in-depth asserts host ∈ ALLOWED_OUTBOUND_HOSTS (the
 *          fetch interceptor is the backstop) — refuse with 500 if it ever drifts.
 *        • PER-ACCOUNT spec (W38-S735): host = X-Bishop-Upstream-Host (daemon-
 *          supplied), admitted ONLY when it matches THIS spec's OWN anchored
 *          vendor pattern (spec.hostPattern — spec-bind, SSRF-bounded to the
 *          vendor domain). Missing header → 400; pattern mismatch → 400; never
 *          a forward to a non-matching host.
 *   3b. per-tenant PATH (W38-S736): a frozen-host spec MAY carry
 *        pathTenantFromUpstream — its pathPrefix has a {tenantId} placeholder the
 *        route substitutes from a daemon-supplied, GUID-validated
 *        X-Bishop-Upstream-Path-Tenant header. Missing → 400; non-GUID → 400. The
 *        host stays frozen (a path segment cannot redirect egress off it).
 *   4. rebuild upstream Bearer auth from x-bishop-upstream-key (missing → 400);
 *      all client identifiers stripped (Pillar 1 — only content-type + accept
 *      forwarded so the upstream can negotiate SSE).
 *   5. flat-weight quota /check (abuse-bound, weight 1, cost 0 — no tier-cost).
 *   6. fetchWithRetry forward of the raw JSON-RPC body; SSE-capable (the upstream
 *      .body ReadableStream is streamed straight back, like the chat leg).
 *   7. emitResponse — metadata-only ProxyLogEvent (request_id + token_id +
 *      status). The upstream key and the JSON-RPC body are NEVER logged (Pillar 1).
 *
 * upstream host = spec.host (frozen allowlist) for fixed-host servers, or the
 * pattern-validated X-Bishop-Upstream-Host for per-account servers (W38-S735),
 * unless env[spec.baseUrlVar] overrides for test environments. A fixed-host
 * server's host is NEVER derived from the inbound request; a per-account host is
 * daemon-supplied + anchored-pattern-validated + spec-bound (§3.2).
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import type { ProxyLogEvent } from "../lib/log";
import { MCP_SERVER_SPECS } from "../lib/mcp-specs";
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
 * W38-S736 — a bare lowercase GUID (8-4-4-4-12 hex). The daemon-supplied
 * per-tenant PATH segment MUST match this exactly: anchored ^…$, lowercase-only,
 * no `/`, `.`, `..` or any other character — which blocks every path-injection.
 */
const MCP_TENANT_GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Rebuild upstream headers for the MCP forward. Strip-all like
 * rebuildByokHeaders (Pillar 1 identifier-strip) but ALSO forward `accept` so
 * the upstream can negotiate `text/event-stream` for the Streamable-HTTP SSE
 * reply. Only content-type + accept survive; the resolved upstream key becomes
 * the Bearer.
 */
function rebuildMcpHeaders(incoming: Headers, key: string): Headers {
  const out = new Headers();
  for (const [k, v] of incoming.entries()) {
    const lk = k.toLowerCase();
    if (lk === "content-type" || lk === "accept") out.set(k, v);
  }
  out.set("authorization", `Bearer ${key}`);
  if (!out.has("content-type")) out.set("content-type", "application/json");
  if (!out.has("accept")) out.set("accept", "application/json, text/event-stream");
  return out;
}

export async function handleMcp(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "mcp", "<server_id>", ...]
  const serverId = parts[2] ?? "";
  const spec = MCP_SERVER_SPECS[serverId];
  if (!spec) {
    // Unknown server_id → 404, NO forward (SSRF: no request-derived host).
    emitError(requestId, ip, requestSize, 404, "unknown_mcp_server", startedAt);
    return jsonError(404, "unknown_mcp_server");
  }
  const derivedPath = "/" + parts.slice(3).join("/");

  // Step 1 — Bearer parsing.
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

  // Step 2 — token verification via AuthStoreDO /verify-token.
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
  const record = verify.record;
  const tokenId = record.token_id;

  // Step 3 — SSRF-safe host derive.
  //  • FIXED-host spec: spec.host is the SOLE source — never the request.
  //    Defense-in-depth: assert it ∈ the static allowlist (the fetch interceptor
  //    is the runtime backstop). A spec whose host is not allow-listed is a
  //    config error and fails closed (500), NOT a silent forward.
  //  • PER-ACCOUNT spec (W38-S735): the host arrives in X-Bishop-Upstream-Host
  //    (daemon-supplied) and is admitted ONLY when it matches THIS spec's OWN
  //    anchored vendor pattern (spec.hostPattern — spec-bind: a snowflake spec
  //    admits only *.snowflakecomputing.com, never another vendor's valid host).
  //    Missing header → 400; pattern mismatch → 400 (fail-closed, NO forward).
  //    §3.2: per-account host — anchored-pattern-validated, see
  //    strongest_claims_security.md §3.2.
  let upstreamHost: string;
  if (spec.hostFromUpstream) {
    const suppliedHost = (request.headers.get("x-bishop-upstream-host") ?? "").trim();
    if (!suppliedHost) {
      emitError(requestId, ip, requestSize, 400, "mcp_upstream_host_missing", startedAt, tokenId);
      return jsonError(400, "mcp_upstream_host_missing");
    }
    const patterns = spec.hostPattern ?? [];
    if (!patterns.some((re) => re.test(suppliedHost))) {
      emitError(requestId, ip, requestSize, 400, "mcp_host_not_allowed", startedAt, tokenId);
      return jsonError(400, "mcp_host_not_allowed");
    }
    upstreamHost = suppliedHost;
  } else {
    if (!spec.host || !(ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(spec.host)) {
      emitError(requestId, ip, requestSize, 500, "mcp_host_not_allowed", startedAt, tokenId);
      return jsonError(500, "mcp_host_not_allowed");
    }
    upstreamHost = spec.host;
  }

  // Step 3b — per-tenant PATH substitution (W38-S736). A frozen-host spec MAY
  // carry a per-tenant id in its PATH (spec.pathTenantFromUpstream): microsoft-365
  // / onedrive-sharepoint on the shared Agent 365 host. The host is UNCHANGED
  // (still frozen + allow-listed, Step 3) — only pathPrefix's {tenantId} placeholder
  // is substituted from the daemon-supplied X-Bishop-Upstream-Path-Tenant header,
  // which is GUID-validated (a bare lowercase GUID blocks `/`, `.`, `..` and every
  // path-injection). Missing → 400 mcp_upstream_tenant_missing; non-GUID → 400
  // mcp_tenant_not_allowed (fail-closed, NO forward).
  // §3.2: frozen host + daemon-supplied GUID-validated tenant PATH segment (host
  // never from request; a path segment cannot redirect egress off a frozen
  // allow-listed host) — see strongest_claims_security.md §3.2.
  let effectivePathPrefix = spec.pathPrefix;
  if (spec.pathTenantFromUpstream) {
    const tenant = (request.headers.get("x-bishop-upstream-path-tenant") ?? "").trim();
    if (!tenant) {
      emitError(requestId, ip, requestSize, 400, "mcp_upstream_tenant_missing", startedAt, tokenId);
      return jsonError(400, "mcp_upstream_tenant_missing");
    }
    if (!MCP_TENANT_GUID_RE.test(tenant)) {
      emitError(requestId, ip, requestSize, 400, "mcp_tenant_not_allowed", startedAt, tokenId);
      return jsonError(400, "mcp_tenant_not_allowed");
    }
    effectivePathPrefix = spec.pathPrefix.replace("{tenantId}", tenant);
  }

  // Step 4 — entitlement gate: rebuild upstream auth from x-bishop-upstream-key.
  const upstreamKey = (request.headers.get("x-bishop-upstream-key") ?? "").trim();
  if (!upstreamKey) {
    emitError(requestId, ip, requestSize, 400, "mcp_upstream_key_missing", startedAt, tokenId);
    return jsonError(400, "mcp_upstream_key_missing");
  }

  // Step 5 — tier read + flat-weight quota /check (abuse-bound; no cost meter —
  // MCP is not model inference).
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

  // Step 6 — forward the raw JSON-RPC body. Byte-exact pass-through (no parse/
  // re-serialize); the body is never logged. Host constructed server-side from
  // spec; SSE-capable (upstream .body streamed straight back).
  const rawBody = await request.text();
  const upstreamHeaders = rebuildMcpHeaders(request.headers, upstreamKey);
  const baseUrl = envVar(env, spec.baseUrlVar)
    ?? `https://${upstreamHost}`;
  const searchSuffix = url.search || "";
  const upstream = await fetchWithRetry(
    `${baseUrl}${effectivePathPrefix}${derivedPath.replace(/^\//, "")}${searchSuffix}`,
    {
      method: "POST",
      headers: upstreamHeaders,
      body: rawBody,
    },
  );

  // Step 7 — metadata-only audit (Pillar 1 — no token, no body).
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

  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  // SSE passthrough: stream the upstream body straight back to the daemon.
  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}

// Re-export so callers/tests can read the leg's audit event type if needed.
export type { ProxyLogEvent };
