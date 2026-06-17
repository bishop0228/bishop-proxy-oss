/**
 * POST /byok/<seg>/... — generalized BYOK upstream route.
 *
 * Same 8-step choke as grok.ts (auth → verify → tier → body-parse → quota →
 * classify → entitlement-gate → forward) but per-leg constants are read from
 * BYOK_UPSTREAM_SPECS keyed by the path segment at position [2].
 *
 * Entitlement gate: managed → operator key from env[spec.operatorKeyVar] (fail
 * closed with managed_key_unavailable if absent — never reads the inbound
 * header); byok → x-bishop-upstream-key (byok_key_missing if absent).
 * rebuildByokHeaders strips all client identifiers (Pillar 1).
 *
 * Audit emits: seg + key_name (env var name, never the value) + event_type +
 * status_code ONLY — key value is never recorded.
 *
 * upstream host = spec.upstreamHost (frozen allowlist) unless env[spec.baseUrlVar]
 * overrides for test environments. Never derived from the inbound request.
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import { resolveUpstreamKey, rebuildByokHeaders } from "../lib/headers";
import { classify } from "../lib/classifier";
import { logEvent, type ProxyLogEvent } from "../lib/log";
import { BYOK_UPSTREAM_SPECS } from "../lib/byok-specs";
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

export async function handleByok(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "byok", "<seg>", ...]
  const seg = parts[2] ?? "";
  const spec = BYOK_UPSTREAM_SPECS[seg];
  if (!spec) {
    emitError(requestId, ip, requestSize, 404, "unknown_provider", startedAt);
    return jsonError(404, "unknown_provider");
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

  // Step 3 — tier-cache read keyed by token_id.
  const tier = await readTier(env, tokenId);

  // Parse body. We do NOT log the body.
  let body: { model?: string } & Record<string, unknown>;
  try {
    body = JSON.parse(await request.text()) as typeof body;
  } catch {
    emitError(requestId, ip, requestSize, 400, "bad_json", startedAt, tokenId);
    return jsonError(400, "bad_json");
  }
  if (typeof body.model !== "string" || body.model.trim().length === 0) {
    emitError(requestId, ip, requestSize, 400, "unsupported_model", startedAt, tokenId);
    return jsonError(400, "unsupported_model");
  }

  // Step 4 — quota /check (flat weight, no cost meter on this leg).
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

  // Step 5 — content classifier (SAME classify as messages.ts).
  const cls = await classify(body, env);
  if (cls.decision === "allow") {
    const allowEvent: ProxyLogEvent = {
      event_type: "classification",
      timestamp: new Date().toISOString(),
      request_id: requestId,
      token_id: tokenId,
      ip,
      request_size_bytes: requestSize,
      response_status: 0,
      response_size_bytes: 0,
      token_count_in: null,
      token_count_out: null,
      cached_tokens: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      classification_decision: "allow",
      classification_category: cls.category,
      classifier_error_reason: cls.classifier_error_reason,
      duration_ms: Date.now() - startedAt,
      upstream_status: null,
      cap_type_hit: null,
    };
    try { logEvent(allowEvent); } catch { /* shape error is itself an audit signal */ }
  }
  if (cls.decision === "block") {
    const blockEvent: ProxyLogEvent = {
      event_type: "classification",
      timestamp: new Date().toISOString(),
      request_id: requestId,
      token_id: tokenId,
      ip,
      request_size_bytes: requestSize,
      response_status: 451,
      response_size_bytes: 0,
      token_count_in: null,
      token_count_out: null,
      cached_tokens: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      classification_decision: "block",
      classification_category: cls.category,
      classifier_error_reason: cls.classifier_error_reason,
      duration_ms: Date.now() - startedAt,
      upstream_status: null,
      cap_type_hit: null,
    };
    try { logEvent(blockEvent); } catch { /* shape error is itself an audit signal */ }
    return new Response(
      JSON.stringify({
        type: "error",
        error: {
          type: "content_policy_violation",
          message: "Request blocked by content classifier.",
        },
      }),
      { status: 451, headers: { "content-type": "application/json" } },
    );
  }

  // Step 6 — entitlement gate (fail-closed). Managed → operator key from env[spec.operatorKeyVar].
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const operatorKey = envVar(env, spec.operatorKeyVar) ?? null;
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, operatorKey);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders = rebuildByokHeaders(request.headers, keyResolution.key);

  // Step 7 — upstream fetch. Host derived from spec (frozen allowlist), never from request.
  // For providers that block the proxy's raw Worker egress IP (DeepSeek returns HTTP 451 to
  // Cloudflare datacenter IPs on a direct fetch), route through Cloudflare AI Gateway when the
  // CF_AIG_* env is configured — its managed egress is accepted by the provider. The host
  // gateway.ai.cloudflare.com is already in ALLOWED_OUTBOUND_HOSTS (§H-DYNAMIC), so this widens
  // nothing. Falls back to the direct host when AI Gateway is unconfigured (no regression).
  let baseUrl: string;
  let upstreamPath = derivedPath;
  if (spec.aiGatewayProvider && env.CF_AIG_ACCOUNT && env.CF_AIG_GATEWAY && env.CF_AIG_TOKEN) {
    baseUrl = `https://gateway.ai.cloudflare.com/v1/${env.CF_AIG_ACCOUNT}/${env.CF_AIG_GATEWAY}/${spec.aiGatewayProvider}`;
    // AI Gateway's provider path is the vendor-native path without a leading /v1 segment.
    upstreamPath = derivedPath.replace(/^\/v1(?=\/|$)/, "");
    // Authenticated-gateway token (cf-aig-authorization) — distinct from the user's BYOK
    // provider key, which rebuildByokHeaders already placed in the provider auth header.
    upstreamHeaders.set("cf-aig-authorization", `Bearer ${env.CF_AIG_TOKEN}`);
  } else {
    baseUrl = envVar(env, spec.baseUrlVar) ?? `https://${spec.upstreamHost}`;
  }
  const upstream = await fetchWithRetry(`${baseUrl}${upstreamPath}`, {
    method: "POST",
    headers: upstreamHeaders,
    body: JSON.stringify(body),
  });

  // Step 8 — response (no tee/SSE-usage on this leg). Emit response audit event.
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
    classification_decision: cls.decision,
    classification_category: cls.category,
    classifier_error_reason: cls.classifier_error_reason,
    duration_ms: Date.now() - startedAt,
    upstream_status: upstream.status,
  });

  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}
