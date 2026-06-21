/**
 * POST /v1/grok/chat/completions — xAI Grok OpenAI-compatible upstream route.
 *
 * Lean mirror of handleMessages: it flows through the SAME choke sequence
 * (auth → verify → tier → quota → classify → entitlement-gate → forward), but
 * the Grok leg carries no tee()/SSE-usage parsing and no cost meter — quota
 * is checked at a flat weight of 1. The upstream host is derived from the route
 * (frozen allowlist), never from the request, preserving the single-seal §3.2.
 *
 * Entitlement gate: managed → operator XAI_API_KEY (fail closed with
 * managed_key_unavailable if absent — never reads the inbound header); byok →
 * the user key (byok_key_missing if absent). rebuildOpenAIHeaders strips all
 * client identifiers (Pillar 1).
 */

import type { Env } from "../index";
import { resolveUpstreamKey, rebuildOpenAIHeaders } from "../lib/headers";
import { classify } from "../lib/classifier";
import { logEvent, type ProxyLogEvent } from "../lib/log";
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

export async function handleGrok(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

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
  // OpenAI model ids are not haiku/sonnet — require a non-empty string only.
  if (typeof body.model !== "string" || body.model.trim().length === 0) {
    emitError(requestId, ip, requestSize, 400, "unsupported_model", startedAt, tokenId);
    return jsonError(400, "unsupported_model");
  }

  // Step 4 — quota /check (flat weight, no cost meter on this leg).
  const quotaStub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
  const checkResp = await quotaStub.fetch("https://internal/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    // W38-S923: forward account_mode so a CONNECTED (byok) device bypasses the
    // free-tier daily_floor (it pays its own provider); managed/FREE stays metered.
    body: JSON.stringify({
      tier,
      weight: 1,
      cost_cents_estimate: 0,
      account_mode: record.account_mode ?? "managed",
    }),
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

  // Step 6 — entitlement gate (fail-closed). Managed → operator XAI_API_KEY.
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, env.XAI_API_KEY ?? null);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders = rebuildOpenAIHeaders(request.headers, keyResolution.key);

  // Step 7 — upstream fetch with retry. Host derived from the route, not the request.
  const upstreamUrl = env.XAI_BASE_URL ?? "https://api.x.ai";
  const upstream = await fetchWithRetry(`${upstreamUrl}/v1/chat/completions`, {
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
