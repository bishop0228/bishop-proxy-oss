/**
 * POST /byok/azure/<path> — Azure OpenAI api-key distinct-auth BYOK leg (§1.17.18).
 *
 * Shares the 8-step security choke (auth→verify→tier→body-parse→quota→classify→
 * entitlement-gate→forward) with byok.ts but diverges at three steps:
 *   Step 4: byte-exact body pass-through — rawBody = request.text(), no re-serialization.
 *   Step 6: BYOK-only entitlement gate — managed fails closed (azure_requires_byok, 400).
 *          Credential format: x-bishop-upstream-key = "<resource>:<apiKey>".
 *          Resource validated via isAnchoredEnterpriseHost; azure_resource_invalid on failure.
 *   Step 7: api-key header upstream fetch — host constructed server-side from resource;
 *          url.search preserved (?api-version); NO authorization header; fresh Headers.
 *
 * Pillar 1 invariant: resource name and apiKey are NEVER recorded in any ProxyLogEvent.
 * Audit carries request_id + token_id + status only.
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import { classify } from "../lib/classifier";
import { logEvent, type ProxyLogEvent } from "../lib/log";
import { AZURE_UPSTREAM } from "../lib/azure-spec";
import { isAnchoredEnterpriseHost } from "../lib/outbound-allowlist";
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

export async function handleAzure(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "byok", "azure", ...]
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

  // Step 4 — byte-exact body capture (no parse/re-serialize round-trip).
  // Classifier still receives parsed JSON; if body is non-JSON classify sees empty object.
  const rawBody = await request.text();
  let bodyForClassify: Record<string, unknown> = {};
  try {
    bodyForClassify = JSON.parse(rawBody) as Record<string, unknown>;
  } catch { /* non-JSON body: classify sees empty object, allow by default */ }

  const contentType = request.headers.get("content-type") ?? "application/json";

  // Step 4b — quota /check.
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

  // Step 5 — content classifier.
  const cls = await classify(bodyForClassify, env);
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

  // Step 6 — entitlement gate. Azure is BYOK-only; managed fails closed.
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  if (accountMode !== "byok") {
    emitError(requestId, ip, requestSize, 400, "azure_requires_byok", startedAt, tokenId);
    return jsonError(400, "azure_requires_byok");
  }

  const upstreamKeyRaw = request.headers.get("x-bishop-upstream-key") ?? "";
  if (!upstreamKeyRaw) {
    emitError(requestId, ip, requestSize, 400, "byok_key_missing", startedAt, tokenId);
    return jsonError(400, "byok_key_missing");
  }

  // Credential format: "<resource>:<apiKey>"
  const colonIdx = upstreamKeyRaw.indexOf(":");
  if (colonIdx < 1) {
    emitError(requestId, ip, requestSize, 400, "byok_key_missing", startedAt, tokenId);
    return jsonError(400, "byok_key_missing");
  }
  const resource = upstreamKeyRaw.slice(0, colonIdx).toLowerCase();
  const apiKey = upstreamKeyRaw.slice(colonIdx + 1);

  // SSRF defence: server-side host construct + anchored single-label validation.
  // Interceptor defense-in-depth: isAnchoredEnterpriseHost also checked by allowlist
  // interceptor if the resource somehow bypasses this early gate.
  const azureHost = `${resource}${AZURE_UPSTREAM.hostSuffix}`;
  if (!isAnchoredEnterpriseHost(azureHost)) {
    emitError(requestId, ip, requestSize, 400, "azure_resource_invalid", startedAt, tokenId);
    return jsonError(400, "azure_resource_invalid");
  }

  // Step 7 — api-key upstream fetch.
  // host constructed server-side; url.search preserved (?api-version etc.).
  // NO authorization header — Azure uses api-key header auth.
  const upstreamHeaders = new Headers();
  upstreamHeaders.set("content-type", contentType);
  upstreamHeaders.set("api-key", apiKey);

  const baseUrl = envVar(env, AZURE_UPSTREAM.baseUrlVar)
    ?? `https://${azureHost}`;
  const searchSuffix = url.search || "";
  const upstream = await fetchWithRetry(`${baseUrl}${derivedPath}${searchSuffix}`, {
    method: "POST",
    headers: upstreamHeaders,
    body: rawBody,
  });

  // Step 8 — response audit emit (no credential fields — Pillar 1).
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
