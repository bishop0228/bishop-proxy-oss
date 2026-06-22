/**
 * OAuth subscription legs.
 *
 * POST /v1/<seg>/... — handleOAuthCompletion
 *   Same 8-step choke as byok.ts (auth → verify → tier → body-parse → quota →
 *   classify → entitlement-gate → forward) with exactly THREE changes from byok.ts:
 *   1. spec = OAUTH_UPSTREAM_SPECS[seg] (keyed at URL position [2] of /v1/<seg>/...)
 *   2. operatorKey = null (OAuth is byok-class; no operator subscription to lend)
 *   3. Upstream URL uses spec.completionPath (FIXED) + spec.completionBaseUrlVar;
 *      extraUpstreamHeaders applied after rebuildByokHeaders if present.
 *
 * POST /oauth/<seg>/token — handleOAuthToken
 *   Sealed urlencoded forward: Bishop-auth steps 1-2 only (Bearer parse + verify-token).
 *   No tier / quota / classify / key injection. Strips inbound Bishop Authorization before
 *   forwarding raw body to spec.tokenPath. Metadata-only audit emit; access_token body
 *   is passed through to the daemon but NEVER logged (Pillar 1).
 *
 * Entitlement invariant (Pillar 4 / strongest_claims_security):
 *   managed → resolveUpstreamKey(null) → managed_key_unavailable (400, fail-closed).
 *   byok → x-bishop-upstream-key (the OAuth access token); absent → byok_key_missing (400).
 *   Operator fallback is structurally unrepresentable: no operatorKeyVar in OAuthUpstreamSpec.
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import { resolveUpstreamKey, rebuildByokHeaders } from "../lib/headers";
import { classify } from "../lib/classifier";
import { OAUTH_UPSTREAM_SPECS } from "../lib/oauth-specs";
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
  classificationGate,
} from "./messages";

interface VerifyTokenResult {
  valid: boolean;
  record: AuthRecord | null;
  reason: "not_found" | "revoked" | "expired" | null;
}

export async function handleOAuthCompletion(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "v1", "<seg>", ...]
  const seg = parts[2] ?? "";
  const spec = OAUTH_UPSTREAM_SPECS[seg];
  if (!spec) {
    emitError(requestId, ip, requestSize, 404, "unknown_provider", startedAt);
    return jsonError(404, "unknown_provider");
  }

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

  // Step 5 — content classifier.
  const cls = await classify(body, env);
  const gateResponse = classificationGate(cls, requestId, tokenId, ip, requestSize, startedAt);
  if (gateResponse) return gateResponse;

  // Step 6 — entitlement gate. operatorKey = null: OAuth is byok-class; no operator key to lend.
  // managed → resolveUpstreamKey trims null → managed_key_unavailable (400, fail-closed).
  // byok → x-bishop-upstream-key (the OAuth access token); absent → byok_key_missing (400).
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const operatorKey = null;
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, operatorKey);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders = rebuildByokHeaders(request.headers, keyResolution.key);

  // Apply extra upstream headers required by provider (e.g. qwen_alibaba X-DashScope-AuthType).
  if (spec.extraUpstreamHeaders) {
    for (const [k, v] of Object.entries(spec.extraUpstreamHeaders)) {
      upstreamHeaders.set(k, v);
    }
  }

  // Per-request account-id passthrough (e.g. chatgpt-account-id for openai_codex). The daemon sends
  // the Bishop-namespaced X-Bishop-Upstream-Account-Id, which rebuildByokHeaders drops along with
  // every other client identifier (Pillar 1); map its value to the upstream header THIS spec needs.
  // Omitted when absent — never fabricated.
  if (spec.accountIdHeader) {
    const acctId = (request.headers.get("x-bishop-upstream-account-id") ?? "").trim();
    if (acctId) upstreamHeaders.set(spec.accountIdHeader, acctId);
  }

  // Per-request session-id passthrough (e.g. session_id for openai_codex). Same shape as the
  // account-id: the daemon sends the Bishop-namespaced X-Bishop-Upstream-Session-Id (dropped by
  // rebuildByokHeaders); map its value to the upstream header THIS spec needs. Omitted when absent.
  if (spec.sessionIdHeader) {
    const sessionId = (request.headers.get("x-bishop-upstream-session-id") ?? "").trim();
    if (sessionId) upstreamHeaders.set(spec.sessionIdHeader, sessionId);
  }

  // Step 7 — upstream fetch. Path is FIXED per spec (never derived from inbound request).
  const baseUrl = envVar(env, spec.completionBaseUrlVar) ?? `https://${spec.completionHost}`;
  const upstream = await fetchWithRetry(`${baseUrl}${spec.completionPath}`, {
    method: "POST",
    headers: upstreamHeaders,
    body: JSON.stringify(body),
  });

  // Step 8 — response audit emit.
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

export async function handleOAuthToken(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "oauth", "<seg>", "token"]
  const seg = parts[2] ?? "";
  const spec = OAUTH_UPSTREAM_SPECS[seg];
  if (!spec) {
    emitError(requestId, ip, requestSize, 404, "unknown_provider", startedAt);
    return jsonError(404, "unknown_provider");
  }
  if (parts[3] !== "token") {
    emitError(requestId, ip, requestSize, 404, "not_found", startedAt);
    return jsonError(404, "not_found");
  }

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

  // Sealed urlencoded forward — no tier / quota / classify / key injection.
  const rawBody = await request.text();

  // Build clean upstream headers: content-type only. Strip inbound Bishop Authorization.
  const upstreamHeaders = new Headers();
  upstreamHeaders.set(
    "content-type",
    request.headers.get("content-type") ?? "application/x-www-form-urlencoded",
  );

  const baseUrl = envVar(env, spec.tokenBaseUrlVar) ?? `https://${spec.tokenHost}`;
  const upstream = await fetchWithRetry(`${baseUrl}${spec.tokenPath}`, {
    method: "POST",
    headers: upstreamHeaders,
    body: rawBody,
  });

  // Metadata-only emit; token-leg response body (access_token) is passed through unlogged.
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

  // Pass access_token body through to daemon; strip every upstream header except content-type.
  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}
