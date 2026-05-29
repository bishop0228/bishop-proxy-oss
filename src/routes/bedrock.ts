/**
 * POST /byok/bedrock/<path> — AWS Bedrock SigV4 distinct-auth BYOK leg (§1.17.17).
 *
 * Shares the 8-step security choke (auth→verify→tier→body-parse→quota→classify→
 * entitlement-gate→forward) with byok.ts but diverges at three steps:
 *   Step 4: byte-exact body pass-through — rawBody = request.text(), no re-serialization.
 *   Step 6: BYOK-only entitlement gate — managed fails closed (bedrock_requires_byok, 400).
 *          Credential format: x-bishop-upstream-key = "AKIAXXXX:secretAccessKey".
 *   Step 7: SigV4-signed request — Authorization header computed via HMAC-SHA256 chain;
 *          host header = real AWS host (bedrock-runtime.us-east-1.amazonaws.com) always,
 *          even when BEDROCK_BASE_URL redirects to a test server.
 *
 * Pillar 1 invariant: accessKeyId, secretAccessKey, and computed signature are NEVER
 * recorded in any ProxyLogEvent. Audit carries request_id + token_id + status only.
 */

import type { Env } from "../index";
import { classify } from "../lib/classifier";
import { logEvent, type ProxyLogEvent } from "../lib/log";
import { BEDROCK_UPSTREAM } from "../lib/bedrock-spec";
import { sigv4Sign, amzDateNow } from "../lib/sigv4";
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

export async function handleBedrock(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  const parts = url.pathname.split("/"); // ["", "byok", "bedrock", ...]
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

  // Step 6 — entitlement gate. Bedrock is BYOK-only; managed fails closed.
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  if (accountMode !== "byok") {
    emitError(requestId, ip, requestSize, 400, "bedrock_requires_byok", startedAt, tokenId);
    return jsonError(400, "bedrock_requires_byok");
  }

  const upstreamKeyRaw = request.headers.get("x-bishop-upstream-key") ?? "";
  if (!upstreamKeyRaw) {
    emitError(requestId, ip, requestSize, 400, "byok_key_missing", startedAt, tokenId);
    return jsonError(400, "byok_key_missing");
  }

  // Credential format: "AKIAXXXXXXXXXX:secretAccessKeyValue"
  const colonIdx = upstreamKeyRaw.indexOf(":");
  if (colonIdx < 1) {
    emitError(requestId, ip, requestSize, 400, "byok_key_missing", startedAt, tokenId);
    return jsonError(400, "byok_key_missing");
  }
  const accessKeyId = upstreamKeyRaw.slice(0, colonIdx);
  const secretAccessKey = upstreamKeyRaw.slice(colonIdx + 1);

  // Step 7 — SigV4-signed upstream fetch.
  // host is ALWAYS the real AWS host (canonical request signing requirement);
  // actual HTTP connection target may be overridden by BEDROCK_BASE_URL for tests.
  const awsHost = BEDROCK_UPSTREAM.upstreamHost;
  const amzDate = amzDateNow();

  const { authorization } = await sigv4Sign({
    accessKeyId,
    secretAccessKey,
    region: BEDROCK_UPSTREAM.region,
    service: BEDROCK_UPSTREAM.service,
    method: "POST",
    path: derivedPath,
    host: awsHost,
    contentType,
    amzDate,
    payload: rawBody,
  });

  const upstreamHeaders = new Headers();
  upstreamHeaders.set("content-type", contentType);
  upstreamHeaders.set("host", awsHost);
  upstreamHeaders.set("x-amz-date", amzDate);
  upstreamHeaders.set("authorization", authorization);

  const baseUrl = (env as Record<string, string | undefined>)[BEDROCK_UPSTREAM.baseUrlVar]
    ?? `https://${awsHost}`;
  const upstream = await fetchWithRetry(`${baseUrl}${derivedPath}`, {
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
