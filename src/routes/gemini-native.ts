/**
 * POST /v1beta/models/{model}:generateContent — NATIVE Google Gemini upstream route.
 *
 * The Bishop daemon's Gemini adapter speaks the NATIVE generateContent protocol
 * (model in the URL path, body `{contents:[{parts:[{text}]}]}`, native effort via
 * `generationConfig.thinkingConfig`) — the OpenAI-compatible leg at
 * `/v1/gemini/chat/completions` does NOT serve that path, so every native request
 * 404'd at the default handler (W38-S970: the gemini-BYOK 404→mock-fall regression).
 * This route gives the native protocol the proxy hop it always needed, WITHOUT
 * forcing the daemon adapter (or its ratified R3b effort / R3d model-pinning arcs)
 * onto the OpenAI-compat shim.
 *
 * Same choke sequence as handleGemini (auth → verify → tier → quota → classify →
 * entitlement-gate → forward) and the SAME single-seal §3.2 posture: the upstream
 * host is frozen server-side (generativelanguage.googleapis.com, already in
 * ALLOWED_OUTBOUND_HOSTS), never derived from the request; only the model id is
 * taken from the path (anchored-validated). Auth is the native `x-goog-api-key`
 * header (rebuildGeminiNativeHeaders), never the inbound Bearer.
 *
 * Entitlement gate: managed → operator GEMINI_API_KEY (fail closed with
 * managed_key_unavailable if absent — never reads the inbound header); byok → the
 * user key (byok_key_missing if absent).
 */

import type { Env } from "../index";
import { resolveUpstreamKey, rebuildGeminiNativeHeaders } from "../lib/headers";
import { classify } from "../lib/classifier";
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

// Anchored match for `/v1beta/models/{model}:generateContent`. The model segment
// is constrained to the Gemini id alphabet (letters/digits/dot/dash/underscore) —
// no slash, no second colon — so it can never inject a path or a host.
const NATIVE_GENERATE_PATH = /^\/v1beta\/models\/([A-Za-z0-9._-]+):generateContent$/;
const DEFAULT_GEMINI_NATIVE_BASE = "https://generativelanguage.googleapis.com/v1beta";

export async function handleGeminiNative(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);
  const url = new URL(request.url);

  // Model id from the path (host is NEVER request-derived — single seal §3.2).
  const pathMatch = NATIVE_GENERATE_PATH.exec(url.pathname);
  if (!pathMatch) {
    emitError(requestId, ip, requestSize, 400, "unsupported_model", startedAt);
    return jsonError(400, "unsupported_model");
  }
  const model = pathMatch[1];

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

  // Parse body (native generateContent shape). We do NOT log the body.
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(await request.text()) as Record<string, unknown>;
  } catch {
    emitError(requestId, ip, requestSize, 400, "bad_json", startedAt, tokenId);
    return jsonError(400, "bad_json");
  }

  // Step 4 — quota /check (flat weight, no cost meter on this leg).
  const quotaStub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
  const checkResp = await quotaStub.fetch("https://internal/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    // A CONNECTED (byok) device bypasses the free-tier daily_floor (it pays its
    // own provider); managed/FREE stays metered.
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

  // Step 5 — content classifier (reads the native `contents` shape, W38-S970).
  const cls = await classify(body, env);
  const gateResponse = classificationGate(cls, requestId, tokenId, ip, requestSize, startedAt);
  if (gateResponse) return gateResponse;

  // Step 6 — entitlement gate (fail-closed). Managed → operator GEMINI_API_KEY.
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, env.GEMINI_API_KEY ?? null);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders = rebuildGeminiNativeHeaders(request.headers, keyResolution.key);

  // Step 7 — upstream fetch with retry. Host frozen server-side; only the
  // path-validated model id varies (never the host).
  const upstreamBase = env.GEMINI_NATIVE_BASE_URL ?? DEFAULT_GEMINI_NATIVE_BASE;
  const upstream = await fetchWithRetry(`${upstreamBase}/models/${model}:generateContent`, {
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
