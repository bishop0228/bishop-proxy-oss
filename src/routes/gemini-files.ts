/**
 * Gemini Files API passthrough — point/ship large-media upload (leg A).
 *
 *   POST   /v1beta/files:upload   → Gemini media upload (raw bytes + mime)
 *   DELETE /v1beta/files/{id}     → Gemini file delete (upload → use → DELETE)
 *
 * When a pointed image/PDF/video is too large to ship INLINE in generateContent, the
 * daemon's gemini_files client uploads the raw bytes here; the proxy forwards them to
 * Gemini's Files API, returns the {file:{uri,name}} resource, and the daemon references
 * the fileUri in generateContent then DELETEs the file right after the completion.
 *
 * Same choke sequence as handleGeminiNative (auth → verify → tier → quota →
 * entitlement-gate → forward) and the SAME single-seal §3.2 posture: the upstream host
 * is FROZEN server-side (generativelanguage.googleapis.com, already in
 * ALLOWED_OUTBOUND_HOSTS), never request-derived. Auth is the native `x-goog-api-key`
 * (rebuildGeminiNativeHeaders), never the inbound Bearer.
 *
 * Two leg-specific omissions vs the generateContent route, both deliberate:
 *   - NO JSON parse — the body is raw file bytes; it is forwarded verbatim, never read
 *     or logged.
 *   - NO content classifier — the classifier reads the `contents` text shape; raw media
 *     bytes aren't classifiable that way. The file's TEXT floor (OCR/transcript) is
 *     injected into the generateContent prompt and IS classified on that leg; the binary
 *     upload itself is transparency-tagged (the daemon's dynamic retention tag degrades
 *     to "stored"), the chosen posture — never silently blocked.
 *
 * Entitlement gate (fail-closed): managed → operator GEMINI_API_KEY
 * (managed_key_unavailable if absent — never reads the inbound header); byok → the user
 * key (byok_key_missing if absent).
 */

import type { Env } from "../index";
import { resolveUpstreamKey, rebuildGeminiNativeHeaders } from "../lib/headers";
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

// Host FROZEN server-side (single seal §3.2) — never request-derived. Only the
// path-validated file id varies on delete.
const DEFAULT_GEMINI_UPLOAD_URL =
  "https://generativelanguage.googleapis.com/upload/v1beta/files?uploadType=media";
const DEFAULT_GEMINI_FILES_BASE = "https://generativelanguage.googleapis.com/v1beta";

// Defensive body cap — mirrors the daemon's PROXY_UPLOAD_MAX_BYTES. A larger file is
// leg B's job (streaming, scoped direct URL); reject here rather than buffer it.
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

// Anchored delete path: `/v1beta/files/{id}` — id constrained to Gemini's file-name
// alphabet (no slash, no second segment) so it can never inject a path or a host.
const DELETE_PATH = /^\/v1beta\/(files\/[A-Za-z0-9._-]+)$/;

export async function handleGeminiFiles(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);
  const url = new URL(request.url);
  const isDelete = request.method === "DELETE";

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

  // Step 4 — quota /check (flat weight; an upload/delete is one governed op).
  const quotaStub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
  const checkResp = await quotaStub.fetch("https://internal/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
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

  // Step 5 — entitlement gate (fail-closed). Managed → operator GEMINI_API_KEY.
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, env.GEMINI_API_KEY ?? null);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders = rebuildGeminiNativeHeaders(request.headers, keyResolution.key);

  // Step 6 — forward. Host frozen server-side; the body is raw bytes (upload) or empty
  // (delete) — never parsed, never logged.
  let upstreamUrl: string;
  let method: string;
  let body: BodyInit | null = null;
  if (isDelete) {
    const m = DELETE_PATH.exec(url.pathname);
    if (!m) {
      emitError(requestId, ip, requestSize, 400, "bad_file_id", startedAt, tokenId);
      return jsonError(400, "bad_file_id");
    }
    upstreamUrl = `${env.GEMINI_FILES_BASE_URL ?? DEFAULT_GEMINI_FILES_BASE}/${m[1]}`;
    method = "DELETE";
  } else {
    if (requestSize > MAX_UPLOAD_BYTES) {
      // Beyond the leg-A in-memory ceiling → leg B's job; reject without buffering.
      emitError(requestId, ip, requestSize, 413, "upload_too_large", startedAt, tokenId);
      return jsonError(413, "upload_too_large");
    }
    upstreamUrl = env.GEMINI_UPLOAD_URL ?? DEFAULT_GEMINI_UPLOAD_URL;
    method = "POST";
    body = request.body;
  }

  const upstream = await fetchWithRetry(upstreamUrl, {
    method,
    headers: upstreamHeaders,
    body,
  });

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
    classification_decision: null, // binary upload — not a classifiable text shape
    classification_category: null,
    classifier_error_reason: null,
    duration_ms: Date.now() - startedAt,
    upstream_status: upstream.status,
  });

  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  return new Response(upstream.body, { status: upstream.status, headers: respHeaders });
}
