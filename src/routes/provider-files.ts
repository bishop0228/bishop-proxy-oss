/**
 * OpenAI + Anthropic Files API passthrough — point/ship large-media upload (leg A),
 * provider-agnostic: PDFs and images work on every cloud model, not just Gemini.
 *
 *   POST   /v1/openai/files        → api.openai.com/v1/files       (multipart)
 *   DELETE /v1/openai/files/{id}   → api.openai.com/v1/files/{id}
 *   POST   /v1/anthropic/files     → api.anthropic.com/v1/files    (multipart)
 *   DELETE /v1/anthropic/files/{id}→ api.anthropic.com/v1/files/{id}
 *
 * Both providers expose `POST /v1/files`, so the proxy namespaces them by provider in
 * the path (the existing /v1/<provider>/... convention). The daemon's per-provider
 * Files client uploads the raw image/PDF bytes as multipart/form-data, references the
 * returned file_id in the completion (OpenAI input_file / Anthropic document|image
 * block), then DELETEs it right after (upload → use → DELETE).
 *
 * Same choke sequence + single-seal §3.2 posture as the Gemini route: host FROZEN
 * server-side (api.openai.com / api.anthropic.com, both already allowlisted), never
 * request-derived; operator key substituted (managed → operator OPENAI/ANTHROPIC key,
 * fail-closed managed_key_unavailable; byok → the user's x-bishop-upstream-key); the
 * inbound daemon Bearer never leaks (Pillar 1). The multipart body is forwarded verbatim
 * — no JSON parse, no classifier on raw bytes (the file's text floor is classified on
 * the completion leg; the binary upload is transparency-tagged via the daemon's dynamic
 * retention tag — never silently blocked).
 *
 * Anthropic files require the `anthropic-beta: files-api-*` + `anthropic-version`
 * headers; the daemon sets them and rebuildHeaders forwards them (they're on the
 * Anthropic FORWARD_ALLOWLIST). OpenAI uses Bearer (rebuildOpenAIHeaders). The
 * multipart Content-Type (with its boundary) is preserved by both rebuilds.
 */

import type { Env } from "../index";
import { resolveUpstreamKey, rebuildHeaders, rebuildOpenAIHeaders } from "../lib/headers";
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

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // leg-A in-memory ceiling; bigger → leg B.

// Host FROZEN server-side (single seal §3.2). { upload, delete-base } per provider.
const DEFAULT_OPENAI_FILES = "https://api.openai.com/v1/files";
const DEFAULT_ANTHROPIC_FILES = "https://api.anthropic.com/v1/files";

// Anchored path matchers — file id constrained to the providers' id alphabet
// (alnum/dot/dash/underscore: OpenAI `file-…`, Anthropic `file_…`); no slash, no host.
const OPENAI_DELETE = /^\/v1\/openai\/files\/([A-Za-z0-9._-]+)$/;
const ANTHROPIC_DELETE = /^\/v1\/anthropic\/files\/([A-Za-z0-9._-]+)$/;

type Provider = "openai" | "anthropic";

function providerOf(pathname: string): Provider | null {
  if (pathname.startsWith("/v1/openai/files")) return "openai";
  if (pathname.startsWith("/v1/anthropic/files")) return "anthropic";
  return null;
}

export async function handleProviderFiles(
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

  const provider = providerOf(url.pathname);
  if (!provider) {
    emitError(requestId, ip, requestSize, 404, "unknown_files_provider", startedAt);
    return jsonError(404, "unknown_files_provider");
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

  // Step 2 — token verification.
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

  // Step 3 — tier.
  const tier = await readTier(env, tokenId);

  // Step 4 — quota /check (flat weight).
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

  // Step 5 — entitlement gate (fail-closed). Operator key per provider.
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const operatorKey = provider === "openai" ? (env.OPENAI_API_KEY ?? null) : env.ANTHROPIC_API_KEY;
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, operatorKey);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders =
    provider === "openai"
      ? rebuildOpenAIHeaders(request.headers, keyResolution.key)
      : rebuildHeaders(request.headers, keyResolution.key);

  // Step 6 — forward. Host frozen server-side; multipart body forwarded verbatim.
  const uploadUrl =
    provider === "openai"
      ? (env.OPENAI_FILES_URL ?? DEFAULT_OPENAI_FILES)
      : (env.ANTHROPIC_FILES_URL ?? DEFAULT_ANTHROPIC_FILES);
  const deleteRe = provider === "openai" ? OPENAI_DELETE : ANTHROPIC_DELETE;

  let upstreamUrl: string;
  let method: string;
  let body: BodyInit | null = null;
  if (isDelete) {
    const m = deleteRe.exec(url.pathname);
    if (!m) {
      emitError(requestId, ip, requestSize, 400, "bad_file_id", startedAt, tokenId);
      return jsonError(400, "bad_file_id");
    }
    upstreamUrl = `${uploadUrl}/${m[1]}`;
    method = "DELETE";
  } else {
    if (requestSize > MAX_UPLOAD_BYTES) {
      emitError(requestId, ip, requestSize, 413, "upload_too_large", startedAt, tokenId);
      return jsonError(413, "upload_too_large");
    }
    upstreamUrl = uploadUrl;
    method = "POST";
    body = request.body;
  }

  const upstream = await fetchWithRetry(upstreamUrl, { method, headers: upstreamHeaders, body });

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
    classification_decision: null, // multipart binary upload — not a classifiable text shape
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
