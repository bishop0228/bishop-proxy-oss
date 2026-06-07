/**
 * POST /byok/vertex/token — §1.17.19 Vertex SA-token mint leg.
 *
 * Steps 1-2 only (Bearer parse + verify-token). No tier / quota / classify /
 * key injection. Forwards the daemon-signed RS256 JWT assertion (urlencoded)
 * to Google's oauth2.googleapis.com/token endpoint. The returned access_token
 * is passed through to the daemon but NEVER logged (Pillar 1).
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import type { AuthRecord } from "../durable-objects/auth-store";
import {
  ip24From,
  jsonError,
  fetchWithRetry,
  emitError,
  emitResponse,
} from "./messages";
import { VERTEX_TOKEN_UPSTREAM } from "../lib/vertex-token-spec";

interface VerifyTokenResult {
  valid: boolean;
  record: AuthRecord | null;
  reason: "not_found" | "revoked" | "expired" | null;
}

export async function handleVertexToken(
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
  const tokenId = verify.record.token_id;

  // Sealed urlencoded forward — no tier / quota / classify / key injection.
  const rawBody = await request.text();

  // Build clean upstream headers: content-type only. Strip inbound Bishop Authorization.
  const upstreamHeaders = new Headers();
  upstreamHeaders.set(
    "content-type",
    request.headers.get("content-type") ?? "application/x-www-form-urlencoded",
  );

  const baseUrl =
    envVar(env, VERTEX_TOKEN_UPSTREAM.tokenBaseUrlVar) ??
    `https://${VERTEX_TOKEN_UPSTREAM.tokenHost}`;
  const upstream = await fetchWithRetry(`${baseUrl}${VERTEX_TOKEN_UPSTREAM.tokenPath}`, {
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
