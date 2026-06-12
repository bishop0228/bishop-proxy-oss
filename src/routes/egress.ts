/**
 * POST /v1/egress — generic allowlist-gated forward egress route (W38-S822, S5b-1).
 *
 * The §3.2-preserving channel a Bishop worker-microVM reaches the outside world
 * through: the (separate) vsock host-relay (S5b-2) forwards a guest's outbound
 * request here, and the proxy forwards it on — but ONLY to a host already on the
 * frozen, founder-reviewed ALLOWED_OUTBOUND_HOSTS allowlist. All worker egress
 * still flows through proxy.mybishop.ai, and the allowlist remains the boundary.
 *
 * Unlike the per-provider inference legs (which hardcode the upstream host + do
 * provider auth/transform), this is a GENERIC forward: the worker says WHERE via
 * the X-Bishop-Egress-Target header, bounded by the allowlist. The body is an
 * opaque byte pass-through (no parse, no classifier, no cost meter) — operational
 * egress, not model inference, so quota is a flat abuse-bound weight of 1.
 *
 *   1. target derive — X-Bishop-Egress-Target (a control header, NEVER the body).
 *      Absent / unparseable / non-http(s) → 400, NO forward.
 *   2. Bearer parse + AuthStoreDO /verify-token            (mirror chat-completions).
 *   3. flat-weight quota /check (abuse-bound, weight 1, cost 0 — not inference).
 *   4. forward — fetchWithRetry(target, { method, headers: <Bishop auth + ALL
 *      X-Bishop-* control headers STRIPPED, Pillar 1>, body }). The installed
 *      installFetchAllowlist() AUTO-rejects a non-allowlisted target by throwing
 *      OutboundHostNotAllowed — caught here → 403 with a generic message (the
 *      allowlist contents are NEVER leaked). No manual host-check: the frozen
 *      allowlist is the single seal.
 *   5. emitResponse — metadata-only ProxyLogEvent (request_id + token_id +
 *      status). The daemon Bearer and the body are NEVER logged (Pillar 1).
 *
 * NO host is added here — the route forwards only to already-allowlisted hosts
 * and 403s everything else. The Class B worker host-adds are per-worker in S5c
 * (founder-reviewed, like the W9.7 per-account/fixed-host arcs). Mechanism first.
 */

import type { Env } from "../index";
import { OutboundHostNotAllowed } from "../lib/outbound-allowlist";
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

/** The control header that carries the worker's intended egress target URL. */
const EGRESS_TARGET_HEADER = "x-bishop-egress-target";

/**
 * Rebuild upstream headers for the generic forward. STRIP (Pillar 1):
 *   • authorization — the daemon Bearer (verified here; NEVER leaked upstream),
 *   • every x-bishop-* control header (incl. X-Bishop-Egress-Target itself), and
 *   • the hop-by-hop host/content-length (recomputed by the runtime fetch).
 * Everything else survives byte-for-byte — a worker that needs upstream auth
 * carries it in a non-Bishop header (e.g. its own x-api-key), which passes through.
 */
function rebuildEgressHeaders(incoming: Headers): Headers {
  const out = new Headers();
  for (const [k, v] of incoming.entries()) {
    const lk = k.toLowerCase();
    if (lk === "authorization") continue; // daemon Bearer — never forwarded
    if (lk.startsWith("x-bishop-")) continue; // ALL Bishop control headers stripped
    if (lk === "host" || lk === "content-length") continue; // recomputed by fetch
    out.set(k, v);
  }
  return out;
}

export async function handleEgress(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  // Step 1 — target from the request (control header, never the body). Reject an
  // absent / unparseable / non-http(s) target with NO forward.
  const rawTarget = (request.headers.get(EGRESS_TARGET_HEADER) ?? "").trim();
  if (!rawTarget) {
    emitError(requestId, ip, requestSize, 400, "egress_target_missing", startedAt);
    return jsonError(400, "egress_target_missing");
  }
  let target: URL;
  try {
    target = new URL(rawTarget);
  } catch {
    emitError(requestId, ip, requestSize, 400, "egress_target_invalid", startedAt);
    return jsonError(400, "egress_target_invalid");
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    emitError(requestId, ip, requestSize, 400, "egress_target_invalid", startedAt);
    return jsonError(400, "egress_target_invalid");
  }

  // Step 2 — Bearer parsing.
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

  // Step 2b — token verification via AuthStoreDO /verify-token.
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

  // Step 3 — tier read + flat-weight quota /check (abuse-bound; no cost meter —
  // generic egress is not model inference).
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

  // Step 4 — forward. The body is buffered opaquely (no parse) so fetchWithRetry
  // may re-send it; headers are rebuilt with the Bishop auth + control headers
  // stripped. The installed allowlist AUTO-gates the target: a non-allowlisted
  // host throws OutboundHostNotAllowed (no manual host-check) — caught → 403 with
  // a GENERIC message (the allowlist contents are never leaked).
  const rawBody = await request.arrayBuffer();
  const upstreamHeaders = rebuildEgressHeaders(request.headers);
  let upstream: Response;
  try {
    upstream = await fetchWithRetry(target.toString(), {
      method: request.method,
      headers: upstreamHeaders,
      body: rawBody.byteLength > 0 ? rawBody : undefined,
    });
  } catch (err) {
    if (err instanceof OutboundHostNotAllowed) {
      emitError(requestId, ip, requestSize, 403, "egress_host_not_allowed", startedAt, tokenId);
      return jsonError(403, "egress_host_not_allowed");
    }
    throw err;
  }

  // Step 5 — metadata-only audit (Pillar 1 — no token, no body).
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

  // Stream the upstream response straight back (status + content-type preserved).
  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}

// Re-export so callers/tests can read the leg's audit event type if needed.
export type { ProxyLogEvent } from "../lib/log";
