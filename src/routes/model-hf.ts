/**
 * GET /model-hf/<path> — governed HuggingFace model-download egress (W38-S868 §9.3.8c).
 *
 * The SECOND governed model-download source after the Ollama registry (B1,
 * src/routes/model-registry.ts). It exists so a user who wants a model NOT in
 * Bishop's curated catalog can still fetch it THROUGH Bishop's sealed boundary
 * (trust-on-first-use content-pin daemon-side) rather than reaching the open web
 * ungoverned. Like /model-registry it is:
 *
 *   • READ-ONLY (GET only; the dispatcher only routes GET here),
 *   • FROZEN-host (HF_HOST = "huggingface.co" is a server-side const, NEVER
 *     request-derived — there is no per-account host shape here), and
 *   • ANONYMOUS (public HF repos need no upstream credential — the daemon Bearer
 *     is NEVER forwarded upstream; Pillar 1 identifier-strip). Gated/private repos
 *     are out of scope (they would need a forwarded HF token — a deliberate
 *     future, founder-reviewed extension).
 *
 * Steps (mirror /model-registry):
 *   1. Bearer parse + AuthStoreDO /verify-token.
 *   2. Path guard: only forward `<org>/<name>/resolve/<rev>/<file>` (the weight-
 *      download path) or `/api/models/...` (metadata). Anything else → 404
 *      model_hf_path_not_allowed, NO forward.
 *   3. Frozen host: HF_HOST const, asserted ∈ ALLOWED_OUTBOUND_HOSTS (drift → 500).
 *   4. flat-weight quota /check (abuse-bound, weight 1, cost 0 — not inference).
 *   5. fetchWithRetry GET, redirect:"manual". HF redirects resolve→LFS/Xet CDN
 *      (HUGGINGFACE_CDN_HOST_PATTERN). Each 3xx Location host is re-checked
 *      against the egress allowlist — an off-allowlist redirect target is REFUSED
 *      (model_hf_redirect_blocked, 502, NO re-fetch). Bounded hop count.
 *   6. emitResponse — metadata-only (no Bearer, no body — Pillar 1).
 *   7. Stream the upstream body straight back (content-type/length preserved;
 *      multi-GB weights are NEVER buffered).
 *
 * NO cert-pinning here (a Worker cannot pin TLS chains); the integrity floor on
 * THIS leg is the frozen host + every redirect hop allowlisted + no-secrets-in-
 * logs. The daemon-side trust-on-first-use sha256 pin (model_tofu) is the
 * artifact-integrity backstop.
 */

import type { Env } from "../index";
import type { ProxyLogEvent } from "../lib/log";
import {
  ALLOWED_OUTBOUND_HOSTS,
  isAnchoredEnterpriseHost,
} from "../lib/outbound-allowlist";
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

/** The single frozen HuggingFace host. NEVER derived from the request. */
const HF_HOST = "huggingface.co";

/** Bound on the explicit redirect-follow chain (resolve → CDN). */
const MAX_REDIRECT_HOPS = 5;

/**
 * Forwardable sub-paths: a weight-download `<org>/<name>/resolve/<rev>/<file>`
 * OR the read-only model-metadata API `/api/models/...`. Anything else is
 * refused with NO forward (no arbitrary HF reach).
 */
const RESOLVE_PATH_RE = /^\/[^/]+\/[^/]+\/resolve\//;
function isForwardablePath(subPath: string): boolean {
  return RESOLVE_PATH_RE.test(subPath) || subPath.startsWith("/api/models/");
}

/**
 * A redirect target host is admissible only when it is on the same egress
 * boundary the fetch interceptor enforces — an exact allowlist entry OR an
 * anchored enterprise/CDN pattern. Anything else is an open-redirect → exfil
 * vector and is refused before any re-fetch.
 */
function isAllowedEgressHost(host: string): boolean {
  return (
    (ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(host) ||
    isAnchoredEnterpriseHost(host)
  );
}

/**
 * Rebuild upstream headers for the HF GET. Strip-all (Pillar 1 identifier-strip):
 * the daemon Bearer and every client identifier are dropped — public HF repos are
 * anonymous, so NO authorization is forwarded. Only `accept` + `range` survive so
 * the CDN can negotiate the media type / resumable byte ranges.
 */
function rebuildHfHeaders(incoming: Headers): Headers {
  const out = new Headers();
  const accept = incoming.get("accept");
  if (accept) out.set("accept", accept);
  if (!out.has("accept")) out.set("accept", "application/octet-stream");
  const range = incoming.get("range");
  if (range) out.set("range", range);
  return out;
}

export async function handleModelHf(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  // url.pathname = "/model-hf/<...>"; the forwarded sub-path is the remainder.
  const subPath = url.pathname.slice("/model-hf".length);

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

  // Step 1b — token verification via AuthStoreDO /verify-token.
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

  // Step 2 — path guard. Only the weight-download / metadata sub-paths forward;
  // anything else is refused with NO forward.
  if (!isForwardablePath(subPath)) {
    emitError(requestId, ip, requestSize, 404, "model_hf_path_not_allowed", startedAt, tokenId);
    return jsonError(404, "model_hf_path_not_allowed");
  }

  // Step 3 — frozen host. HF_HOST is the SOLE source — never the request.
  // Defense-in-depth: assert it ∈ the static allowlist (the fetch interceptor is
  // the runtime backstop). A drift is a config error and fails closed (500).
  if (!(ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(HF_HOST)) {
    emitError(requestId, ip, requestSize, 500, "model_hf_host_not_allowed", startedAt, tokenId);
    return jsonError(500, "model_hf_host_not_allowed");
  }

  // Step 4 — tier read + flat-weight quota /check (abuse-bound; no cost meter —
  // model downloads are not inference).
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

  // Step 5 — forward the GET with manual redirect handling. The base URL host is
  // the frozen HF host (env override is a test seam only); the search is
  // preserved. Each 3xx is re-checked against the egress allowlist before an
  // EXPLICIT re-fetch — a transparent follow would leave an open-redirect → exfil
  // gap. Bounded hop count guards against a redirect loop.
  const upstreamHeaders = rebuildHfHeaders(request.headers);
  const baseUrl = env.HF_BASE_URL ?? `https://${HF_HOST}`;
  let currentUrl = `${baseUrl}${subPath}${url.search || ""}`;
  let upstream = await fetchWithRetry(currentUrl, {
    method: "GET",
    headers: upstreamHeaders,
    redirect: "manual",
  });

  let hops = 0;
  while (upstream.status >= 300 && upstream.status < 400 && hops < MAX_REDIRECT_HOPS) {
    const location = upstream.headers.get("location");
    if (!location) break; // 3xx without a Location — pass it straight back.
    let nextUrl: URL;
    try {
      nextUrl = new URL(location, currentUrl);
    } catch {
      emitError(requestId, ip, requestSize, 502, "model_hf_redirect_blocked", startedAt, tokenId);
      return jsonError(502, "model_hf_redirect_blocked");
    }
    if (!isAllowedEgressHost(nextUrl.hostname)) {
      // Off-allowlist redirect target → REFUSE, NO re-fetch (open-redirect block).
      emitError(requestId, ip, requestSize, 502, "model_hf_redirect_blocked", startedAt, tokenId);
      return jsonError(502, "model_hf_redirect_blocked");
    }
    currentUrl = nextUrl.toString();
    upstream = await fetchWithRetry(currentUrl, {
      method: "GET",
      headers: upstreamHeaders,
      redirect: "manual",
    });
    hops++;
  }

  // Step 6 — metadata-only audit (Pillar 1 — no token, no body).
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

  // Step 7 — stream the upstream body straight back (content-type + content-length
  // preserved; multi-GB weights are NEVER buffered).
  const respHeaders = new Headers();
  const ct = upstream.headers.get("content-type");
  if (ct) respHeaders.set("content-type", ct);
  const cl = upstream.headers.get("content-length");
  if (cl) respHeaders.set("content-length", cl);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}

// Re-export so callers/tests can read the leg's audit event type if needed.
export type { ProxyLogEvent };
