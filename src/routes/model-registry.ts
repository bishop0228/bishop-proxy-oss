/**
 * GET /model-registry/<path> — governed model-registry egress route (B1).
 *
 * The §3.2 operational-egress path for read-only model-registry lookups: Bishop's
 * daemon routes outbound Ollama model-registry GETs through this proxy so the
 * registry manifest/blob fetch shares the byok auth/quota choke. Like the /mcp/
 * leg this is NOT model inference — it drops the classifier and cost-meter — but
 * unlike /mcp/ it is:
 *
 *   • READ-ONLY (GET only; the dispatcher only routes GET here),
 *   • FROZEN-host (registry.ollama.ai is a server-side const, NEVER request-
 *     derived — there is no per-account or per-tenant host shape here), and
 *   • ANONYMOUS (the public Ollama registry needs no upstream credential — the
 *     daemon Bearer is NEVER forwarded upstream; Pillar 1 identifier-strip).
 *
 * Steps:
 *   1. Bearer parse + AuthStoreDO /verify-token            (mirror /mcp/ step 1-2).
 *   2. Path guard: only forward sub-paths under /v2/ (the OCI-distribution
 *      registry API root). Anything else → 404 model_registry_path_not_allowed,
 *      NO forward.
 *   3. Frozen host: REGISTRY_HOST = "registry.ollama.ai" — a server const, never
 *      from the request. Defense-in-depth asserts it ∈ ALLOWED_OUTBOUND_HOSTS
 *      (the fetch interceptor is the runtime backstop); a drift fails closed (500).
 *   4. flat-weight quota /check (abuse-bound, weight 1, cost 0 — not inference).
 *   5. fetchWithRetry GET with redirect:"manual". The registry redirects manifest/
 *      blob reads to a CDN; we DO NOT auto-follow. Each 3xx Location host is
 *      re-checked against the egress allowlist — an off-allowlist redirect target
 *      is REFUSED (model_registry_redirect_blocked, 502, NO re-fetch); an allowed
 *      target is re-fetched EXPLICITLY (bounded hop count). This closes the
 *      open-redirect → SSRF/exfil gap a transparent redirect-follow would leave.
 *   6. Stream the upstream body straight back (content-type + content-length
 *      preserved; multi-GB blobs are NEVER buffered).
 *   7. emitResponse — metadata-only ProxyLogEvent (request_id + token_id +
 *      status). The daemon Bearer and the body are NEVER logged (Pillar 1).
 *
 * NO cert-pinning here: a Cloudflare Worker cannot enforce TLS chain pinning
 * (the daemon-side content-pin is B2). The integrity floor on THIS leg is the
 * frozen host + every redirect hop allowlisted + no-secrets-in-logs.
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

/** The single frozen model-registry host. NEVER derived from the request. */
const REGISTRY_HOST = "registry.ollama.ai";

/** Bound on the explicit redirect-follow chain (manifest → blob → CDN). */
const MAX_REDIRECT_HOPS = 5;

/**
 * A redirect target host is admissible only when it is on the same egress
 * boundary the fetch interceptor enforces — an exact allowlist entry OR an
 * anchored enterprise pattern. Anything else is an open-redirect → exfil vector
 * and is refused before any re-fetch.
 */
function isAllowedEgressHost(host: string): boolean {
  return (
    (ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(host) ||
    isAnchoredEnterpriseHost(host)
  );
}

/**
 * Rebuild upstream headers for the registry GET. Strip-all (Pillar 1 identifier-
 * strip): the daemon Bearer and every client identifier are dropped — the public
 * registry is anonymous, so NO authorization is forwarded. Only `accept` survives
 * so the registry can negotiate the manifest/blob media type.
 */
function rebuildRegistryHeaders(incoming: Headers): Headers {
  const out = new Headers();
  const accept = incoming.get("accept");
  if (accept) out.set("accept", accept);
  if (!out.has("accept")) out.set("accept", "application/json");
  return out;
}

export async function handleModelRegistry(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  const url = new URL(request.url);
  // url.pathname = "/model-registry/v2/<...>"; the forwarded sub-path is the
  // remainder. The dispatcher only routes "/model-registry/..." here.
  const subPath = url.pathname.slice("/model-registry".length);

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

  // Step 2 — path guard. Only the OCI-distribution /v2/ API root is forwardable;
  // anything else is refused with NO forward (no arbitrary registry reach).
  if (!subPath.startsWith("/v2/")) {
    emitError(requestId, ip, requestSize, 404, "model_registry_path_not_allowed", startedAt, tokenId);
    return jsonError(404, "model_registry_path_not_allowed");
  }

  // Step 3 — frozen host. REGISTRY_HOST is the SOLE source — never the request.
  // Defense-in-depth: assert it ∈ the static allowlist (the fetch interceptor is
  // the runtime backstop). A drift is a config error and fails closed (500).
  if (!(ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(REGISTRY_HOST)) {
    emitError(requestId, ip, requestSize, 500, "model_registry_host_not_allowed", startedAt, tokenId);
    return jsonError(500, "model_registry_host_not_allowed");
  }

  // Step 4 — tier read + flat-weight quota /check (abuse-bound; no cost meter —
  // registry reads are not model inference).
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
  // the frozen registry host (env override is a test seam only); the search is
  // preserved. Each 3xx is re-checked against the egress allowlist before an
  // EXPLICIT re-fetch — a transparent follow would leave an open-redirect → exfil
  // gap. Bounded hop count guards against a redirect loop.
  const upstreamHeaders = rebuildRegistryHeaders(request.headers);
  const baseUrl = env.OLLAMA_REGISTRY_BASE_URL ?? `https://${REGISTRY_HOST}`;
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
      emitError(requestId, ip, requestSize, 502, "model_registry_redirect_blocked", startedAt, tokenId);
      return jsonError(502, "model_registry_redirect_blocked");
    }
    if (!isAllowedEgressHost(nextUrl.hostname)) {
      // Off-allowlist redirect target → REFUSE, NO re-fetch (open-redirect block).
      emitError(requestId, ip, requestSize, 502, "model_registry_redirect_blocked", startedAt, tokenId);
      return jsonError(502, "model_registry_redirect_blocked");
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
  // preserved; multi-GB blobs are NEVER buffered).
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
