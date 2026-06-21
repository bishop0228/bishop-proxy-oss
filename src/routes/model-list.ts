/**
 * GET model-list leg (provider-generic; W38-S935) — the live-freshness fan-out.
 *
 * The daemon's freshness layer (daemon/src/model/freshness_fetch.py) GETs the
 * live per-provider model list through this leg so retired ids auto-prune
 * (deepseek-r1, decommissioned groq, future churn) instead of leaking from the
 * bundled (stale) catalog. Before this route existed the GET fell through to
 * not_found 404 for EVERY provider → freshness was universally `[bundled]`.
 *
 * This is OPERATIONAL egress, NOT model inference — like /model-registry/ and
 * /mcp/ it drops the classifier + cost-meter and carries only the flat
 * abuse-bound quota. It is:
 *
 *   • PROVIDER-GENERIC — the upstream {host, model-list path, auth shape} is read
 *     SERVER-SIDE from the frozen MODEL_LIST_SPECS keyed by the `X-Bishop-Provider`
 *     header, NEVER from the inbound request (the W9.7 SSRF discipline). The
 *     inbound path is advisory only; the proxy derives the real upstream path.
 *   • CREDENTIAL-SCOPED — managed providers use the operator key (the user's key
 *     is never spent on a managed list); BYOK/subscription forward the user's own
 *     key in `X-Bishop-Upstream-Key`, mapped into the provider's auth shape.
 *   • ZERO-NEW-EGRESS — every spec host is already in ALLOWED_OUTBOUND_HOSTS (the
 *     completion legs' hosts), reused here for a read-only GET.
 *
 * Steps (mirroring the /model-registry/ leg's hygiene):
 *   1. Provider lookup — X-Bishop-Provider → MODEL_LIST_SPECS; unknown → 404
 *      unknown_provider, NO forward (→ daemon degrades to bundled).
 *   2. Bearer parse + AuthStoreDO /verify-token.
 *   3. Egress assert — spec.upstreamHost ∈ ALLOWED_OUTBOUND_HOSTS (defense-in-depth;
 *      a drift fails closed 500, never silently widens).
 *   4. flat-weight quota /check (abuse-bound, weight 1, cost 0 — not inference).
 *   5. Credential resolve — operator key (managed) / forwarded X-Bishop-Upstream-Key
 *      (BYOK); fail-closed if absent, NO forward.
 *   6. Forward the upstream GET (key in the provider's auth shape; deepseek via
 *      Cloudflare AI Gateway when CF_AIG_* is set). Manual redirect — each 3xx
 *      Location host is re-checked against the egress allowlist before an EXPLICIT
 *      re-fetch (open-redirect → exfil block).
 *   7. emitResponse — metadata-only ProxyLogEvent (request_id + token_id + status).
 *      The credential and the body are NEVER logged (Pillar 1).
 *   8. Stream the upstream body straight back (the daemon parses the id list from
 *      the OpenAI `{"data":[{"id"}]}` / Gemini `{"models":[{"name"}]}` shapes).
 */

import type { Env } from "../index";
import { envVar } from "../lib/env-var";
import {
  ALLOWED_OUTBOUND_HOSTS,
  isAnchoredEnterpriseHost,
} from "../lib/outbound-allowlist";
import { MODEL_LIST_SPECS, type ModelListSpec } from "../lib/model-list-specs";
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

/** Bound on the explicit redirect-follow chain. */
const MAX_REDIRECT_HOPS = 5;

/**
 * A host is admissible only when it is on the egress boundary the fetch
 * interceptor enforces — an exact allowlist entry OR an anchored enterprise
 * pattern. Anything else is refused before any fetch.
 */
function isAllowedEgressHost(host: string): boolean {
  return (
    (ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(host) ||
    isAnchoredEnterpriseHost(host)
  );
}

/**
 * Rebuild the upstream GET headers. Strip-all (Pillar 1 identifier-strip): NONE
 * of the inbound headers (the daemon Bearer, X-Bishop-Upstream-Key, user-agent,
 * x-forwarded-for) survive — only `accept` is set, plus the resolved credential
 * in the provider's auth shape. `query` auth carries the key in the URL, not here.
 */
function rebuildModelListHeaders(spec: ModelListSpec, key: string): Headers {
  const out = new Headers();
  out.set("accept", "application/json");
  if (spec.auth === "bearer") {
    out.set("authorization", `Bearer ${key}`);
  } else if (spec.auth === "anthropic") {
    out.set("x-api-key", key);
    out.set("anthropic-version", spec.anthropicVersion ?? "2023-06-01");
  }
  return out;
}

export async function handleModelList(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  // Step 1 — provider lookup. The provider names the upstream; the host + path +
  // auth are derived server-side from the frozen spec (never the request).
  const provider = (request.headers.get("x-bishop-provider") ?? "").trim();
  const spec = MODEL_LIST_SPECS[provider];
  if (!spec) {
    emitError(requestId, ip, requestSize, 404, "unknown_provider", startedAt);
    return jsonError(404, "unknown_provider");
  }

  // Step 2 — Bearer parse (the daemon's device/proxy token).
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
  const record = verify.record;
  const tokenId = record.token_id;

  // Step 3 — egress assert. spec.upstreamHost is the SOLE source — never the
  // request. Defense-in-depth: assert it ∈ the static allowlist (the fetch
  // interceptor is the runtime backstop). A drift fails closed (500); the route
  // NEVER widens egress.
  if (!isAllowedEgressHost(spec.upstreamHost)) {
    emitError(requestId, ip, requestSize, 500, "model_list_host_not_allowed", startedAt, tokenId);
    return jsonError(500, "model_list_host_not_allowed");
  }

  // Step 4 — tier read + flat-weight quota /check (abuse-bound; no cost meter —
  // a model-list read is not model inference).
  const tier = await readTier(env, tokenId);
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

  // Step 5 — credential resolve (fail-closed; NO forward on failure).
  let upstreamKey: string;
  if (spec.credentialSource === "operator") {
    // Managed: the operator key. The user's key is NEVER spent here.
    const op = (envVar(env, spec.operatorKeyVar ?? "") ?? "").trim();
    if (!op) {
      emitError(requestId, ip, requestSize, 400, "managed_key_unavailable", startedAt, tokenId);
      return jsonError(400, "managed_key_unavailable");
    }
    upstreamKey = op;
  } else {
    // BYOK/subscription: the user's own key, forwarded by the daemon. Absent →
    // fail closed (→ the daemon degrades that provider to its bundled catalog).
    const fwd = (request.headers.get("x-bishop-upstream-key") ?? "").trim();
    if (!fwd) {
      emitError(requestId, ip, requestSize, 400, "byok_key_missing", startedAt, tokenId);
      return jsonError(400, "byok_key_missing");
    }
    upstreamKey = fwd;
  }

  // Step 6 — forward the upstream GET. Host + path derived from the frozen spec.
  // deepseek (and any aiGatewayProvider spec) routes through Cloudflare AI Gateway
  // when CF_AIG_* is configured — gateway.ai.cloudflare.com is already allowlisted
  // (widens nothing); falls back to the direct host when AI Gateway is unset.
  const upstreamHeaders = rebuildModelListHeaders(spec, upstreamKey);
  let baseUrl: string;
  let upstreamPath = spec.modelListPath;
  if (spec.aiGatewayProvider && env.CF_AIG_ACCOUNT && env.CF_AIG_GATEWAY && env.CF_AIG_TOKEN) {
    baseUrl = `https://gateway.ai.cloudflare.com/v1/${env.CF_AIG_ACCOUNT}/${env.CF_AIG_GATEWAY}/${spec.aiGatewayProvider}`;
    // AI Gateway's provider path is the vendor-native path without the leading /v1.
    upstreamPath = spec.modelListPath.replace(/^\/v1(?=\/|$)/, "");
    upstreamHeaders.set("cf-aig-authorization", `Bearer ${env.CF_AIG_TOKEN}`);
  } else {
    baseUrl = `https://${spec.upstreamHost}`;
  }
  // `query` auth carries the credential in the URL (Gemini native model-list).
  const search = spec.auth === "query" ? `?key=${encodeURIComponent(upstreamKey)}` : "";
  let currentUrl = `${baseUrl}${upstreamPath}${search}`;
  let upstream = await fetchWithRetry(currentUrl, {
    method: "GET",
    headers: upstreamHeaders,
    redirect: "manual",
  });

  let hops = 0;
  while (upstream.status >= 300 && upstream.status < 400 && hops < MAX_REDIRECT_HOPS) {
    const location = upstream.headers.get("location");
    if (!location) break;
    let nextUrl: URL;
    try {
      nextUrl = new URL(location, currentUrl);
    } catch {
      emitError(requestId, ip, requestSize, 502, "model_list_redirect_blocked", startedAt, tokenId);
      return jsonError(502, "model_list_redirect_blocked");
    }
    if (!isAllowedEgressHost(nextUrl.hostname)) {
      // Off-allowlist redirect target → REFUSE, NO re-fetch (open-redirect block).
      emitError(requestId, ip, requestSize, 502, "model_list_redirect_blocked", startedAt, tokenId);
      return jsonError(502, "model_list_redirect_blocked");
    }
    currentUrl = nextUrl.toString();
    upstream = await fetchWithRetry(currentUrl, {
      method: "GET",
      headers: upstreamHeaders,
      redirect: "manual",
    });
    hops++;
  }

  // Step 7 — metadata-only audit (Pillar 1 — no credential, no body).
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

  // Step 8 — stream the upstream body straight back (content-type preserved). The
  // daemon parses the id list from the OpenAI / Gemini response shapes.
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
