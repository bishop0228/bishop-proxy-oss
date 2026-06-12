/**
 * POST /browser-egress — the §3.2 leg-4 SANDBOXED-BROWSER egress route
 * (W38-S827, S5c-3b). The ONE egress class where the destination host is
 * REQUEST-determined (the open web a browser is driven to) rather than
 * server-side from a frozen spec.
 *
 * This is sound — NOT a hole in the §3.2 "host never taken unbounded from the
 * request" anchor — because the caller is a per-workflow microVM browser worker
 * that holds NONE of the user's data (no memory graph, no vault, no files, no
 * other workflow's data — only the current task's). Reaching an arbitrary public
 * host therefore cannot leak anything of the user's. The guarantee here is held
 * by ISOLATION + SSRF-GATING, not by allowlisting (a general browser cannot be
 * expressed as a fixed host list). See strongest_claims_security.md §3.2 leg 4 +
 * the Anchor carve.
 *
 * Discipline preserved:
 *   • SSRF-gated (isPublicHttpUrl) — reject RFC-1918 / link-local 169.254 +
 *     fe80::/10 / loopback 127 + ::1 / ULA fc00::/7 / cloud-metadata /
 *     non-http(s) scheme; allow PUBLIC http/https ONLY. The browser cannot pivot
 *     inward. (Defense-in-depth: the daemon relay ALSO SSRF-gates daemon-side via
 *     url_validator.validate_url BEFORE the request reaches here.)
 *   • §3.3 log discipline — the request/response BODY is NEVER logged (the
 *     ProxyLogEvent allowlist has no body/prompt/header field). The host is
 *     proxy-OBSERVED (the proxy forwards to it) but no user content is recorded.
 *   • Pillar 1 — the daemon Bearer + all X-Bishop-* control headers are stripped
 *     before the forward; never leaked to the public host.
 *
 *   1. target derive — the daemon relay supplies the request-determined target
 *      URL in X-Bishop-Browser-Target (missing → 400, NO forward).
 *   2. Bearer parse + AuthStoreDO /verify-token (mirror /egress).
 *   3. SSRF gate the target — non-public/internal → 400, NO forward (fail-closed).
 *   4. flat-weight quota /check (abuse-bound, weight 1, cost 0 — operational, not
 *      inference).
 *   5. forward via the rawBrowserEgressFetch() seam (the sanctioned, SSRF-gated
 *      bypass of the static-host interceptor — leg 4 only) to the target URL,
 *      with the Bishop auth + ALL X-Bishop-* control headers STRIPPED.
 *   6. emitResponse — metadata-only ProxyLogEvent (no body, no host-content).
 */

import type { Env } from "../index";
import { rawBrowserEgressFetch } from "../lib/outbound-allowlist";
import type { AuthRecord } from "../durable-objects/auth-store";
import {
  ip24From,
  jsonError,
  readTier,
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

export interface SsrfVerdict {
  ok: boolean;
  reason: string; // empty when ok; deny-rule name when blocked
  host: string;
}

// ── SSRF gate (mirrors daemon url_validator.validate_url's reject-set) ────────
// A Cloudflare Worker cannot resolve DNS synchronously, so this gate is
// hostname/scheme-shaped: it rejects IP-literals in the private/reserved ranges,
// the named internal hostnames, and non-http(s) schemes. The DNS-resolved
// IP-range check is the DAEMON's first gate (url_validator.validate_url) — this
// is defense-in-depth at the proxy, not the sole gate.

function isPrivateIPv4(host: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const o = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (o.some((n) => n > 255)) return true; // malformed octet → treat as unsafe
  const [a, b] = o;
  if (a === 10) return true; // 10.0.0.0/8   RFC-1918
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC-1918
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC-1918
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local + 169.254.169.254 metadata
  if (a === 0) return true; // 0.0.0.0/8
  return false;
}

function isPrivateIPv6(host: string): boolean {
  let h = host;
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.indexOf(":") === -1) return false; // not an IPv6 literal
  h = h.toLowerCase();
  if (h === "::" || h === "::1") return true; // unspecified / loopback
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  if (mapped) return isPrivateIPv4(mapped[1]); // IPv4-mapped → check the v4
  if (/^fe[89ab]/.test(h)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(h)) return true; // fc00::/7 ULA
  return false;
}

/**
 * Allow a PUBLIC http/https URL only. Returns {ok:false, reason} for any
 * internal/private/reserved destination or non-http(s) scheme — fail-closed.
 */
export function isPublicHttpUrl(target: string): SsrfVerdict {
  let u: URL;
  try {
    u = new URL(target);
  } catch {
    return { ok: false, reason: "url_malformed", host: "" };
  }
  const scheme = u.protocol.toLowerCase();
  if (scheme !== "http:" && scheme !== "https:") {
    return { ok: false, reason: "scheme_not_http_https", host: u.hostname };
  }
  const raw = u.hostname.toLowerCase();
  const bare = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  if (!bare) return { ok: false, reason: "url_malformed", host: "" };
  if (
    bare === "localhost" ||
    bare.endsWith(".localhost") ||
    bare.endsWith(".local") ||
    bare.endsWith(".internal") ||
    bare === "metadata.google.internal" ||
    bare === "metadata.goog"
  ) {
    return { ok: false, reason: "internal_hostname", host: bare };
  }
  if (isPrivateIPv4(bare)) return { ok: false, reason: "ip_private_or_reserved", host: bare };
  if (isPrivateIPv6(raw)) return { ok: false, reason: "ip_private_or_reserved", host: bare };
  return { ok: true, reason: "", host: bare };
}

/**
 * Rebuild forward headers. STRIP (Pillar 1): the daemon Bearer, every
 * x-bishop-* control header (incl. X-Bishop-Browser-Target), and the hop-by-hop
 * host/content-length. Everything else survives byte-for-byte.
 */
function rebuildBrowserHeaders(incoming: Headers): Headers {
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

export async function handleBrowserEgress(
  request: Request,
  env: Env,
  _ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  // Step 1 — the request-determined target (the open web the browser is driven
  // to). Supplied by the daemon relay in X-Bishop-Browser-Target; missing → 400.
  const target = (request.headers.get("x-bishop-browser-target") ?? "").trim();
  if (!target) {
    emitError(requestId, ip, requestSize, 400, "browser_egress_target_missing", startedAt);
    return jsonError(400, "browser_egress_target_missing");
  }

  // Step 2 — Bearer parse.
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

  // Step 3 — SSRF gate the request-determined target. Non-public/internal →
  // 400, NO forward (fail-closed). The browser cannot pivot inward.
  const verdict = isPublicHttpUrl(target);
  if (!verdict.ok) {
    emitError(requestId, ip, requestSize, 400, `ssrf_${verdict.reason}`, startedAt, tokenId);
    return jsonError(400, "browser_egress_ssrf_blocked", { reason: verdict.reason });
  }

  // Step 4 — flat-weight quota /check (abuse-bound; no cost meter — operational
  // egress, not model inference).
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

  // Step 5 — forward to the request-determined PUBLIC target via the sanctioned
  // SSRF-gated raw-fetch seam (the ONE bypass of the static-host interceptor,
  // leg 4 only). The body is buffered opaquely; the Bishop auth + control
  // headers are stripped (Pillar 1).
  const rawBody = await request.arrayBuffer();
  const forwardFetch = rawBrowserEgressFetch();
  const upstream = await forwardFetch(target, {
    method: request.method,
    headers: rebuildBrowserHeaders(request.headers),
    body: rawBody.byteLength > 0 ? rawBody : undefined,
  });

  // Step 6 — metadata-only audit (Pillar 1 — no token, no body, no host-content).
  // The destination host is proxy-OBSERVED (the forward above went to it); the
  // ProxyLogEvent allowlist structurally guarantees the BODY is never logged.
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
