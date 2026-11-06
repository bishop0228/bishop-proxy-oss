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
 *   1b. the browser's own request (W38-S1283 (4)) — its method rides
 *      X-Bishop-Egress-Method (missing or not one of the methods a browser
 *      sends → 400, NO forward), each of its headers rides
 *      X-Bishop-Browser-Header-<name>, and its body is the request body. The
 *      relay used to POST the browser's raw request bytes as the body, which
 *      this route forwarded with the relay's own method and headers: every GET
 *      reached the site as a POST of an HTTP request.
 *   2. Bearer parse + AuthStoreDO /verify-token (mirror /egress).
 *   3. SSRF gate the target — non-public/internal → 400, NO forward (fail-closed).
 *   4. flat-weight quota /check (abuse-bound, weight 1, cost 0 — operational, not
 *      inference).
 *   5. forward via the rawBrowserEgressFetch() seam (the sanctioned, SSRF-gated
 *      bypass of the static-host interceptor — leg 4 only) to the target URL,
 *      with the browser's method, its own headers only (never the Bishop auth,
 *      an X-Bishop-* header or the relay hop's headers) and its body; redirect
 *      "manual", so a 3xx goes back to the browser, which follows it through the
 *      relay itself: every hop then passes this route's gates, and the Worker
 *      never follows a host unseen.
 *   5b. a forward that throws → 502 upstream_fetch_failed, naming no cause (the
 *      runtime's message names none); a 525 or 526 answer, Cloudflare's when the
 *      TLS connection to the site failed → 502 upstream_tls_failed. Every other
 *      answer, any other 5xx included, is the site's and passes back.
 *   6. emitResponse — metadata-only ProxyLogEvent (no body, no host-content).
 *   7. the answer goes back with its headers (Set-Cookie and Location among
 *      them), less the hop-by-hop ones and the encoding the runtime has undone.
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

/** The methods a browser sends that this route carries (W38-S1283 (4)); CONNECT and TRACE are not among them. */
const BROWSER_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

/** Headers a proxy never forwards (RFC 9110 §7.6.1), with those the forward recomputes. */
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer",
  "transfer-encoding", "upgrade", "host", "content-length", "expect",
]);

const BROWSER_HEADER_PREFIX = "x-bishop-browser-header-";

/**
 * The browser's own headers, from the X-Bishop-Browser-Header-<name> fields the relay sends (W38-S1283 (4)). ONLY
 * those reach the site (Pillar 1): never the daemon Bearer, an X-Bishop-* control header or the relay hop's own
 * headers; a field naming a hop-by-hop header or an X-Bishop-* name is dropped too.
 */
function rebuildBrowserHeaders(incoming: Headers): Headers {
  const out = new Headers();
  for (const [k, v] of incoming.entries()) {
    const lk = k.toLowerCase();
    if (!lk.startsWith(BROWSER_HEADER_PREFIX)) continue;
    const name = lk.slice(BROWSER_HEADER_PREFIX.length);
    if (!name || HOP_BY_HOP.has(name) || name.startsWith("x-bishop-")) continue;
    out.append(name, v);
  }
  return out;
}

/**
 * The site's answer headers for the browser: all of them, Set-Cookie and Location among them, less the hop-by-hop
 * ones and the encoding headers (the runtime hands back the decoded body and recomputes its length). Iterating a
 * Headers yields each Set-Cookie on its own (the Fetch standard; measured in workerd and Node, 2026-11-06), so each
 * is appended as it came.
 */
function answerHeaders(upstream: Headers): Headers {
  const out = new Headers();
  for (const [k, v] of upstream.entries()) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) || lk === "content-encoding" || lk === "content-length") continue;
    out.append(k, v);
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

  // Step 1b — the browser's own method (W38-S1283 (4)); missing or not one a browser sends → 400, NO forward.
  const method = (request.headers.get("x-bishop-egress-method") ?? "").trim().toUpperCase();
  if (!BROWSER_METHODS.has(method)) {
    emitError(requestId, ip, requestSize, 400, "browser_egress_method_invalid", startedAt);
    return jsonError(400, "browser_egress_method_invalid");
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
  // leg 4 only), as the browser made it: its method, its own headers only
  // (Pillar 1) and its body. redirect "manual": a 3xx goes back to the browser.
  const rawBody = await request.arrayBuffer();
  const bodyless = method === "GET" || method === "HEAD";
  const forwardFetch = rawBrowserEgressFetch();
  const init: RequestInit = {
    method,
    headers: rebuildBrowserHeaders(request.headers),
    body: !bodyless && rawBody.byteLength > 0 ? rawBody : undefined,
    redirect: "manual",
  };
  // Step 5b — only the fetch is caught, so a fault in this route's own code still surfaces as one. A fetch that
  // throws never reached the site, whatever the cause, and the runtime's message ("internal error; reference = ..."
  // for a refused certificate and a failed DNS lookup alike) names none: a named 502 that claims no cause and
  // carries none of that text (the architect window's ruling, 2026-11-06).
  let upstream: Response;
  try {
    upstream = await forwardFetch(target, init);
  } catch {
    emitError(requestId, ip, requestSize, 502, "upstream_fetch_failed", startedAt, tokenId);
    return jsonError(502, "upstream_fetch_failed", { message: "the site could not be reached" });
  }
  // A 525 or 526 is Cloudflare's answer when the TLS connection to the site failed: the handshake, or the certificate
  // under the Full (strict) check a Worker's subrequest outside its zone always gets (Cloudflare's error-526 page, its
  // Workers section). A named 502 the guest can show as a certificate error. Every other answer, any other 5xx
  // included, is the site's and passes back below.
  if (upstream.status === 525 || upstream.status === 526) {
    emitError(requestId, ip, requestSize, 502, "upstream_tls_failed", startedAt, tokenId);
    return jsonError(502, "upstream_tls_failed", {
      message: "the site's TLS connection failed",
      upstream_status: upstream.status,
    });
  }

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

  // Step 7 — stream the upstream response straight back: its status and its headers, less the hop-by-hop ones and
  // the encoding the runtime has undone (W38-S1283 (4); before, only Content-Type came back).
  return new Response(upstream.body, {
    status: upstream.status,
    headers: answerHeaders(upstream.headers),
  });
}
