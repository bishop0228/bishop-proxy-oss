/**
 * Behavioral probes for the W38-S827 (S5c-3b) §3.2 leg-4 SANDBOXED-BROWSER
 * egress leg (POST /browser-egress).
 *
 * UNLIKE /egress/<server_id> (host server-side from a frozen spec), the
 * destination here is REQUEST-determined — the open web a browser is driven to.
 * Soundness is by ISOLATION + SSRF-GATING, not allowlisting: the caller is a
 * VM-isolated, data-empty browser worker. These probes prove:
 *
 *   (S) isPublicHttpUrl SSRF-gates each internal class (RFC-1918 / link-local /
 *       loopback / ULA / metadata / IPv6 loopback / non-http(s) / malformed) and
 *       admits a PUBLIC http/https host.
 *   (1) ★ public-host forward — a public target → 200, forwarded to EXACTLY the
 *       request-determined host via the sanctioned raw-fetch seam.
 *   (2) ★ SSRF-reject-no-forward — each internal target → 400, NO forward.
 *   (3) ★ missing-target — no X-Bishop-Browser-Target → 400, NO forward.
 *   (4) ★ bad-token-401 — missing/invalid bearer → 401, NO forward.
 *   (5) ★ header-strip — daemon Bearer + ALL X-Bishop-* (incl. the target
 *       header) stripped; a non-Bishop header survives byte-for-byte.
 *   (6) ★ host-observed-body-never-logged — the forward reaches the observed
 *       host, and the emitted ProxyLogEvent carries NO body/prompt/header (§3.3).
 *   (7) quota — a quota /check 429 → 429 quota_exceeded passthrough; NO forward.
 *   (8) ★ the browser's request replayed (W38-S1283 (4)) — its method, its own
 *       headers (X-Bishop-Browser-Header-*) and its body reach the site; a GET
 *       carries no body; redirect "manual".
 *   (9) ★ method-invalid — a missing method, CONNECT or TRACE → 400, NO forward.
 *  (10) ★ the answer's headers — Location and each Set-Cookie come back, less the
 *       hop-by-hop and encoding headers; a 3xx is returned, never followed.
 *  (11) ★ tls — a 525 or 526 answer to the forward → 502 upstream_tls_failed.
 *  (12) ★ fetch-failed — a forward that throws → 502 upstream_fetch_failed,
 *       naming no cause and none of the runtime's text.
 *  (13) ★ other answers — a site's 503 passes back unchanged; a 200 control.
 *  (14) ★ own fault — a fault before the forward surfaces as itself.
 *  (15) ★ list caps — over 128 headers, a value over 16384 or a list over
 *       60 KiB → 502 upstream_headers_too_large; at the caps, the list built.
 *  (16) ★ own answers — the proxy's own answers carry no list.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleBrowserEgress, isPublicHttpUrl } from "../src/routes/browser-egress";
import {
  installFetchAllowlist,
  _resetForTesting,
} from "../src/lib/outbound-allowlist";
import { isProxyLogEvent } from "../src/lib/log";
import type { Env } from "../src/index";

// ── constants ──────────────────────────────────────────────────────────────

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
const PUBLIC_TARGET = "https://example.com/login?next=/portal";
const PUBLIC_HOST = "example.com";

// ── DO stubs (mirror egress.test.ts) ─────────────────────────────────────────

function makeStub(handler: (req: Request) => Promise<Response> | Response) {
  return {
    fetch: async (input: RequestInfo, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input as string, init);
      return handler(req);
    },
  };
}

function makeNamespace(handler: (req: Request) => Promise<Response> | Response): DurableObjectNamespace {
  return {
    idFromName: (_name: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    idFromString: (_s: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    newUniqueId: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    get: (_id: DurableObjectId) => makeStub(handler) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function makeCtx(): ExecutionContext {
  return {
    waitUntil: (_p: Promise<unknown>) => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
}

function makeAuthNamespace(valid: boolean) {
  const record = {
    token: DAEMON_BEARER,
    token_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-browser-egress-0.1.0",
    account_mode: "managed" as const,
  };
  return makeNamespace(async () =>
    valid
      ? new Response(JSON.stringify({ valid: true, record, reason: null }), {
          headers: { "content-type": "application/json" },
        })
      : new Response(JSON.stringify({ valid: false, record: null, reason: "not_found" }), {
          headers: { "content-type": "application/json" },
        }),
  );
}

function makeTierNamespace() {
  return makeNamespace(async () =>
    new Response(JSON.stringify({ tier: "free" }), { headers: { "content-type": "application/json" } }),
  );
}

function makeQuotaNamespace(status: 200 | 429) {
  return makeNamespace(async () =>
    status === 429
      ? new Response(JSON.stringify({ reason: "monthly_tasks_exceeded" }), {
          status: 429,
          headers: { "content-type": "application/json" },
        })
      : new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }),
  );
}

function makeEnv(opts: { authValid?: boolean; quotaStatus?: 200 | 429 } = {}): Env {
  return {
    AUTH_STORE: makeAuthNamespace(opts.authValid ?? true),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(opts.quotaStatus ?? 200),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
  } as unknown as Env;
}

// ── request helper ───────────────────────────────────────────────────────────

function browserReq(opts: {
  target?: string | null;
  bearer?: string | null;
  method?: string | null;
  hopMethod?: string;
  browserHeaders?: Record<string, string>;
  extraHeaders?: Record<string, string>;
  body?: string;
} = {}): Request {
  // The relay's hop: its own headers, the browser's method and headers as fields, the browser's body (W38-S1283 (4)).
  // The egress clerk makes the hop with the browser's own method (the architect window's ruling of 2026-11-06), a GET
  // or HEAD with no body and no Content-Type; a POST, as the clerk made every hop before, unless hopMethod names one.
  const hopMethod = opts.hopMethod ?? "POST";
  const bodyless = hopMethod === "GET" || hopMethod === "HEAD";
  const headers: Record<string, string> = {
    "user-agent": "bishop-daemon/0.1.0",
  };
  if (!bodyless) headers["content-type"] = "application/octet-stream";
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  const target = opts.target === undefined ? PUBLIC_TARGET : opts.target;
  if (target !== null) headers["x-bishop-browser-target"] = target;
  const method = opts.method === undefined ? "GET" : opts.method;
  if (method !== null) headers["x-bishop-egress-method"] = method;
  for (const [k, v] of Object.entries(opts.browserHeaders ?? {})) headers[`x-bishop-browser-header-${k}`] = v;
  Object.assign(headers, opts.extraHeaders ?? {});
  return new Request("http://proxy/browser-egress", {
    method: hopMethod,
    headers,
    body: bodyless ? undefined : opts.body ?? "",
  });
}

// ── isPublicHttpUrl unit probe (S) ──────────────────────────────────────────

describe("S5c-3b isPublicHttpUrl SSRF gate", () => {
  const BLOCKED: Array<[string, string]> = [
    ["http://10.0.0.5/x", "ip_private_or_reserved"],
    ["http://10.255.255.255/", "ip_private_or_reserved"],
    ["http://172.16.0.1/", "ip_private_or_reserved"],
    ["http://172.31.255.1/", "ip_private_or_reserved"],
    ["http://192.168.1.1/", "ip_private_or_reserved"],
    ["http://127.0.0.1/", "ip_private_or_reserved"],
    ["http://169.254.0.1/", "ip_private_or_reserved"],
    ["http://169.254.169.254/latest/meta-data/", "ip_private_or_reserved"], // cloud metadata
    ["http://0.0.0.0/", "ip_private_or_reserved"],
    ["http://[::1]/", "ip_private_or_reserved"], // IPv6 loopback
    ["http://[fe80::1]/", "ip_private_or_reserved"], // IPv6 link-local
    ["http://[fc00::1]/", "ip_private_or_reserved"], // IPv6 ULA
    ["http://[fd12:3456::1]/", "ip_private_or_reserved"], // IPv6 ULA fd
    ["http://localhost/", "internal_hostname"],
    ["http://foo.localhost/", "internal_hostname"],
    ["http://svc.internal/", "internal_hostname"],
    ["http://metadata.google.internal/", "internal_hostname"],
    ["ftp://example.com/", "scheme_not_http_https"],
    ["file:///etc/passwd", "scheme_not_http_https"],
    ["not-a-url", "url_malformed"],
  ];

  it("blocks every internal / reserved / non-http(s) class", () => {
    for (const [url, reason] of BLOCKED) {
      const v = isPublicHttpUrl(url);
      expect(v.ok, `${url} must be blocked`).toBe(false);
      expect(v.reason, `${url} reason`).toBe(reason);
    }
  });

  it("admits a PUBLIC http/https host", () => {
    for (const url of [
      "https://example.com/login",
      "http://api.github.com/x",
      "https://93.184.216.34/", // a public IP literal
    ]) {
      const v = isPublicHttpUrl(url);
      expect(v.ok, `${url} must be allowed`).toBe(true);
    }
  });
});

// ── handler probes ──────────────────────────────────────────────────────────

/** The site's headers as the clerk unwraps them: the decoded X-Bishop-Browser-Answer-Headers list (W38-S1283 (4)). */
function answerList(resp: Response): [string, string][] {
  const encoded = resp.headers.get("x-bishop-browser-answer-headers");
  if (encoded === null) throw new Error("no answer list");
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))));
}

interface Capture {
  url: string;
  headers: Headers;
  method: string;
  redirect: string | undefined;
  body: string | null;
}

describe("S5c-3b /browser-egress route", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  // Stub global fetch, THEN install the REAL allowlist interceptor — so
  // rawBrowserEgressFetch() (the sanctioned leg-4 seam) returns the captured
  // pre-install fetch = this mock. A SSRF-blocked target never reaches it.
  function installFetch(responder: (call: number, url: string) => Response) {
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const headers = input instanceof Request ? input.headers : new Headers(init?.headers);
      const body = init?.body ? new TextDecoder().decode(init.body as ArrayBuffer) : null;
      captures.push({ url, headers, method: String(init?.method ?? "GET"), redirect: init?.redirect, body });
      return responder(captures.length - 1, url);
    });
    vi.stubGlobal("fetch", mockFetch);
    installFetchAllowlist();
  }

  beforeEach(() => {
    captures = [];
  });

  afterEach(() => {
    _resetForTesting();
    vi.unstubAllGlobals();
  });

  // ── Probe 1: ★ public-host forward ──────────────────────────────────────
  it("★ public-host: a public target → 200, forwarded to EXACTLY the request-determined host", async () => {
    installFetch(() =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const resp = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();
    // The forward went to the request-determined target — host AND path/query.
    expect(captures[0].url).toBe(PUBLIC_TARGET);
    expect(new URL(captures[0].url).hostname).toBe(PUBLIC_HOST);
    expect(answerList(resp)).toContainEqual(["content-type", "application/json"]);
  });

  // ── Probe 2: ★ SSRF-reject-no-forward ───────────────────────────────────
  it("★ SSRF-reject: each internal target → 400 browser_egress_ssrf_blocked, NO forward", async () => {
    installFetch(() => new Response("LEAKED", { status: 200 }));

    const internal = [
      "http://127.0.0.1/admin",
      "http://10.1.2.3/",
      "http://192.168.0.1/",
      "http://169.254.169.254/latest/meta-data/",
      "http://[::1]/",
      "http://localhost:8080/",
      "ftp://example.com/x",
    ];
    for (const target of internal) {
      const resp = await handleBrowserEgress(browserReq({ target }), makeEnv(), makeCtx());
      expect(resp.status, `${target} must be 400`).toBe(400);
      expect(((await resp.json()) as { error: string }).error).toBe("browser_egress_ssrf_blocked");
    }
    // No internal target ever forwarded.
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 3: ★ missing-target ────────────────────────────────────────────
  it("★ missing-target: no X-Bishop-Browser-Target → 400 browser_egress_target_missing, NO forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const resp = await handleBrowserEgress(browserReq({ target: null }), makeEnv(), makeCtx());
    expect(resp.status).toBe(400);
    expect(((await resp.json()) as { error: string }).error).toBe("browser_egress_target_missing");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 4: ★ bad-token-401 ─────────────────────────────────────────────
  it("★ bad-token-401: missing bearer → 401 missing_bearer; invalid token → 401 token_not_found; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const noBearer = await handleBrowserEgress(browserReq({ bearer: null }), makeEnv(), makeCtx());
    expect(noBearer.status).toBe(401);
    expect(((await noBearer.json()) as { error: string }).error).toBe("missing_bearer");

    const badToken = await handleBrowserEgress(
      browserReq({ bearer: "z".repeat(40) }),
      makeEnv({ authValid: false }),
      makeCtx(),
    );
    expect(badToken.status).toBe(401);
    expect(((await badToken.json()) as { error: string }).error).toBe("token_not_found");

    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 5: ★ header-strip ──────────────────────────────────────────────
  it("★ header-strip: only the browser's own headers reach the site; never the Bearer, an X-Bishop-* header or the relay hop's", async () => {
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));

    const resp = await handleBrowserEgress(
      browserReq({
        browserHeaders: {
          "x-api-key": "browser-site-key", // the browser's own — survives
          "x-bishop-run-id": "run-123", // a field naming a Bishop header — dropped
          connection: "keep-alive", // hop-by-hop — dropped
        },
        extraHeaders: {
          "x-bishop-run-id": "run-123", // control header — must be stripped
          "x-relay-own": "relay-hop", // the relay hop's own header — not the browser's, never forwarded
        },
      }),
      makeEnv(),
      makeCtx(),
    );
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();

    const fwd = captures[0].headers;
    expect(fwd.get("authorization")).toBeNull(); // Bishop Bearer never forwarded
    expect(fwd.get("x-bishop-browser-target")).toBeNull(); // the control target header stripped
    expect(fwd.get("x-bishop-egress-method")).toBeNull();
    expect(fwd.get("x-bishop-run-id")).toBeNull();
    expect(fwd.get("connection")).toBeNull();
    expect(fwd.get("x-relay-own")).toBeNull();
    expect(fwd.get("user-agent")).toBeNull(); // the relay's agent is not the browser's
    expect(fwd.get("x-api-key")).toBe("browser-site-key"); // the browser's own header survives
    expect([...fwd.keys()].some((k) => k.startsWith("x-bishop-"))).toBe(false);
  });

  // ── Probe 8: ★ the browser's request replayed (W38-S1283 (4)) ────────────
  it("★ replay: the browser's method, headers and body reach the site; a GET carries no body; redirect manual", async () => {
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));

    const post = await handleBrowserEgress(
      browserReq({ method: "POST", body: "a=1&b=2", browserHeaders: {
        "content-type": "application/x-www-form-urlencoded", cookie: "s=1; t=2", "user-agent": "Mozilla/5.0 Chromium",
      } }),
      makeEnv(),
      makeCtx(),
    );
    expect(post.status).toBe(200);
    expect(captures[0].method).toBe("POST");
    expect(captures[0].body).toBe("a=1&b=2");
    expect(captures[0].redirect).toBe("manual");
    expect(captures[0].headers.get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(captures[0].headers.get("cookie")).toBe("s=1; t=2");
    expect(captures[0].headers.get("user-agent")).toBe("Mozilla/5.0 Chromium");

    const get = await handleBrowserEgress(browserReq({ method: "get", body: "ignored" }), makeEnv(), makeCtx());
    expect(get.status).toBe(200);
    expect(captures[1].method).toBe("GET");
    expect(captures[1].body).toBeNull();
  });

  it("★ hop method: a hop made with the browser's own method is replayed by the field, as a POST hop is", async () => {
    // The egress clerk's hop carries the browser's method since the architect window's ruling of 2026-11-06, so that a
    // route forwarding the hop's own method (main's, before this branch) sends the site the browser's; this route
    // reads X-Bishop-Egress-Method, whatever the hop's.
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    const cases: [string, string | undefined][] = [
      ["GET", undefined], ["HEAD", undefined], ["DELETE", undefined], ["OPTIONS", undefined],
      ["POST", "a=1"], ["PUT", "a=1"], ["PATCH", "a=1"],
    ];
    for (const [method, body] of cases) {
      const resp = await handleBrowserEgress(browserReq({ method, hopMethod: method, body }), makeEnv(), makeCtx());
      expect(resp.status).toBe(200);
      const sent = captures[captures.length - 1];
      expect(sent.method).toBe(method);
      expect(sent.body).toBe(body ?? null);
    }
    expect(captures).toHaveLength(cases.length);
  });

  // ── Probe 9: ★ method-invalid ──────────────────────────────────────────────
  it("★ method-invalid: a missing method, CONNECT or TRACE → 400 browser_egress_method_invalid, NO forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    for (const method of [null, "", "CONNECT", "TRACE", "BREW"]) {
      const resp = await handleBrowserEgress(browserReq({ method }), makeEnv(), makeCtx());
      expect(resp.status, `${method} must be 400`).toBe(400);
      expect(((await resp.json()) as { error: string }).error).toBe("browser_egress_method_invalid");
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 10: ★ the answer's headers ─────────────────────────────────────
  it("★ answer: a 3xx comes back with Location and each Set-Cookie in the one list, less hop-by-hop and encoding headers", async () => {
    installFetch(() => {
      const h = new Headers({ location: "https://example.com/next", connection: "keep-alive",
        "content-encoding": "gzip", "cache-control": "no-store", "content-type": "text/html" });
      h.append("set-cookie", "a=1; Path=/");
      h.append("set-cookie", "b=2; Path=/; HttpOnly");
      return new Response(null, { status: 302, headers: h });
    });

    const resp = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
    expect(resp.status).toBe(302);
    expect(mockFetch).toHaveBeenCalledOnce(); // returned to the browser, not followed
    expect(answerList(resp)).toEqual([
      ["cache-control", "no-store"], ["content-type", "text/html"], ["location", "https://example.com/next"],
      ["set-cookie", "a=1; Path=/"], ["set-cookie", "b=2; Path=/; HttpOnly"],
    ]);
    // The site's headers travel only in the list: none on this answer itself, to which the edge adds its own.
    expect([...resp.headers.keys()]).toEqual(["x-bishop-browser-answer-headers"]);
  });

  // ── Probe 11: ★ a TLS failure reaching the site (W38-S1283) ────────────────
  it("★ tls: a 525 or 526 answer to the forward → 502 upstream_tls_failed, naming Cloudflare's status", async () => {
    const statuses = [526, 525];
    installFetch((call) =>
      new Response("<html>an error page</html>", { status: statuses[call], headers: { "content-type": "text/html" } }),
    );
    for (const status of statuses) {
      const resp = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
      expect(resp.status, `${status} must become 502`).toBe(502);
      expect(await resp.json()).toEqual({
        error: "upstream_tls_failed", message: "the site's TLS connection failed", upstream_status: status,
      });
    }
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  // ── Probe 12: ★ a forward that throws ─────────────────────────────────────
  it("★ fetch-failed: a forward that throws → 502 upstream_fetch_failed, naming no cause and none of the runtime's text", async () => {
    installFetch(() => {
      throw new Error("internal error; reference = 4u69l3nkp73o8c2srrqapjpo"); // workerd's, measured 2026-11-06
    });
    const resp = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
    expect(resp.status).toBe(502);
    const text = await resp.text();
    expect(JSON.parse(text)).toEqual({ error: "upstream_fetch_failed", message: "the site could not be reached" });
    expect(text).not.toMatch(/internal error|reference|4u69l3nk/);
  });

  // ── Probe 13: ★ every other answer is the site's ──────────────────────────
  it("★ other answers: a site's 503 passes back unchanged, and a 200 (the control)", async () => {
    const answers = [
      () => new Response("down for maintenance", { status: 503, headers: { "retry-after": "120" } }),
      () => new Response("fine", { status: 200, headers: { "content-type": "text/plain" } }),
    ];
    installFetch((call) => answers[call]());
    const down = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
    expect(down.status).toBe(503);
    expect(await down.text()).toBe("down for maintenance");
    expect(answerList(down)).toContainEqual(["retry-after", "120"]);
    const fine = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
    expect(fine.status).toBe(200);
    expect(await fine.text()).toBe("fine");
  });

  // ── Probe 14: ★ the route's own fault is not the site's ───────────────────
  it("★ own fault: a fault before the forward (a request body already read) surfaces as itself, not as upstream_fetch_failed", async () => {
    installFetch(() => new Response("never", { status: 200 }));
    const req = browserReq({ method: "POST", body: "a=1" });
    await req.arrayBuffer(); // the body is spent, so the route's own read of it fails
    await expect(handleBrowserEgress(req, makeEnv(), makeCtx())).rejects.toThrow();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 15: ★ the list's caps (the daemon's) ───────────────────────────
  it("★ list caps: over 128 headers, a value over 16384 or a list over 60 KiB → 502 upstream_headers_too_large", async () => {
    const many = new Headers();
    for (let i = 0; i < 129; i++) many.append(`x-h${i}`, "v");
    const long = new Headers({ "x-long": "v".repeat(16385) });
    const wide = new Headers();
    for (let i = 0; i < 8; i++) wide.append(`x-w${i}`, "w".repeat(8000));
    const atCaps = new Headers({ "x-long": "v".repeat(16384) });
    for (let i = 0; i < 126; i++) atCaps.append(`x-h${i}`, "v"); // with the string body's own Content-Type: 128
    const answers = [many, long, wide, atCaps];
    installFetch((call) => new Response("x", { status: 200, headers: answers[call] }));
    for (const label of ["129 headers", "a 16385-byte value", "a list over 60 KiB"]) {
      const resp = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
      expect(resp.status, label).toBe(502);
      expect(((await resp.json()) as { error: string }).error, label).toBe("upstream_headers_too_large");
    }
    const control = await handleBrowserEgress(browserReq(), makeEnv(), makeCtx());
    expect(control.status).toBe(200);
    expect(answerList(control)).toHaveLength(128); // at the caps: 128 headers, one value of 16384
  });

  // ── Probe 16: ★ the proxy's own answers carry no list ─────────────────────
  it("★ own answers: a forward-failure 502, a 401 and a 400 carry no list", async () => {
    installFetch(() => new Response(null, { status: 526 }));
    const answers = [
      await handleBrowserEgress(browserReq(), makeEnv(), makeCtx()),
      await handleBrowserEgress(browserReq({ bearer: null }), makeEnv(), makeCtx()),
      await handleBrowserEgress(browserReq({ method: "TRACE" }), makeEnv(), makeCtx()),
    ];
    expect(answers.map((r) => r.status)).toEqual([502, 401, 400]);
    for (const r of answers) expect(r.headers.get("x-bishop-browser-answer-headers")).toBeNull();
  });

  // ── Probe 6: ★ host-observed, body-never-logged (§3.3) ───────────────────
  it("★ host-observed-body-never-logged: forward reaches the observed host; the log carries no body", async () => {
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const SECRET_BODY = "secret-form-field=user-private-content-xyz";
    const resp = await handleBrowserEgress(
      browserReq({ body: SECRET_BODY }),
      makeEnv(),
      makeCtx(),
    );
    expect(resp.status).toBe(200);
    // Host OBSERVED — the proxy forwarded to the request-determined host.
    expect(new URL(captures[0].url).hostname).toBe(PUBLIC_HOST);

    // BODY NEVER LOGGED — every emitted log line is a metadata-only ProxyLogEvent
    // (its allowlist has no body/prompt/header field), and the secret body text
    // appears in NO log line.
    const logged = logSpy.mock.calls.map((c) => String(c[0]));
    expect(logged.length).toBeGreaterThan(0);
    for (const line of logged) {
      const evt = JSON.parse(line);
      expect(isProxyLogEvent(evt), `log line must be a valid ProxyLogEvent: ${line}`).toBe(true);
      expect(line).not.toContain("secret-form-field");
      expect(line).not.toContain("user-private-content");
    }
    logSpy.mockRestore();
  });

  // ── Probe 7: quota passthrough ───────────────────────────────────────────
  it("quota: a quota /check 429 → 429 quota_exceeded passthrough; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const resp = await handleBrowserEgress(browserReq(), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(resp.status).toBe(429);
    expect(((await resp.json()) as { error: string }).error).toBe("quota_exceeded");
    expect(resp.headers.get("X-Bishop-Cap-Type")).toBe("monthly_tasks");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
