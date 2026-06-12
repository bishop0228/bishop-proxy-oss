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
  extraHeaders?: Record<string, string>;
  body?: string;
} = {}): Request {
  const headers: Record<string, string> = { "content-type": "application/octet-stream" };
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  const target = opts.target === undefined ? PUBLIC_TARGET : opts.target;
  if (target !== null) headers["x-bishop-browser-target"] = target;
  Object.assign(headers, opts.extraHeaders ?? {});
  return new Request("http://proxy/browser-egress", {
    method: "POST",
    headers,
    body: opts.body ?? "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
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

interface Capture {
  url: string;
  headers: Headers;
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
      captures.push({ url, headers });
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
    expect(resp.headers.get("content-type")).toContain("application/json");
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
  it("★ header-strip: daemon Bearer + ALL X-Bishop-* (incl. target) stripped; non-Bishop survives", async () => {
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));

    const resp = await handleBrowserEgress(
      browserReq({
        extraHeaders: {
          "x-bishop-run-id": "run-123", // control header — must be stripped
          "x-api-key": "worker-upstream-secret", // non-Bishop — must survive
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
    expect(fwd.get("x-bishop-run-id")).toBeNull();
    expect(fwd.get("x-api-key")).toBe("worker-upstream-secret"); // worker's own upstream auth survives
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
