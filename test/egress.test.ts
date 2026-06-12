/**
 * Behavioral probes for the W38-S822 (S5b-1) generic allowlist-gated forward
 * egress leg (POST /v1/egress).
 *
 * The §3.2 channel a worker-microVM reaches the outside world through: the target
 * is request-supplied (X-Bishop-Egress-Target), but the forward is leashed to the
 * frozen ALLOWED_OUTBOUND_HOSTS allowlist. Every probe installs the REAL
 * installFetchAllowlist() interceptor over a stubbed global fetch, so the
 * allowlist auto-gate is exercised genuinely — an allowlisted host reaches the
 * (mocked) upstream; a non-allowlisted host is rejected by the interceptor and
 * the handler maps it to a clean 403 that never leaks the allowlist.
 *
 *   (1) ★ allowlisted-forward — a target on the frozen list → 200, forwarded to
 *       EXACTLY that host; the upstream response is streamed back.
 *   (2) ★ non-allowlisted-403 — an off-allowlist target → 403 egress_host_not_allowed
 *       (the allowlist auto-rejects; the prior/real fetch is NEVER reached; the
 *       response body does not leak the allowlist).
 *   (3) ★ bad-target-400 — missing / unparseable / non-http(s) X-Bishop-Egress-Target
 *       → 400, NO forward.
 *   (4) ★ bad-token-401 — missing bearer → 401 missing_bearer; invalid token →
 *       401 token_not_found; NO forward.
 *   (5) ★ header-strip — the daemon Bearer + ALL X-Bishop-* control headers are
 *       stripped before forwarding; a non-Bishop header survives byte-for-byte.
 *   (6) quota — a quota /check 429 → 429 quota_exceeded passthrough; NO forward.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleEgress } from "../src/routes/egress";
import {
  installFetchAllowlist,
  _resetForTesting,
} from "../src/lib/outbound-allowlist";
import type { Env } from "../src/index";

// ── constants ──────────────────────────────────────────────────────────────

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
// api.perplexity.ai is already on the frozen ALLOWED_OUTBOUND_HOSTS (no host-add).
const ALLOWED_TARGET = "https://api.perplexity.ai/v1/search?q=bishop";
const ALLOWED_HOST = "api.perplexity.ai";
const BLOCKED_TARGET = "https://evil-cdn.attacker.example/exfil";

// ── DO stubs (mirror the unit-style env helpers in model-registry.test.ts) ──

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
    client_version: "test-egress-0.1.0",
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

function egressReq(opts: {
  target?: string | null;
  bearer?: string | null;
  extraHeaders?: Record<string, string>;
  body?: string;
} = {}): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  const target = opts.target === undefined ? ALLOWED_TARGET : opts.target;
  if (target !== null) headers["x-bishop-egress-target"] = target;
  Object.assign(headers, opts.extraHeaders ?? {});
  return new Request("http://proxy/v1/egress", {
    method: "POST",
    headers,
    body: opts.body ?? JSON.stringify({ q: "opaque-pass-through" }),
  });
}

// ── fetch-stub + real-interceptor plumbing ──────────────────────────────────

interface Capture {
  url: string;
  headers: Headers;
}

describe("S5b-1 generic egress leg (POST /v1/egress)", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  // Stub the global fetch with a deterministic responder, THEN install the REAL
  // allowlist interceptor over it. After install, global fetch = interceptor →
  // (for allowlisted hosts) the mock; an off-allowlist host is rejected by the
  // interceptor with OutboundHostNotAllowed and the mock is never reached.
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

  // ── Probe 1: ★ allowlisted-forward ──────────────────────────────────────
  it("★ allowlisted-forward: a frozen-list target → 200, forwarded to EXACTLY that host", async () => {
    installFetch(() =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const resp = await handleEgress(egressReq(), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();

    const u = new URL(captures[0].url);
    expect(u.hostname).toBe(ALLOWED_HOST);
    expect(u.pathname).toBe("/v1/search");
    expect(u.search).toBe("?q=bishop");
    expect(resp.headers.get("content-type")).toContain("application/json");
  });

  // ── Probe 2: ★ non-allowlisted-403 ──────────────────────────────────────
  it("★ non-allowlisted-403: an off-allowlist target → 403, prior fetch NEVER reached, no leak", async () => {
    installFetch(() => new Response("LEAKED", { status: 200 }));

    const resp = await handleEgress(egressReq({ target: BLOCKED_TARGET }), makeEnv(), makeCtx());
    expect(resp.status).toBe(403);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe("egress_host_not_allowed");
    // The error never leaks the allowlist contents (no host names in the body).
    expect(JSON.stringify(body)).not.toContain("anthropic");
    expect(JSON.stringify(body)).not.toContain(ALLOWED_HOST);
    // The interceptor rejected before the real/mock fetch ran.
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 3: ★ bad-target-400 ───────────────────────────────────────────
  it("★ bad-target-400: missing / unparseable / non-http(s) target → 400, no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const missing = await handleEgress(egressReq({ target: null }), makeEnv(), makeCtx());
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as { error: string }).error).toBe("egress_target_missing");

    for (const bad of ["not a url", "file:///etc/passwd", "ftp://host/x", "://broken"]) {
      const resp = await handleEgress(egressReq({ target: bad }), makeEnv(), makeCtx());
      expect(resp.status).toBe(400);
      expect(((await resp.json()) as { error: string }).error).toBe("egress_target_invalid");
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 4: ★ bad-token-401 ────────────────────────────────────────────
  it("★ bad-token-401: missing bearer → 401 missing_bearer; invalid token → 401 token_not_found; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const noBearer = await handleEgress(egressReq({ bearer: null }), makeEnv(), makeCtx());
    expect(noBearer.status).toBe(401);
    expect(((await noBearer.json()) as { error: string }).error).toBe("missing_bearer");

    const badToken = await handleEgress(
      egressReq({ bearer: "z".repeat(40) }),
      makeEnv({ authValid: false }),
      makeCtx(),
    );
    expect(badToken.status).toBe(401);
    expect(((await badToken.json()) as { error: string }).error).toBe("token_not_found");

    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 5: ★ header-strip ─────────────────────────────────────────────
  it("★ header-strip: daemon Bearer + ALL X-Bishop-* stripped; non-Bishop header survives", async () => {
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));

    const resp = await handleEgress(
      egressReq({
        extraHeaders: {
          "x-bishop-egress-target": ALLOWED_TARGET, // control header — must be stripped
          "x-bishop-run-id": "run-123", // any control header — must be stripped
          "x-api-key": "worker-upstream-secret", // non-Bishop — must survive
        },
      }),
      makeEnv(),
      makeCtx(),
    );
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();

    const fwd = captures[0].headers;
    // Bishop daemon Bearer is NEVER forwarded upstream (Pillar 1).
    expect(fwd.get("authorization")).toBeNull();
    // Every X-Bishop-* control header is stripped (incl. the egress target).
    expect(fwd.get("x-bishop-egress-target")).toBeNull();
    expect(fwd.get("x-bishop-run-id")).toBeNull();
    // A non-Bishop header (the worker's own upstream auth) passes through.
    expect(fwd.get("x-api-key")).toBe("worker-upstream-secret");
  });

  // ── Probe 6: quota passthrough ──────────────────────────────────────────
  it("quota: a quota /check 429 → 429 quota_exceeded passthrough; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const resp = await handleEgress(egressReq(), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(resp.status).toBe(429);
    expect(((await resp.json()) as { error: string }).error).toBe("quota_exceeded");
    expect(resp.headers.get("X-Bishop-Cap-Type")).toBe("monthly_tasks");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
