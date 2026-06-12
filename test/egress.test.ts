/**
 * Behavioral probes for the W38-S822-FIX (S5b-1) server_id-keyed generic forward
 * egress leg (POST /egress/<server_id>).
 *
 * §3.2-aligned: the upstream host is derived SERVER-SIDE from the frozen
 * CLASS_B_EGRESS_SPECS entry keyed by <server_id> — NEVER from the request, the
 * W9.7 /mcp/<server_id> SSRF-safe discipline. A worker names only the server_id
 * (the path); it can reach ONLY that server_id's own spec host. Every probe
 * installs the REAL installFetchAllowlist() interceptor over a stubbed global
 * fetch, so the allowlist auto-gate is exercised genuinely.
 *
 *   (1) ★ known-server forwards to spec.host — a known fixed-host server_id → 200,
 *       forwarded to EXACTLY spec.host (api.perplexity.ai), NOT anything supplied.
 *   (2) ★ unknown-server-404 — an unknown server_id → 404, NO forward (the
 *       fast-fail happens before any fetch — no retry-budget delay).
 *   (3) ★ per-account match/mismatch — a per-account spec with a matching
 *       X-Bishop-Upstream-Host forwards to that host; a non-matching one →
 *       fail-closed 400, NO forward; a missing one → 400, NO forward.
 *   (4) ★ egress-target-IGNORED — an X-Bishop-Egress-Target header is IGNORED;
 *       the host still comes from the spec (the regression guard for this fix).
 *   (5) ★ bad-token-401 — missing bearer → 401 missing_bearer; invalid token →
 *       401 token_not_found; NO forward.
 *   (6) ★ header-strip — the daemon Bearer + ALL X-Bishop-* control headers are
 *       stripped before forwarding; a non-Bishop header survives byte-for-byte.
 *   (7) quota — a quota /check 429 → 429 quota_exceeded passthrough; NO forward.
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
// The "test-fixed" CLASS_B_EGRESS_SPECS entry pins api.perplexity.ai (already on
// the frozen ALLOWED_OUTBOUND_HOSTS — no host-add).
const FIXED_SERVER = "test-fixed";
const FIXED_HOST = "api.perplexity.ai";
// The "test-peraccount" entry validates X-Bishop-Upstream-Host vs the snowflake
// anchored pattern (an ENTERPRISE_HOST_PATTERNS conjunct — the fetch backstop
// admits a matching host).
const PERACCOUNT_SERVER = "test-peraccount";
const PERACCOUNT_MATCH_HOST = "acme-bishop.snowflakecomputing.com";
const PERACCOUNT_MISMATCH_HOST = "evil-cdn.attacker.example";

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
  serverId?: string;
  path?: string;
  bearer?: string | null;
  extraHeaders?: Record<string, string>;
  body?: string;
} = {}): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  Object.assign(headers, opts.extraHeaders ?? {});
  const serverId = opts.serverId ?? FIXED_SERVER;
  const path = opts.path ?? "search?q=bishop";
  return new Request(`http://proxy/egress/${serverId}/${path}`, {
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

describe("S5b-1 server_id-keyed egress leg (POST /egress/<server_id>)", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  // Stub the global fetch with a deterministic responder, THEN install the REAL
  // allowlist interceptor over it. After install, global fetch = interceptor →
  // (for allowed hosts) the mock; an off-allowlist host is rejected by the
  // interceptor and the mock is never reached.
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

  // ── Probe 1: ★ known-server forwards to spec.host ───────────────────────
  it("★ known-server: a fixed-host server_id → 200, forwarded to EXACTLY spec.host", async () => {
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
    // The host is the SPEC's (api.perplexity.ai) — server-side, not request-named.
    expect(u.hostname).toBe(FIXED_HOST);
    // pathPrefix "/v1/" + the remaining path segment + query preserved.
    expect(u.pathname).toBe("/v1/search");
    expect(u.search).toBe("?q=bishop");
    expect(resp.headers.get("content-type")).toContain("application/json");
  });

  // ── Probe 2: ★ unknown-server-404 ───────────────────────────────────────
  it("★ unknown-server-404: an unknown server_id → 404, NO forward (fast-fail before any fetch)", async () => {
    installFetch(() => new Response("LEAKED", { status: 200 }));

    const resp = await handleEgress(egressReq({ serverId: "no-such-server" }), makeEnv(), makeCtx());
    expect(resp.status).toBe(404);
    expect(((await resp.json()) as { error: string }).error).toBe("unknown_egress_server");
    // No fetch attempted at all — the 404 happens before fetchWithRetry.
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 3: ★ per-account match / mismatch / missing ───────────────────
  it("★ per-account: a matching X-Bishop-Upstream-Host forwards; mismatch + missing fail-closed (no forward)", async () => {
    installFetch(() =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    // (a) matching host → forwarded to EXACTLY that daemon-supplied host.
    const match = await handleEgress(
      egressReq({
        serverId: PERACCOUNT_SERVER,
        path: "mcp-servers/x",
        extraHeaders: { "x-bishop-upstream-host": PERACCOUNT_MATCH_HOST },
      }),
      makeEnv(),
      makeCtx(),
    );
    expect(match.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();
    expect(new URL(captures[0].url).hostname).toBe(PERACCOUNT_MATCH_HOST);

    // (b) mismatching host → 400 fail-closed, NO forward.
    const mismatch = await handleEgress(
      egressReq({
        serverId: PERACCOUNT_SERVER,
        path: "mcp-servers/x",
        extraHeaders: { "x-bishop-upstream-host": PERACCOUNT_MISMATCH_HOST },
      }),
      makeEnv(),
      makeCtx(),
    );
    expect(mismatch.status).toBe(400);
    expect(((await mismatch.json()) as { error: string }).error).toBe("egress_host_not_allowed");

    // (c) missing host → 400 fail-closed, NO forward.
    const missing = await handleEgress(
      egressReq({ serverId: PERACCOUNT_SERVER, path: "mcp-servers/x" }),
      makeEnv(),
      makeCtx(),
    );
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as { error: string }).error).toBe("egress_upstream_host_missing");

    // Only the matching call ever forwarded.
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  // ── Probe 4: ★ egress-target-IGNORED (regression guard for this fix) ─────
  it("★ egress-target-IGNORED: an X-Bishop-Egress-Target header does NOT redirect the host", async () => {
    installFetch(() =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const resp = await handleEgress(
      egressReq({
        // The OLD host-from-request source — must be entirely ignored now.
        extraHeaders: { "x-bishop-egress-target": "https://evil-cdn.attacker.example/exfil" },
      }),
      makeEnv(),
      makeCtx(),
    );
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();
    // The host is STILL the spec's — the attacker-supplied target was ignored.
    expect(new URL(captures[0].url).hostname).toBe(FIXED_HOST);
    expect(new URL(captures[0].url).hostname).not.toBe("evil-cdn.attacker.example");
  });

  // ── Probe 5: ★ bad-token-401 ────────────────────────────────────────────
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

  // ── Probe 6: ★ header-strip ─────────────────────────────────────────────
  it("★ header-strip: daemon Bearer + ALL X-Bishop-* stripped; non-Bishop header survives", async () => {
    installFetch(() => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));

    const resp = await handleEgress(
      egressReq({
        extraHeaders: {
          "x-bishop-upstream-host": "ignored-on-fixed-host.example", // control header — must be stripped
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
    // Every X-Bishop-* control header is stripped.
    expect(fwd.get("x-bishop-upstream-host")).toBeNull();
    expect(fwd.get("x-bishop-run-id")).toBeNull();
    // A non-Bishop header (the worker's own upstream auth) passes through.
    expect(fwd.get("x-api-key")).toBe("worker-upstream-secret");
    // The host is still the spec's (the x-bishop-upstream-host is ignored on a
    // fixed-host spec — it is only consulted for hostFromUpstream specs).
    expect(new URL(captures[0].url).hostname).toBe(FIXED_HOST);
  });

  // ── Probe 7: quota passthrough ──────────────────────────────────────────
  it("quota: a quota /check 429 → 429 quota_exceeded passthrough; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const resp = await handleEgress(egressReq(), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(resp.status).toBe(429);
    expect(((await resp.json()) as { error: string }).error).toBe("quota_exceeded");
    expect(resp.headers.get("X-Bishop-Cap-Type")).toBe("monthly_tasks");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
