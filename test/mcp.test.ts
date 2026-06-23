/**
 * Behavioral probes for §1.18.15 MCP-forward egress leg (/mcp/<server_id>).
 *
 * The §3.2 operational-egress path. 8 probes (real unstable_dev worker except
 * the unit-style Pillar-1 leg):
 *   (1) ★ forward happy path — rebuilt upstream Bearer reaches the mock; the
 *       x-bishop-upstream-key header is STRIPPED (Pillar 1 identifier-strip).
 *   (2) ★ SSRF — unknown server_id → 404 unknown_mcp_server; mock NOT hit
 *       (no request-derived host; the only forward host is the frozen spec).
 *   (3) ★ auth — no Bearer → 401; invalid token → 401 token_not_found; mock NOT hit.
 *   (4) ★ Pillar-1 — no logEvent contains the upstream key or the daemon bearer.
 *   (5) missing x-bishop-upstream-key → 400 mcp_upstream_key_missing; mock NOT hit.
 *   (6) ★ SSE passthrough — ?sse=1 → text/event-stream streamed straight back.
 *   (7) allowlist length UNCHANGED (no runtime widen — §3.2 sentinel) + host present.
 *   (8) SSRF unit — spec.host is server-side/frozen and ∈ ALLOWED_OUTBOUND_HOSTS.
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { clearAuthRateLimits } from "./helpers/clear-auth-rate-limits";
import { ALLOWED_OUTBOUND_HOSTS } from "../src/lib/outbound-allowlist";
import { MCP_SERVER_SPECS } from "../src/lib/mcp-specs";
import { handleMcp } from "../src/routes/mcp";
import { isProxyLogEvent } from "../src/lib/log";
import type { Env } from "../src/index";

// ── constants ──────────────────────────────────────────────────────────────

const PROXY_VARS_BASE = {
  STRIPE_WEBHOOK_SECRET: "test_secret",
  ANTHROPIC_API_KEY: "test_key",
  TARGET_ZERO_BITS: "8",
  TARGET_MEMORY_KIB: "8",
  CHALLENGE_TTL: "60",
  MOCK_AI: "1",
};

// GitHub Copilot per-server token forwarded as x-bishop-upstream-key.
const UPSTREAM_KEY = "gho_mock-copilot-token-value";

const TEST_BODY = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "create_issue", arguments: { title: "hi" } },
});

// ── PoW + enroll helpers (mirrors vertex.test.ts) ──────────────────────────

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function countLeadingZeroBits(bytes: Uint8Array): number {
  let count = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      count += 8;
    } else {
      count += Math.clz32(byte) - 24;
      break;
    }
  }
  return count;
}

function solvePow(fingerprintHash: string, nonce: string, targetBits: number, memKib: number): string {
  const fpBytes = fromHex(fingerprintHash);
  const nonceBytes = fromHex(nonce);
  const salt = new Uint8Array(24);
  salt.set(nonceBytes, 0);
  for (let i = 0; i < 0xffffffff; i++) {
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, BigInt(i), false);
    salt.set(counterBytes, 16);
    const hash = argon2id(fpBytes, salt, { t: 1, m: memKib, p: 1, dkLen: 32 });
    if (countLeadingZeroBits(hash) >= targetBits) {
      return toHex(counterBytes);
    }
  }
  throw new Error("No solution found");
}

async function enroll(worker: Unstable_DevWorker, fp: string): Promise<string> {
  const challengeRes = await worker.fetch("/v1/challenge");
  if (challengeRes.status !== 200) throw new Error(`challenge failed: ${challengeRes.status}`);
  const cBody = (await challengeRes.json()) as { nonce?: string };
  if (!cBody.nonce) throw new Error(`challenge no nonce: ${JSON.stringify(cBody)}`);
  const counter = solvePow(fp, cBody.nonce, 8, 8);
  const enrollRes = await worker.fetch("/v1/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce: cBody.nonce,
      counter,
      fingerprint_hash: fp,
      client_version: "test-mcp-0.1.0",
    }),
  });
  expect([200, 201]).toContain(enrollRes.status);
  const rec = (await enrollRes.json()) as { token: string };
  return rec.token;
}

// ── Unit-style env helpers (for the Pillar-1 leg) ──────────────────────────

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

function makeAuthNamespace() {
  const record = {
    token: "bsk_staging_" + "v".repeat(24),
    token_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-mcp-0.1.0",
    account_mode: "managed" as const,
  };
  return makeNamespace(async () =>
    new Response(JSON.stringify({ valid: true, record, reason: null }), {
      headers: { "content-type": "application/json" },
    }),
  );
}

function makeTierNamespace() {
  return makeNamespace(async () =>
    new Response(JSON.stringify({ tier: "free" }), { headers: { "content-type": "application/json" } }),
  );
}

function makeQuotaNamespace() {
  return makeNamespace(async () =>
    new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }),
  );
}

function makeAllowEnv(): Env {
  return {
    AUTH_STORE: makeAuthNamespace(),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
    MCP_GITHUB_BASE_URL: "https://api.githubcopilot.com",
  } as unknown as Env;
}

// ── describe ───────────────────────────────────────────────────────────────

describe("MCP-forward egress leg (/mcp/<server_id>)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let token: string;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-mcp-upstream.ts", {
      config: "test/wrangler.mock.toml",
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      persist: false,
    });
    mockUrl = `http://${mock.address}:${mock.port}`;

    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: {
        ...PROXY_VARS_BASE,
        ADMIN_TOKEN: "test_admin",
        USER_INDEX_HMAC_KEY: "test_hmac_key",
        MCP_GITHUB_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
      },
      persist: false,
    });

    // Self-isolate against the serial suite's shared on-disk AuthStoreDO:
    // clear BOTH the challenge nonce + enroll rate-limit counters.
    await clearAuthRateLimits(worker);

    // Distinct fingerprint pattern (single-hex slots reserved across other suites).
    token = await enroll(worker, "1a".repeat(32));
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  // ── Probe 1: ★ forward happy path + upstream-key strip ────────────────

  it("★ forward: rebuilt upstream Bearer reaches upstream; x-bishop-upstream-key STRIPPED", async () => {
    const res = await worker.fetch("/mcp/github", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(200);

    // Upstream saw the rebuilt Bearer (= the per-server key), NOT the daemon token.
    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBe(`Bearer ${UPSTREAM_KEY}`);
    expect(auth).not.toContain(token);

    // x-bishop-upstream-key is a client identifier — it MUST be stripped.
    const keyResp = await mock.fetch(mockUrl + "/__last_upstream_key");
    const { upstreamKey } = (await keyResp.json()) as { upstreamKey: string | null };
    expect(upstreamKey).toBeNull();
  }, 30000);

  // ── Probe 2: ★ SSRF — unknown server_id → 404; mock NOT hit ───────────

  it("★ SSRF: unknown server_id → 404 unknown_mcp_server; no forward", async () => {
    const res = await worker.fetch("/mcp/evilserver", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unknown_mcp_server");

    // Mock must NOT have been called (no request-derived host to forward to).
    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 3: ★ auth — no bearer / invalid token → 401; mock NOT hit ───

  it("★ auth: missing bearer → 401; invalid token → 401; no forward", async () => {
    const noBearer = await worker.fetch("/mcp/github", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bishop-upstream-key": UPSTREAM_KEY },
      body: TEST_BODY,
    });
    expect(noBearer.status).toBe(401);

    const badToken = await worker.fetch("/mcp/github", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${"z".repeat(40)}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(badToken.status).toBe(401);
    const b = (await badToken.json()) as { error: string };
    expect(b.error).toBe("token_not_found");

    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 4: ★ Pillar-1 — no logEvent contains the key or daemon bearer ─

  it("★ Pillar-1: no logEvent contains the upstream key or daemon bearer (unit-style)", async () => {
    const daemonBearer = "bsk_staging_" + "v".repeat(24);
    const mockFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    try {
      const req = new Request("http://proxy/mcp/github", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${daemonBearer}`,
          "x-bishop-upstream-key": UPSTREAM_KEY,
        },
        body: TEST_BODY,
      });
      const resp = await handleMcp(req, makeAllowEnv(), makeCtx());
      expect(resp.status).toBe(200);

      for (const call of logSpy.mock.calls) {
        const line = String(call[0]);
        expect(line).not.toContain(UPSTREAM_KEY);
        expect(line).not.toContain(daemonBearer);
      }
      expect(logSpy.mock.calls.length).toBeGreaterThan(0);
      const allValid = logSpy.mock.calls.every((call) => {
        try {
          return isProxyLogEvent(JSON.parse(String(call[0])));
        } catch {
          return false;
        }
      });
      expect(allValid).toBe(true);
    } finally {
      logSpy.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  // ── Probe 5: missing x-bishop-upstream-key → 400; mock NOT hit ────────

  it("missing x-bishop-upstream-key → 400 mcp_upstream_key_missing; no forward", async () => {
    const res = await worker.fetch("/mcp/github", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
        // x-bishop-upstream-key intentionally absent
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(400);
    const b = (await res.json()) as { error: string };
    expect(b.error).toBe("mcp_upstream_key_missing");

    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 6: ★ SSE passthrough — ?sse=1 streamed straight back ────────

  it("★ SSE: text/event-stream reply is passed straight through", async () => {
    const res = await worker.fetch("/mcp/github?sse=1", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const text = await res.text();
    expect(text).toContain("data:");
    expect(text).toContain("mock-mcp-ok");
  }, 30000);

  // ── Probe 7: allowlist length sentinel (§3.2 no-runtime-widen) ───────

  it("ALLOWED_OUTBOUND_HOSTS length === 90 + github host already present", () => {
    // §1.18.15 itself added NO host (api.githubcopilot.com was already present
    // for the §1.17.16 GitHub Copilot OAuth leg; the MCP leg reuses it).
    // W38-S731 Block 4 added the 49 verified MCP egress hosts (32→81); W38-S734
    // then unwired 7 → native-covered (81→74); W38-S736 added 2 fixed-host
    // (agent365.svc.cloud.microsoft + api.salesforce.com) → 76; B1 added 1
    // model-registry host (registry.ollama.ai) → 77; W38-S831 S6b added 3
    // worker-egress fixed hosts (people.googleapis.com / api.xero.com /
    // quickbooks.api.intuit.com) → 80; W38-S868 §9.3.8c added 1 governed
    // HuggingFace BYO-model host (huggingface.co) → 81; W38-S964 added 1 BYOK
    // completion upstream (api.sakana.ai) → 82; W38-S966 added 7 OpenAI-compat
    // BYOK completion upstreams → 89; W38-S968 added 1 (api.novita.ai) → 90.
    // Still no runtime widen.
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(90);
    expect((ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes("api.githubcopilot.com")).toBe(true);
  });

  // ── Probe 8: SSRF unit — spec.host frozen, server-side, ∈ allowlist ───

  it("SSRF unit: github spec.host is frozen, server-side, and ∈ ALLOWED_OUTBOUND_HOSTS", () => {
    const spec = MCP_SERVER_SPECS["github"];
    expect(spec).toBeDefined();
    expect(spec.host).toBe("api.githubcopilot.com");
    // The map is frozen — a request can never mutate or inject a host.
    expect(Object.isFrozen(MCP_SERVER_SPECS)).toBe(true);
    expect((ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(spec.host as string)).toBe(true);
    // Unknown server_id has no spec → handler refuses (probe 2) — no host fallback.
    expect(MCP_SERVER_SPECS["evilserver"]).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// W38-S731 Block 4 — every wired MCP spec is host-allowlisted + SSRF-safe.
//
// Data-driven invariant over ALL MCP_SERVER_SPECS (github + the 42). This is
// the durable, committed half of the §5 ultracode spec-audit: no spec may carry
// a host outside ALLOWED_OUTBOUND_HOSTS (the route step-3 backstop would 500),
// and every host is a single static DNS host (no SSRF / per-tenant template).
// W38-S734 unwired 7 (granola/fireflies/fathom + zapier/make/ifttt/workato) → 43.
// ─────────────────────────────────────────────────────────────────────────────

describe("W38-S731 Block 4 — MCP specs wired + allowlisted (50: 46 fixed + 4 per-account)", () => {
  const allow = new Set<string>(ALLOWED_OUTBOUND_HOSTS as readonly string[]);
  const entries = Object.entries(MCP_SERVER_SPECS);
  const fixedEntries = entries.filter(([, s]) => !s.hostFromUpstream);
  const perAccountEntries = entries.filter(([, s]) => s.hostFromUpstream);

  it("MCP_SERVER_SPECS has 50 entries (46 fixed-host + 4 per-account) and is frozen", () => {
    expect(entries.length).toBe(50);
    expect(fixedEntries.length).toBe(46);   // github + 42 Block-4 + 3 W38-S736 fixed-host
    expect(perAccountEntries.length).toBe(4); // W38-S735 snowflake/netsuite/databricks/shopify
    expect(Object.isFrozen(MCP_SERVER_SPECS)).toBe(true);
  });

  it("the 3 formerly-deferred servers are now wired fixed-host (W38-S736)", () => {
    // W38-S736 wired the last 3 "templated" servers as FIXED-host: salesforce on
    // api.salesforce.com (no tenant path); microsoft-365 + onedrive-sharepoint on
    // the shared frozen Agent 365 host with a daemon-supplied GUID-validated
    // {tenantId} PATH segment (pathTenantFromUpstream). None remains deferred.
    const sf = MCP_SERVER_SPECS["salesforce"];
    expect(sf).toBeDefined();
    expect(sf.host).toBe("api.salesforce.com");
    expect(sf.hostFromUpstream).toBeUndefined();
    expect(sf.pathTenantFromUpstream).toBeUndefined();

    for (const sid of ["microsoft-365", "onedrive-sharepoint"]) {
      const spec = MCP_SERVER_SPECS[sid];
      expect(spec).toBeDefined();
      expect(spec.host).toBe("agent365.svc.cloud.microsoft");
      expect(spec.hostFromUpstream).toBeUndefined();   // host is frozen, not per-account
      expect(spec.pathTenantFromUpstream).toBe(true);
      expect(spec.pathPrefix.includes("{tenantId}")).toBe(true);
    }
  });

  it("the 4 W38-S735 per-account servers are wired as per-account (no frozen host)", () => {
    for (const sid of ["snowflake", "netsuite", "databricks", "shopify"]) {
      const spec = MCP_SERVER_SPECS[sid];
      expect(spec).toBeDefined();
      expect(spec.hostFromUpstream).toBe(true);
      expect(spec.host).toBeUndefined();          // never a frozen host
      expect(Array.isArray(spec.hostPattern)).toBe(true);
      expect((spec.hostPattern ?? []).length).toBeGreaterThanOrEqual(1);
    }
    // databricks is multi-cloud — 3 anchored patterns (AWS/Azure/GCP).
    expect(MCP_SERVER_SPECS["databricks"].hostPattern?.length).toBe(3);
  });

  for (const [sid, spec] of fixedEntries) {
    it(`${sid}: host ∈ ALLOWED_OUTBOUND_HOSTS, single static host, valid pathPrefix`, () => {
      // (a) host is on the egress allowlist (else route step 3 → 500).
      expect(allow.has(spec.host as string)).toBe(true);
      // (b) single static DNS host — no SSRF / template / path smuggled in.
      expect(/^[a-z0-9.-]+$/.test(spec.host as string)).toBe(true);
      for (const ch of ["{", "}", "<", ">", "*", "/", ":", " "]) {
        expect((spec.host as string).includes(ch)).toBe(false);
      }
      // (c) pathPrefix is "" or rooted ("/..."); https://host+pathPrefix parses
      // and its origin is exactly the frozen host (no host smuggled via path).
      expect(spec.pathPrefix === "" || spec.pathPrefix.startsWith("/")).toBe(true);
      const u = new URL(`https://${spec.host}${spec.pathPrefix}`);
      expect(u.hostname).toBe(spec.host);
      // (d) bearer auth + a test-seam env var name (never request-derived host).
      expect(spec.authStyle).toBe("bearer");
      expect(spec.baseUrlVar).toMatch(/^MCP_[A-Z0-9_]+_BASE_URL$/);
    });
  }

  for (const [sid, spec] of perAccountEntries) {
    it(`${sid}: per-account spec is host-free + carries anchored spec-bound pattern(s)`, () => {
      // (a) NO frozen host, NO host smuggled into the allowlist.
      expect(spec.host).toBeUndefined();
      expect(spec.hostFromUpstream).toBe(true);
      // (b) every bound pattern is fully anchored (^…$) — no .*, no `i` flag.
      const patterns = spec.hostPattern ?? [];
      expect(patterns.length).toBeGreaterThanOrEqual(1);
      for (const re of patterns) {
        expect(re.source.startsWith("^")).toBe(true);
        expect(re.source.endsWith("$")).toBe(true);
        expect(re.source.includes(".*")).toBe(false);
        expect(re.flags.includes("i")).toBe(false);
      }
      // (c) pathPrefix rooted; bearer auth + test-seam env var name.
      expect(spec.pathPrefix === "" || spec.pathPrefix.startsWith("/")).toBe(true);
      expect(spec.authStyle).toBe("bearer");
      expect(spec.baseUrlVar).toMatch(/^MCP_[A-Z0-9_]+_BASE_URL$/);
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// W38-S735 — per-account host derivation negative-security suite.
//
// The per-account host arrives daemon-supplied (X-Bishop-Upstream-Host) and is
// SSRF-bounded by the spec's OWN anchored vendor pattern (spec-bind). The route
// must: forward a valid host to EXACTLY that host; refuse an out-of-pattern host,
// a suffix-spoof, a DIFFERENT vendor's valid host on this spec, and a missing
// header — all WITHOUT forwarding. Unit-style (handleMcp + stubbed global fetch):
// the upstream forward is captured so we can assert the exact host, and the
// no-forward legs assert fetch was never called.
// ─────────────────────────────────────────────────────────────────────────────

describe("W38-S735 per-account host derivation (/mcp/<per-account server>)", () => {
  const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);

  // Valid per-account hosts (one per vendor + each databricks cloud).
  const SNOWFLAKE_OK = "acme-marketing.snowflakecomputing.com";
  const NETSUITE_OK = "1234567.suitetalk.api.netsuite.com";
  const SHOPIFY_OK = "acme-store.myshopify.com";
  const DATABRICKS_AWS_OK = "dbc-a1b2c3d4-e5f6.cloud.databricks.com";
  const DATABRICKS_AZURE_OK = "adb-984752964297111.11.azuredatabricks.net";
  const DATABRICKS_GCP_OK = "1234567890123456.7.gcp.databricks.com";

  function perAccountReq(serverId: string, upstreamHost: string | null): Request {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      authorization: `Bearer ${DAEMON_BEARER}`,
      "x-bishop-upstream-key": UPSTREAM_KEY,
    };
    if (upstreamHost !== null) headers["x-bishop-upstream-host"] = upstreamHost;
    return new Request(`http://proxy/mcp/${serverId}`, {
      method: "POST",
      headers,
      body: TEST_BODY,
    });
  }

  let capturedUrl: string | null;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    capturedUrl = null;
    mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      capturedUrl = input instanceof Request ? input.url : String(input);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function expectForwardsToHost(serverId: string, host: string) {
    const resp = await handleMcp(perAccountReq(serverId, host), makeAllowEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();
    // No base-URL override env is set for these → baseUrl = https://<validated>,
    // so the captured upstream URL host is EXACTLY the daemon-supplied host.
    expect(new URL(capturedUrl as string).hostname).toBe(host);
  }

  async function expectRefused(serverId: string, host: string | null, errorCode: string) {
    const resp = await handleMcp(perAccountReq(serverId, host), makeAllowEnv(), makeCtx());
    expect(resp.status).toBe(400);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe(errorCode);
    expect(mockFetch).not.toHaveBeenCalled(); // NO forward on a refusal
  }

  // ── ★ valid host → forwards to EXACTLY that host (no arbitrary reachability) ──
  it("★ snowflake: valid host forwards to exactly that host", async () => {
    await expectForwardsToHost("snowflake", SNOWFLAKE_OK);
  });
  it("★ netsuite: valid host forwards to exactly that host", async () => {
    await expectForwardsToHost("netsuite", NETSUITE_OK);
  });
  it("★ shopify: valid host forwards to exactly that host", async () => {
    await expectForwardsToHost("shopify", SHOPIFY_OK);
  });
  it("★ databricks: valid AWS host forwards to exactly that host", async () => {
    await expectForwardsToHost("databricks", DATABRICKS_AWS_OK);
  });
  it("★ databricks: valid Azure host forwards to exactly that host", async () => {
    await expectForwardsToHost("databricks", DATABRICKS_AZURE_OK);
  });
  it("★ databricks: valid GCP host forwards to exactly that host", async () => {
    await expectForwardsToHost("databricks", DATABRICKS_GCP_OK);
  });

  // ── ★ out-of-pattern host → refused, no forward ──────────────────────────────
  it("★ snowflake: out-of-pattern host (evil.com) → 400 mcp_host_not_allowed, no forward", async () => {
    await expectRefused("snowflake", "evil.com", "mcp_host_not_allowed");
  });
  it("★ snowflake: suffix-spoof host → 400 mcp_host_not_allowed, no forward", async () => {
    await expectRefused("snowflake", "acme.snowflakecomputing.com.attacker.com", "mcp_host_not_allowed");
  });
  it("★ databricks: a non-databricks host → 400 mcp_host_not_allowed, no forward", async () => {
    await expectRefused("databricks", SNOWFLAKE_OK, "mcp_host_not_allowed");
  });

  // ── ★ wrong-vendor-but-valid-pattern → refused (SPEC-BIND) ───────────────────
  it("★ spec-bind: a netsuite-valid host on the snowflake spec → 400, no forward", async () => {
    await expectRefused("snowflake", NETSUITE_OK, "mcp_host_not_allowed");
  });
  it("★ spec-bind: a snowflake-valid host on the netsuite spec → 400, no forward", async () => {
    await expectRefused("netsuite", SNOWFLAKE_OK, "mcp_host_not_allowed");
  });
  it("★ spec-bind: a shopify-valid host on the databricks spec → 400, no forward", async () => {
    await expectRefused("databricks", SHOPIFY_OK, "mcp_host_not_allowed");
  });

  // ── ★ missing X-Bishop-Upstream-Host → refused, no forward ───────────────────
  it("★ snowflake: missing X-Bishop-Upstream-Host → 400 mcp_upstream_host_missing, no forward", async () => {
    await expectRefused("snowflake", null, "mcp_upstream_host_missing");
  });
  it("★ shopify: missing X-Bishop-Upstream-Host → 400 mcp_upstream_host_missing, no forward", async () => {
    await expectRefused("shopify", null, "mcp_upstream_host_missing");
  });

  // ── spec-bind, pure-regex: each spec's pattern admits ONLY its vendor ─────────
  it("spec-bind invariant: each vendor pattern rejects the other vendors' valid hosts", () => {
    const okByVendor: Record<string, string> = {
      snowflake: SNOWFLAKE_OK,
      netsuite: NETSUITE_OK,
      shopify: SHOPIFY_OK,
    };
    for (const [sid, ownHost] of Object.entries(okByVendor)) {
      const patterns = MCP_SERVER_SPECS[sid].hostPattern ?? [];
      // Own host matches at least one of the spec's bound patterns…
      expect(patterns.some((re) => re.test(ownHost))).toBe(true);
      // …and NO other vendor's valid host matches this spec.
      for (const [otherSid, otherHost] of Object.entries(okByVendor)) {
        if (otherSid === sid) continue;
        expect(patterns.some((re) => re.test(otherHost))).toBe(false);
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// W38-S736 — frozen-host-with-templated-tenant-PATH negative-security suite.
//
// microsoft-365 + onedrive-sharepoint share ONE frozen host
// (agent365.svc.cloud.microsoft); the per-tenant id lives in the PATH and is
// daemon-supplied (X-Bishop-Upstream-Path-Tenant). The route must: forward to
// EXACTLY the frozen host with the GUID substituted into the path; refuse a
// missing tenant; refuse any path-injection tenant (/, .., a dotted "host", a
// non-GUID) — all WITHOUT forwarding. salesforce is a plain frozen-host spec and
// sends NO tenant. Unit-style (handleMcp + stubbed global fetch): the upstream
// forward is captured so we can assert host stays frozen AND the path carries the
// substituted GUID; the no-forward legs assert fetch was never called.
// ─────────────────────────────────────────────────────────────────────────────

describe("W38-S736 frozen-host + templated-tenant-PATH (/mcp/<microsoft server>)", () => {
  const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
  const MS_HOST = "agent365.svc.cloud.microsoft";
  const VALID_TENANT = "9a8b7c6d-1234-4567-89ab-0123456789ab"; // bare lowercase GUID

  function tenantReq(serverId: string, tenant: string | null): Request {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      authorization: `Bearer ${DAEMON_BEARER}`,
      "x-bishop-upstream-key": UPSTREAM_KEY,
    };
    if (tenant !== null) headers["x-bishop-upstream-path-tenant"] = tenant;
    return new Request(`http://proxy/mcp/${serverId}`, {
      method: "POST",
      headers,
      body: TEST_BODY,
    });
  }

  let capturedUrl: string | null;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    capturedUrl = null;
    mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      capturedUrl = input instanceof Request ? input.url : String(input);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function expectRefused(serverId: string, tenant: string | null, errorCode: string) {
    const resp = await handleMcp(tenantReq(serverId, tenant), makeAllowEnv(), makeCtx());
    expect(resp.status).toBe(400);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe(errorCode);
    expect(mockFetch).not.toHaveBeenCalled(); // NO forward on a refusal
  }

  // ── ★ valid GUID → forwards to EXACTLY the frozen host, GUID in the path ────
  for (const sid of ["microsoft-365", "onedrive-sharepoint"]) {
    it(`★ ${sid}: valid GUID substitutes into the path; host STILL the frozen host`, async () => {
      const resp = await handleMcp(tenantReq(sid, VALID_TENANT), makeAllowEnv(), makeCtx());
      expect(resp.status).toBe(200);
      expect(mockFetch).toHaveBeenCalledOnce();
      const u = new URL(capturedUrl as string);
      // (a) host is UNCHANGED — the frozen Agent 365 host, never request-derived.
      expect(u.hostname).toBe(MS_HOST);
      // (b) the {tenantId} placeholder is GONE, replaced by the validated GUID.
      expect(u.pathname).toContain(`/agents/tenants/${VALID_TENANT}/servers/`);
      expect(u.pathname.includes("{tenantId}")).toBe(false);
    });
  }

  // ── ★ salesforce: plain frozen-host spec, forwards to its host, NO tenant ───
  it("★ salesforce: forwards to the exact frozen host, no tenant header required", async () => {
    // No tenant header supplied — salesforce is NOT pathTenantFromUpstream.
    const resp = await handleMcp(tenantReq("salesforce", null), makeAllowEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();
    const u = new URL(capturedUrl as string);
    expect(u.hostname).toBe("api.salesforce.com");
    expect(u.pathname.startsWith("/platform/mcp/v1/platform/sobject-all")).toBe(true);
  });

  // ── ★ missing tenant → 400 mcp_upstream_tenant_missing, NO forward ──────────
  it("★ microsoft-365: missing tenant header → 400 mcp_upstream_tenant_missing, no forward", async () => {
    await expectRefused("microsoft-365", null, "mcp_upstream_tenant_missing");
  });
  it("★ onedrive-sharepoint: missing tenant header → 400 mcp_upstream_tenant_missing, no forward", async () => {
    await expectRefused("onedrive-sharepoint", null, "mcp_upstream_tenant_missing");
  });

  // ── ★ path-injection tenant → 400 mcp_tenant_not_allowed, NO forward ────────
  const INJECTION_TENANTS = [
    "..%2f",                                   // encoded path traversal
    "abc/../../evil",                          // raw traversal
    "foo.bar",                                 // dotted "host"-like value
    "../../../etc/passwd",                     // classic traversal
    "9A8B7C6D-1234-4567-89AB-0123456789AB",    // UPPERCASE GUID (lowercase-only regex)
    "9a8b7c6d-1234-4567-89ab-0123456789ab/x",  // valid GUID + smuggled segment
    "",                                        // empty after the header is present-but-blank → missing
  ] as const;
  for (const bad of INJECTION_TENANTS) {
    const expected = bad === "" ? "mcp_upstream_tenant_missing" : "mcp_tenant_not_allowed";
    it(`★ microsoft-365: path-injection tenant ${JSON.stringify(bad)} → 400 ${expected}, no forward`, async () => {
      await expectRefused("microsoft-365", bad, expected);
    });
  }

  // ── 46 fixed + 4 per-account intact (no regression of the prior cohorts) ────
  it("the 46 fixed-host + 4 per-account specs are intact (no host/spec-bind regression)", () => {
    const entries = Object.entries(MCP_SERVER_SPECS);
    const fixed = entries.filter(([, s]) => !s.hostFromUpstream);
    const perAccount = entries.filter(([, s]) => s.hostFromUpstream);
    expect(fixed.length).toBe(46);
    expect(perAccount.length).toBe(4);
    // every fixed host is exact-allow-listed; every per-account spec is host-free.
    const allow = new Set<string>(ALLOWED_OUTBOUND_HOSTS as readonly string[]);
    for (const [, s] of fixed) expect(allow.has(s.host as string)).toBe(true);
    for (const [, s] of perAccount) {
      expect(s.host).toBeUndefined();
      expect(s.hostFromUpstream).toBe(true);
    }
  });
});
