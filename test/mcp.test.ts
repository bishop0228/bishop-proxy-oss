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

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
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

    const today = new Date().toISOString().slice(0, 10);
    for (const endpoint of ["challenge", "enroll"]) {
      const r = await worker.fetch("/admin/rate-limit/clear", {
        method: "POST",
        headers: { "content-type": "application/json", "x-admin-token": "test_admin" },
        body: JSON.stringify({ ip_prefix: "127.0.0", endpoint, date: today }),
      });
      if (!r.ok) throw new Error(`rate-limit clear failed for ${endpoint}: ${r.status}`);
      await r.json();
    }

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

  // ── Probe 7: allowlist length UNCHANGED (§3.2 no-widen sentinel) ──────

  it("ALLOWED_OUTBOUND_HOSTS length UNCHANGED + github host already present", () => {
    // §1.18.15 adds NO host (api.githubcopilot.com was already present for the
    // §1.17.16 GitHub Copilot OAuth leg). The MCP leg reuses it — no runtime widen.
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(32);
    expect((ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes("api.githubcopilot.com")).toBe(true);
  });

  // ── Probe 8: SSRF unit — spec.host frozen, server-side, ∈ allowlist ───

  it("SSRF unit: github spec.host is frozen, server-side, and ∈ ALLOWED_OUTBOUND_HOSTS", () => {
    const spec = MCP_SERVER_SPECS["github"];
    expect(spec).toBeDefined();
    expect(spec.host).toBe("api.githubcopilot.com");
    // The map is frozen — a request can never mutate or inject a host.
    expect(Object.isFrozen(MCP_SERVER_SPECS)).toBe(true);
    expect((ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(spec.host)).toBe(true);
    // Unknown server_id has no spec → handler refuses (probe 2) — no host fallback.
    expect(MCP_SERVER_SPECS["evilserver"]).toBeUndefined();
  });
});
