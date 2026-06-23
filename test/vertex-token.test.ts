/**
 * Behavioral probes for §1.17.19 Vertex SA-token mint leg (/byok/vertex/token).
 *
 * 7 probes:
 *   (1) missing_bearer → 401 (no Authorization header)
 *   (2) malformed_bearer → 401 (token len < 16)
 *   (3) token_not_found → 401 (verify-token rejects unknown token)
 *   (4) happy path: JWT body forwarded; access_token passes through verbatim (200)
 *   (5) Pillar-1: JWT assertion + access_token absent from all logged events
 *   (6) method guard: GET /byok/vertex/token → 404 (not routed to mint handler)
 *   (7) upstream host: fetch targets VERTEX_TOKEN_BASE_URL/token (server-constructed URL)
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { clearAuthRateLimits } from "./helpers/clear-auth-rate-limits";
import { handleVertexToken } from "../src/routes/vertex-token";
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

const FAKE_JWT_ASSERTION =
  "eyJhbGciOiJSUzI1NiJ9." + "x".repeat(50) + "." + "y".repeat(40);
const GRANT_BODY = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${FAKE_JWT_ASSERTION}`;

// ── PoW + enroll helpers ───────────────────────────────────────────────────

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

function solvePow(
  fingerprintHash: string,
  nonce: string,
  targetBits: number,
  memKib: number,
): string {
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

async function enroll(
  worker: Unstable_DevWorker,
  fp: string,
  account_mode?: string,
): Promise<string> {
  const challengeRes = await worker.fetch("/v1/challenge");
  if (challengeRes.status !== 200) throw new Error(`challenge failed: ${challengeRes.status}`);
  const cBody = (await challengeRes.json()) as { nonce?: string };
  if (!cBody.nonce) throw new Error(`challenge no nonce: ${JSON.stringify(cBody)}`);
  const counter = solvePow(fp, cBody.nonce, 8, 8);
  const enrollBody: Record<string, string> = {
    nonce: cBody.nonce,
    counter,
    fingerprint_hash: fp,
    client_version: "test-vertex-token-0.1.0",
  };
  if (account_mode !== undefined) enrollBody["account_mode"] = account_mode;
  const enrollRes = await worker.fetch("/v1/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(enrollBody),
  });
  expect([200, 201]).toContain(enrollRes.status);
  const rec = (await enrollRes.json()) as { token: string };
  return rec.token;
}

// ── Unit-style env helpers ────────────────────────────────────────────────

function makeStub(handler: (req: Request) => Promise<Response> | Response) {
  return {
    fetch: async (input: RequestInfo, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input as string, init);
      return handler(req);
    },
  };
}

function makeNamespace(
  handler: (req: Request) => Promise<Response> | Response,
): DurableObjectNamespace {
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

function makeByokAuthNamespace() {
  const record = {
    token: "bsk_staging_" + "v".repeat(24),
    token_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-vertex-token-0.1.0",
    account_mode: "byok" as const,
  };
  return makeNamespace(async () =>
    new Response(JSON.stringify({ valid: true, record, reason: null }), {
      headers: { "content-type": "application/json" },
    }),
  );
}

function makeInvalidAuthNamespace(reason = "not_found") {
  return makeNamespace(async () =>
    new Response(JSON.stringify({ valid: false, record: null, reason }), {
      headers: { "content-type": "application/json" },
    }),
  );
}

function makeTokenEnv(tokenBaseUrl: string): Env {
  return {
    AUTH_STORE: makeByokAuthNamespace(),
    TIER_CACHE: makeNamespace(async () =>
      new Response(JSON.stringify({ tier: "free" }), {
        headers: { "content-type": "application/json" },
      }),
    ),
    QUOTA_STORE: makeNamespace(async () =>
      new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      }),
    ),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
    VERTEX_TOKEN_BASE_URL: tokenBaseUrl,
  } as unknown as Env;
}

// ── describe ───────────────────────────────────────────────────────────────

describe("Vertex token-mint leg (/byok/vertex/token)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let byokToken: string;

  beforeAll(async () => {
    // Reuse mock-oauth-upstream.ts — POST /token path returns TOKEN_BODY
    mock = await unstable_dev("test/mock-oauth-upstream.ts", {
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
        // §1.17.19 test seam: redirect Google token endpoint to mock
        VERTEX_TOKEN_BASE_URL: mockUrl,
        // Allow mock server IP through the outbound allowlist
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
      },
      persist: false,
    });

    // Self-isolate against the serial suite's shared on-disk AuthStoreDO:
    // clear BOTH the challenge nonce + enroll rate-limit counters.
    await clearAuthRateLimits(worker);

    // Use distinct fingerprints: "4" = byok for this test suite.
    // ("3" is reserved for openai-leg.test.ts managed token; sharing fingerprint
    // causes idempotent DO re-enrollment to return the wrong account_mode.)
    byokToken = await enroll(worker, "4".repeat(64), "byok");
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── Probe 1: missing_bearer → 401 ────────────────────────────────────────

  it("(1) missing_bearer: no Authorization header → 401", async () => {
    const res = await worker.fetch("/byok/vertex/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: GRANT_BODY,
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("missing_bearer");
  }, 30000);

  // ── Probe 2: malformed_bearer → 401 ──────────────────────────────────────

  it("(2) malformed_bearer: token len < 16 → 401", async () => {
    const res = await worker.fetch("/byok/vertex/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: "Bearer short",
      },
      body: GRANT_BODY,
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("malformed_bearer");
  }, 30000);

  // ── Probe 3: token_not_found → 401 ───────────────────────────────────────

  it("(3) token_not_found: unknown (never-enrolled) token → 401", async () => {
    const fakeToken = "bsk_staging_not_enrolled_here_00000000";
    const res = await worker.fetch("/byok/vertex/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${fakeToken}`,
      },
      body: GRANT_BODY,
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/^token_/);
  }, 30000);

  // ── Probe 4: happy path → 200 + access_token verbatim ────────────────────

  it("(4) happy path: JWT body forwarded; access_token passes through verbatim", async () => {
    const res = await worker.fetch("/byok/vertex/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${byokToken}`,
      },
      body: GRANT_BODY,
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { access_token?: string };
    expect(json.access_token).toBe("upstream-minted-xyz");

    // Body was forwarded unmodified.
    const lastBodyRes = await mock.fetch(mockUrl + "/__last_body");
    const { body } = (await lastBodyRes.json()) as { body: string | null };
    expect(body).toBe(GRANT_BODY);

    // Bishop Authorization header was stripped (mock sees no Authorization).
    const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await lastAuthRes.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 5: Pillar-1 — no secret in any logged event (unit-style) ────────

  it("(5) Pillar-1: JWT assertion + access_token absent from all logged events", async () => {
    const MOCK_ACCESS_TOKEN = "ya29.pillar1-unit-test-access-token-secret";
    const mockFetch = vi.fn(async (_input: RequestInfo | URL) =>
      new Response(
        JSON.stringify({ access_token: MOCK_ACCESS_TOKEN, token_type: "Bearer", expires_in: 3600 }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    try {
      const req = new Request("http://proxy/byok/vertex/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: "Bearer bsk_staging_" + "v".repeat(24),
        },
        body: GRANT_BODY,
      });

      const resp = await handleVertexToken(req, makeTokenEnv("http://mock-google.test"), makeCtx());
      expect(resp.status).toBe(200);

      // At least one metadata event must have been emitted.
      expect(logSpy.mock.calls.length).toBeGreaterThan(0);

      // No log line may contain the JWT assertion string or the access_token value.
      for (const call of logSpy.mock.calls) {
        const line = String(call[0]);
        expect(line).not.toContain(FAKE_JWT_ASSERTION);
        expect(line).not.toContain(MOCK_ACCESS_TOKEN);
      }

      // Every emitted event must be a valid ProxyLogEvent (metadata-only).
      const allValid = logSpy.mock.calls.every((call) => {
        try {
          const parsed = JSON.parse(String(call[0]));
          return isProxyLogEvent(parsed);
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

  // ── Probe 6: method guard — GET /byok/vertex/token not routed to mint handler ──

  it("(6) method guard: GET /byok/vertex/token → 404 (POST-only route)", async () => {
    const res = await worker.fetch("/byok/vertex/token", {
      method: "GET",
    });
    expect(res.status).not.toBe(200);
    expect(res.status).toBe(404);
  }, 30000);

  // ── Probe 7: upstream host is server-constructed (unit-style) ─────────────

  it("(7) upstream host: fetch URL = VERTEX_TOKEN_BASE_URL + /token (server-side construction)", async () => {
    const TEST_BASE = "http://mock-google.test";
    let capturedUrl: string | undefined;

    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      capturedUrl = input instanceof Request ? input.url : String(input);
      return new Response(
        JSON.stringify({ access_token: "ya29.captured-url-test", expires_in: 3600, token_type: "Bearer" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", mockFetch);

    try {
      const req = new Request("http://proxy/byok/vertex/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: "Bearer bsk_staging_" + "v".repeat(24),
        },
        body: GRANT_BODY,
      });

      const resp = await handleVertexToken(req, makeTokenEnv(TEST_BASE), makeCtx());
      expect(resp.status).toBe(200);

      // Proxy fetched exactly `<VERTEX_TOKEN_BASE_URL>/token` — not any request-controlled URL.
      expect(capturedUrl).toBe(`${TEST_BASE}/token`);
      expect(mockFetch).toHaveBeenCalledOnce();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
