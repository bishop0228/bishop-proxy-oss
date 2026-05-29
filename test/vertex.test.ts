/**
 * Behavioral probes for §1.17.19 Google Vertex AI Bearer BYOK leg (/byok/vertex/...).
 *
 * 8 probes:
 *   (1) happy path: Bearer reaches upstream (assert auth === "Bearer "+TOKEN)
 *   (2) managed → 400 vertex_requires_byok; mock NOT hit
 *   (3) missing x-bishop-upstream-key → 400 byok_key_missing
 *   (4) no-colon key → 400 byok_key_missing
 *   (5) invalid region (multi-label SSRF) → 400 vertex_region_invalid; mock NOT hit
 *   (6) mixed-case region normalized → 200 (regression guard for control #4)
 *   (7) Pillar-1: access token NEVER in any logged event
 *   (8) url.search ?alt= preserved through forward
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import {
  ALLOWED_OUTBOUND_HOSTS,
  isAnchoredEnterpriseHost,
} from "../src/lib/outbound-allowlist";
import { handleVertex } from "../src/routes/vertex";
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

const TEST_REGION = "us-central1";
const TEST_TOKEN = "ya29.test-access-token";
const UPSTREAM_KEY = `${TEST_REGION}:${TEST_TOKEN}`;

const TEST_BODY = JSON.stringify({
  messages: [{ role: "user", content: "hello vertex" }],
  model: "gemini-pro",
});

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
    client_version: "test-vertex-0.1.0",
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
    token_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "bb".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-vertex-0.1.0",
    account_mode: "byok" as const,
  };
  return makeNamespace(async () =>
    new Response(JSON.stringify({ valid: true, record, reason: null }), {
      headers: { "content-type": "application/json" },
    }),
  );
}

function makeTierNamespace() {
  return makeNamespace(async () =>
    new Response(JSON.stringify({ tier: "free" }), {
      headers: { "content-type": "application/json" },
    }),
  );
}

function makeQuotaNamespace(returnStatus = 200) {
  return makeNamespace(async (req) => {
    const url = new URL(req.url);
    if (url.pathname === "/check") {
      if (returnStatus === 429) {
        return new Response(
          JSON.stringify({ reason: "monthly_cost_exceeded" }),
          { status: 429, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  });
}

function makeAllowEnv(vertexBaseUrl = "https://us-central1-aiplatform.googleapis.com"): Env {
  return {
    AUTH_STORE: makeByokAuthNamespace(),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
    VERTEX_BASE_URL: vertexBaseUrl,
  } as unknown as Env;
}

// ── describe ───────────────────────────────────────────────────────────────

describe("Vertex AI BYOK leg (/byok/vertex/...)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let managedToken: string;
  let byokToken: string;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-vertex-upstream.ts", {
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
        VERTEX_BASE_URL: mockUrl,
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

    // Use distinct fingerprints (9/0 reserved for vertex tests, 7/8 used by azure.test.ts).
    managedToken = await enroll(worker, "9".repeat(64));
    byokToken = await enroll(worker, "0".repeat(64), "byok");
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  // ── Probe 1: happy path — Bearer reaches upstream ─────────────────────

  it("byok: Bearer token forwarded to upstream (happy path)", async () => {
    const res = await worker.fetch("/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(200);

    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBe(`Bearer ${TEST_TOKEN}`);
  }, 30000);

  // ── Probe 2: managed → 400 vertex_requires_byok; mock NOT hit ─────────

  it("managed token: /byok/vertex/... → 400 vertex_requires_byok; mock NOT hit", async () => {
    const res = await worker.fetch("/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("vertex_requires_byok");

    // Mock must NOT have been called (blocked before forwarding).
    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 3: missing x-bishop-upstream-key → 400 byok_key_missing ─────

  it("byok + no upstream key → 400 byok_key_missing; mock NOT hit", async () => {
    const res = await worker.fetch("/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        // x-bishop-upstream-key intentionally absent
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(400);
    const b = (await res.json()) as { error: string };
    expect(b.error).toBe("byok_key_missing");

    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 4: no-colon key → 400 byok_key_missing ─────────────────────

  it("byok + no-colon credential → 400 byok_key_missing; mock NOT hit", async () => {
    const res = await worker.fetch("/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": "uscentral1notoken",
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(400);
    const b = (await res.json()) as { error: string };
    expect(b.error).toBe("byok_key_missing");

    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 5: invalid region (multi-label SSRF) → 400 vertex_region_invalid; mock NOT hit

  it("multi-label SSRF region → 400 vertex_region_invalid; mock NOT hit (fail-before-fetch)", async () => {
    const multiLabelKey = "evil.com/x:ya29.stolen-token";
    const res = await worker.fetch("/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": multiLabelKey,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("vertex_region_invalid");

    // Mock must NOT have been called — gate fires BEFORE fetch.
    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 6: mixed-case region normalized → 200 (control #4 regression) ─

  it("byok: mixed-case region lowercased — reaches upstream (not 400)", async () => {
    const res = await worker.fetch("/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": `US-Central1:${TEST_TOKEN}`,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(200);
    const authResp = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authResp.json()) as { auth: string | null };
    expect(auth).toBe(`Bearer ${TEST_TOKEN}`);
  }, 30000);

  // ── Probe 7: Pillar-1 — access token NEVER in any logged event ────────

  it("Pillar-1: no logEvent contains the access token (unit-style)", async () => {
    const mockFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ id: "chatcmpl-x", choices: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    try {
      const req = new Request(
        "http://proxy/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: "Bearer bsk_staging_" + "v".repeat(24),
            "x-bishop-upstream-key": UPSTREAM_KEY,
          },
          body: TEST_BODY,
        },
      );

      const resp = await handleVertex(req, makeAllowEnv(), makeCtx());
      expect(resp.status).toBe(200);

      // Every logged event must not contain the access token.
      for (const call of logSpy.mock.calls) {
        const line = String(call[0]);
        expect(line).not.toContain(TEST_TOKEN);
        expect(line).not.toContain(UPSTREAM_KEY);
      }

      // At least one logEvent must have been emitted (Step 8 audit).
      expect(logSpy.mock.calls.length).toBeGreaterThan(0);
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

  // ── Probe 8: url.search ?alt= preserved through forward ───────────────

  it("byok: url.search query params preserved through forward", async () => {
    const res = await worker.fetch(
      "/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent?alt=sse",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${byokToken}`,
          "x-bishop-upstream-key": UPSTREAM_KEY,
        },
        body: TEST_BODY,
      },
    );
    expect(res.status).toBe(200);

    const searchResp = await mock.fetch(mockUrl + "/__last_search");
    const { search } = (await searchResp.json()) as { search: string | null };
    expect(search).toContain("alt=sse");
  }, 30000);

  // ── Unit: isAnchoredEnterpriseHost Vertex patterns ────────────────────

  it("isAnchoredEnterpriseHost: valid Vertex region accepted; spoof/sibling rejected", () => {
    // Accepts — valid single-label region + exact suffix.
    expect(isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com")).toBe(true);
    expect(isAnchoredEnterpriseHost("europe-west4-aiplatform.googleapis.com")).toBe(true);

    // Rejects — suffix-spoof (extra trailing domain).
    expect(isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com.attacker.com")).toBe(false);
    // Rejects — sibling (oauth2 service — proves floor did NOT widen to *.googleapis.com).
    expect(isAnchoredEnterpriseHost("oauth2.googleapis.com")).toBe(false);
    // Rejects — unrelated domain.
    expect(isAnchoredEnterpriseHost("evil.com")).toBe(false);
    // Rejects — uppercase (no `i` flag).
    expect(isAnchoredEnterpriseHost("US-CENTRAL1-aiplatform.googleapis.com")).toBe(false);

    // Valid Vertex host is NOT in the exact ALLOWED_OUTBOUND_HOSTS set —
    // it's served by the enterprise-host floor pattern, not the static list.
    const allowedSet = new Set<string>(ALLOWED_OUTBOUND_HOSTS as readonly string[]);
    expect(allowedSet.has("us-central1-aiplatform.googleapis.com")).toBe(false);
  });
});
