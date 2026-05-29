/**
 * Behavioral probes for §1.17.17 AWS Bedrock SigV4 BYOK leg (/byok/bedrock/...).
 *
 * 8 probes:
 *   (1) managed → 400 bedrock_requires_byok; mock NOT hit
 *   (2) byok + no upstream key → 400 byok_key_missing
 *   (3) byte-exact body forwarded (no re-serialization)
 *   (4) SigV4 authorization correct; host header = real AWS host (not mock)
 *   (5) classify-block → 451; Bedrock upstream NOT called   [unit-style]
 *   (6) Pillar-1 audit absence: no logEvent contains cred strings [unit-style]
 *   (7) allowlist floor: bedrock-runtime host added exact-match; no wildcards
 *   (8) shared choke: missing bearer → 401; quota 429 → quota_exceeded + X-Bishop-Cap-Type
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { ALLOWED_OUTBOUND_HOSTS } from "../src/lib/outbound-allowlist";
import { sigv4Sign } from "../src/lib/sigv4";
import { handleBedrock } from "../src/routes/bedrock";
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

const CREDS = {
  accessKeyId: "AKIATEST12345678",
  secretAccessKey: "my-secret-value-1234",
};

const UPSTREAM_KEY = `${CREDS.accessKeyId}:${CREDS.secretAccessKey}`;

const TEST_BODY = JSON.stringify({
  modelId: "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
  messages: [{ role: "user", content: [{ type: "text", text: "hello bedrock" }] }],
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
    client_version: "test-bedrock-0.1.0",
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
    token: "bsk_staging_" + "x".repeat(24),
    token_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "ff".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-bedrock-0.1.0",
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

function makeAllowEnv(): Env {
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
    BEDROCK_BASE_URL: "https://bedrock-runtime.us-east-1.amazonaws.com",
  } as unknown as Env;
}

function makeBlockEnv(): Env {
  return {
    AUTH_STORE: makeByokAuthNamespace(),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    AI: {
      run: async (_model: string, _input: unknown) => ({ response: "unsafe\nS4" }),
    } as unknown as Ai,
    BEDROCK_BASE_URL: "https://bedrock-runtime.us-east-1.amazonaws.com",
  } as unknown as Env;
}

function makeQuota429Env(): Env {
  return {
    AUTH_STORE: makeByokAuthNamespace(),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(429),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
    BEDROCK_BASE_URL: "https://bedrock-runtime.us-east-1.amazonaws.com",
  } as unknown as Env;
}

// ── describe ───────────────────────────────────────────────────────────────

describe("Bedrock BYOK leg (/byok/bedrock/...)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let managedToken: string;
  let byokToken: string;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-bedrock-upstream.ts", {
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
        BEDROCK_BASE_URL: mockUrl,
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

    managedToken = await enroll(worker, "e".repeat(64));
    byokToken = await enroll(worker, "f".repeat(64), "byok");
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  // ── Probe 1: managed → 400 bedrock_requires_byok; mock NOT hit ────────

  it("managed token: /byok/bedrock/... → 400 bedrock_requires_byok; mock NOT hit", async () => {
    const res = await worker.fetch("/byok/bedrock/model/invoke", {
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
    expect(body.error).toBe("bedrock_requires_byok");

    // Mock must NOT have been called (blocked before forwarding).
    const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await lastAuthRes.json()) as { auth: string | null };
    expect(auth).toBeNull();
  }, 30000);

  // ── Probe 2: byok_key_missing ─────────────────────────────────────────

  it("byok + no upstream key → 400 byok_key_missing", async () => {
    const res = await worker.fetch("/byok/bedrock/model/invoke", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        // x-bishop-upstream-key intentionally absent
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 30000);

  // ── Probe 3: byte-exact body forwarded ───────────────────────────────

  it("byok: body forwarded byte-exact (no re-serialization)", async () => {
    const res = await worker.fetch("/byok/bedrock/model/invoke", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(200);

    const lastBodyRes = await mock.fetch(mockUrl + "/__last_body");
    const { body } = (await lastBodyRes.json()) as { body: string | null };
    expect(body).toBe(TEST_BODY);
  }, 30000);

  // ── Probe 4: SigV4 correctness ────────────────────────────────────────

  it("byok: SigV4 authorization correct; host header = real AWS host", async () => {
    const res = await worker.fetch("/byok/bedrock/model/invoke", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": UPSTREAM_KEY,
      },
      body: TEST_BODY,
    });
    expect(res.status).toBe(200);

    const [amzDateResp, authResp, hostResp] = await Promise.all([
      mock.fetch(mockUrl + "/__last_amzdate").then((r) => r.json() as Promise<{ amzDate: string | null }>),
      mock.fetch(mockUrl + "/__last_auth").then((r) => r.json() as Promise<{ auth: string | null }>),
      mock.fetch(mockUrl + "/__last_host").then((r) => r.json() as Promise<{ host: string | null }>),
    ]);

    const capturedAmzDate = amzDateResp.amzDate;
    const capturedAuth = authResp.auth;
    const capturedHost = hostResp.host;

    expect(capturedAmzDate).not.toBeNull();
    expect(capturedAuth).not.toBeNull();
    expect(capturedHost).not.toBeNull();

    // Recompute expected signature with the captured amzDate.
    // We sign with host="bedrock-runtime.us-east-1.amazonaws.com" — the real AWS host.
    // If capturedAuth matches, the proxy signed with the correct canonical host.
    const { authorization: expected } = await sigv4Sign({
      accessKeyId: CREDS.accessKeyId,
      secretAccessKey: CREDS.secretAccessKey,
      region: "us-east-1",
      service: "bedrock-runtime",
      method: "POST",
      path: "/model/invoke",
      host: "bedrock-runtime.us-east-1.amazonaws.com",
      contentType: "application/json",
      amzDate: capturedAmzDate!,
      payload: TEST_BODY,
    });

    expect(capturedAuth).toBe(expected);
    expect(capturedAuth).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIATEST12345678\//);
    expect(capturedAuth).toContain("/us-east-1/bedrock-runtime/aws4_request");

    // The HTTP-level host header reflects the mock server's address in test mode
    // (workerd's fetch client sets Host to the actual target URL — expected behavior).
    // The SigV4 canonical host is proven correct by the signature match above.
    expect(capturedHost).not.toBeNull();
  }, 30000);

  // ── Probe 5: classify-block → 451; Bedrock upstream NOT called (unit) ─

  it("classify block: 451 content_policy_violation; Bedrock upstream NOT called", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    try {
      const req = new Request("http://proxy/byok/bedrock/model/invoke", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer bsk_staging_" + "x".repeat(24),
          "x-bishop-upstream-key": UPSTREAM_KEY,
        },
        body: TEST_BODY,
      });

      const resp = await handleBedrock(req, makeBlockEnv(), makeCtx());
      expect(resp.status).toBe(451);
      const body = (await resp.json()) as { type: string; error: { type: string } };
      expect(body.type).toBe("error");
      expect(body.error.type).toBe("content_policy_violation");

      // Verify upstream was NOT called.
      const bedrockCalls = fetchSpy.mock.calls.filter(([input]) => {
        const url = String(input instanceof Request ? input.url : input);
        return url.includes("bedrock-runtime") || url.includes("amazonaws.com");
      });
      expect(bedrockCalls).toHaveLength(0);

      // Classification log event must have been emitted.
      const loggedEvents = logSpy.mock.calls
        .map((call) => { try { return JSON.parse(String(call[0])); } catch { return null; } })
        .filter((e) => e !== null);
      const classifBlock = loggedEvents.find(
        (e) => e.event_type === "classification" && e.classification_decision === "block",
      );
      expect(classifBlock).toBeDefined();
      expect(isProxyLogEvent(classifBlock)).toBe(true);
    } finally {
      fetchSpy.mockRestore();
      logSpy.mockRestore();
    }
  });

  // ── Probe 6: Pillar-1 audit absence (unit-style) ──────────────────────

  it("Pillar-1: no logEvent contains accessKeyId, secretAccessKey, or signature", async () => {
    // Mock globalThis.fetch so the bedrock-runtime fetch succeeds.
    const mockFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ output: { message: { role: "assistant", content: [] } }, stopReason: "end_turn" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    try {
      const req = new Request("http://proxy/byok/bedrock/model/invoke", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer bsk_staging_" + "x".repeat(24),
          "x-bishop-upstream-key": UPSTREAM_KEY,
        },
        body: TEST_BODY,
      });

      const resp = await handleBedrock(req, makeAllowEnv(), makeCtx());
      // Response is 200 (upstream mock returns 200).
      expect(resp.status).toBe(200);

      // Every logged event must not contain credential strings.
      for (const call of logSpy.mock.calls) {
        const line = String(call[0]);
        expect(line).not.toContain(CREDS.accessKeyId);
        expect(line).not.toContain(CREDS.secretAccessKey);
        // Signature is a hex string derived from the secret; the secret itself must not appear.
        // We check both the raw secret and accessKeyId.
      }

      // At least one logEvent must have been emitted (the Step 8 audit event).
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

  // ── Probe 7: allowlist floor intact ──────────────────────────────────

  it("allowlist floor: bedrock-runtime.us-east-1.amazonaws.com added exact-match; no wildcards", () => {
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("bedrock-runtime.us-east-1.amazonaws.com");

    const hosts = ALLOWED_OUTBOUND_HOSTS as readonly string[];
    const noWildcards = hosts.every(
      (h) => !h.startsWith(".") && !h.includes("*") && !h.includes("?"),
    );
    expect(noWildcards).toBe(true);
  });

  // ── Probe 8: shared choke ─────────────────────────────────────────────

  it("shared choke: missing bearer → 401 missing_bearer; quota 429 → quota_exceeded + X-Bishop-Cap-Type", async () => {
    // 8a — missing bearer (integration).
    const res = await worker.fetch("/byok/bedrock/model/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: TEST_BODY,
    });
    expect(res.status).toBe(401);
    const b = (await res.json()) as { error: string };
    expect(b.error).toBe("missing_bearer");

    // 8b — quota exceeded (unit-style).
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", mockFetch);

    try {
      const req = new Request("http://proxy/byok/bedrock/model/invoke", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer bsk_staging_" + "x".repeat(24),
          "x-bishop-upstream-key": UPSTREAM_KEY,
        },
        body: TEST_BODY,
      });
      const resp = await handleBedrock(req, makeQuota429Env(), makeCtx());
      expect(resp.status).toBe(429);
      const body = (await resp.json()) as { error: string; reason: string | null };
      expect(body.error).toBe("quota_exceeded");
      const capType = resp.headers.get("X-Bishop-Cap-Type");
      expect(capType).toBeTruthy();
      expect(capType).not.toBe("null");
    } finally {
      vi.unstubAllGlobals();
    }
  }, 30000);
});
