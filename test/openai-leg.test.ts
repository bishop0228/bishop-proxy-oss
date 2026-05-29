/**
 * Integration probes for the OpenAI leg: POST /v1/chat/completions.
 *
 * Symmetry sibling of non-openai-legs.test.ts — gives the OpenAI route the same
 * end-to-end entitlement-gate + Pillar-1 proof the grok/qwen/gemini legs carry.
 *
 * Coverage:
 *   - byok token + no X-Bishop-Upstream-Key → 400 byok_key_missing
 *   - managed token + inbound X-Bishop-Upstream-Key → 200; operator key
 *     forwarded to mock, inbound key ignored
 *   - Pillar-1: managed 200 response headers carry no authorization /
 *     x-bishop-upstream-key / operator-key leak; content-type forwarded
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";

const PROXY_VARS_BASE = {
  STRIPE_WEBHOOK_SECRET: "test_secret",
  ANTHROPIC_API_KEY: "test_key",
  TARGET_ZERO_BITS: "8",
  TARGET_MEMORY_KIB: "8",
  CHALLENGE_TTL: "60",
  MOCK_AI: "1",
};

const TEST_VERSION = "test-client-0.1.0";

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
  if (challengeRes.status !== 200) {
    const body = await challengeRes.text();
    throw new Error(`challenge failed status=${challengeRes.status} body=${body}`);
  }
  const cBody = (await challengeRes.json()) as { nonce?: string };
  if (!cBody.nonce) throw new Error(`challenge returned no nonce: ${JSON.stringify(cBody)}`);
  const nonce = cBody.nonce;
  const counter = solvePow(fp, nonce, 8, 8);
  const enrollBody: Record<string, string> = {
    nonce,
    counter,
    fingerprint_hash: fp,
    client_version: TEST_VERSION,
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

describe("OpenAI leg (/v1/chat/completions)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let managedToken: string;
  let byokToken: string;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-openai-compat.ts", {
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
        OPENAI_API_KEY: "op-openai-zzz",
        OPENAI_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
      },
      persist: false,
    });

    // Other test files accumulate challenge calls against the same AuthStoreDO
    // state on disk (.wrangler/state persists across unstable_dev workers even
    // with persist:false). Clear the counter before enrolling so we don't hit
    // the 10/day rate limit.
    const today = new Date().toISOString().slice(0, 10);
    const clearRes = await worker.fetch("/admin/rate-limit/clear", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": "test_admin" },
      body: JSON.stringify({ ip_prefix: "127.0.0", endpoint: "challenge", date: today }),
    });
    if (!clearRes.ok) {
      const errBody = await clearRes.text();
      throw new Error(`rate-limit clear failed: ${clearRes.status} ${errBody}`);
    }
    await clearRes.json();

    // Fingerprints "3"/"4" — distinct from enroll.test.ts (a-d),
    // messages.test.ts (e-f), and non-openai-legs.test.ts (1-2).
    managedToken = await enroll(worker, "3".repeat(64));
    byokToken = await enroll(worker, "4".repeat(64), "byok");
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  it("byok without X-Bishop-Upstream-Key → 400 byok_key_missing", async () => {
    const res = await worker.fetch("/v1/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
      },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 30000);

  it("managed + inbound X-Bishop-Upstream-Key → 200; mock sees operator key", async () => {
    const res = await worker.fetch("/v1/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
        "x-bishop-upstream-key": "should-be-ignored",
      },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await lastAuthRes.json()) as { auth: string | null };
    expect(auth).toBe("Bearer op-openai-zzz");
  }, 30000);

  it("Pillar-1: managed 200 response headers carry no auth leak; content-type forwarded", async () => {
    const res = await worker.fetch("/v1/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.has("authorization")).toBe(false);
    expect(res.headers.has("x-bishop-upstream-key")).toBe(false);
    expect(res.headers.has("operator-key")).toBe(false);
    expect(res.headers.get("content-type")).toBe("application/json");
  }, 30000);
});
