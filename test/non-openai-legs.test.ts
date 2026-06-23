/**
 * Integration probes for non-OpenAI legs: grok, qwen, gemini.
 *
 * Coverage:
 *   - byok token + no X-Bishop-Upstream-Key → 400 byok_key_missing (×3, one per leg)
 *   - managed token + inbound X-Bishop-Upstream-Key → 200; operator key forwarded
 *     to mock, inbound key ignored (×3)
 *   - Pillar-1: managed 200 response headers carry no authorization /
 *     x-bishop-upstream-key / operator-key leak; content-type forwarded (×1)
 *   - W38-S970 NATIVE Gemini route (/v1beta/models/{model}:generateContent):
 *     the daemon's native generateContent URL shape hits a REAL proxy route
 *     (200, not the default 404) — byok fail-closed, managed forwards the
 *     operator key as x-goog-api-key (native auth, not Bearer), no inbound leak.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { clearAuthRateLimits } from "./helpers/clear-auth-rate-limits";
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

describe("non-OpenAI legs (grok/qwen/gemini)", () => {
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
        XAI_API_KEY: "op-xai-zzz",
        QWEN_API_KEY: "op-qwen-zzz",
        GEMINI_API_KEY: "op-gemini-zzz",
        XAI_BASE_URL: mockUrl,
        QWEN_BASE_URL: mockUrl,
        GEMINI_BASE_URL: mockUrl,
        GEMINI_NATIVE_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
      },
      persist: false,
    });

    // Other test files accumulate challenge + enroll calls against the same
    // AuthStoreDO state on disk (.wrangler/state persists across unstable_dev
    // workers even with persist:false). Clear BOTH counters before enrolling so
    // we don't hit the 10/24h rate limit regardless of file ordering.
    await clearAuthRateLimits(worker);

    managedToken = await enroll(worker, "1".repeat(64));
    byokToken = await enroll(worker, "2".repeat(64), "byok");
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  // ---- byok fail-closed (×3) ----

  it("grok: byok without X-Bishop-Upstream-Key → 400 byok_key_missing", async () => {
    const res = await worker.fetch("/v1/grok/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
      },
      body: JSON.stringify({ model: "grok-3", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 30000);

  it("qwen: byok without X-Bishop-Upstream-Key → 400 byok_key_missing", async () => {
    const res = await worker.fetch("/v1/qwen/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
      },
      body: JSON.stringify({ model: "qwen-max", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 30000);

  it("gemini: byok without X-Bishop-Upstream-Key → 400 byok_key_missing", async () => {
    const res = await worker.fetch("/v1/gemini/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
      },
      body: JSON.stringify({ model: "gemini-2.0-flash", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 30000);

  // ---- managed: operator key forwarded, inbound key ignored (×3) ----

  it("grok: managed + inbound X-Bishop-Upstream-Key → 200; mock sees operator key", async () => {
    const res = await worker.fetch("/v1/grok/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
        "x-bishop-upstream-key": "should-be-ignored",
      },
      body: JSON.stringify({ model: "grok-3", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await lastAuthRes.json()) as { auth: string | null };
    expect(auth).toBe("Bearer op-xai-zzz");
  }, 30000);

  it("qwen: managed + inbound X-Bishop-Upstream-Key → 200; mock sees operator key", async () => {
    const res = await worker.fetch("/v1/qwen/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
        "x-bishop-upstream-key": "should-be-ignored",
      },
      body: JSON.stringify({ model: "qwen-max", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await lastAuthRes.json()) as { auth: string | null };
    expect(auth).toBe("Bearer op-qwen-zzz");
  }, 30000);

  it("gemini: managed + inbound X-Bishop-Upstream-Key → 200; mock sees operator key", async () => {
    const res = await worker.fetch("/v1/gemini/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
        "x-bishop-upstream-key": "should-be-ignored",
      },
      body: JSON.stringify({ model: "gemini-2.0-flash", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await lastAuthRes.json()) as { auth: string | null };
    expect(auth).toBe("Bearer op-gemini-zzz");
  }, 30000);

  // ---- Pillar-1: response headers carry no credential leak ----

  it("Pillar-1: managed 200 response headers carry no auth leak; content-type forwarded", async () => {
    const res = await worker.fetch("/v1/grok/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: JSON.stringify({ model: "grok-3", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.has("authorization")).toBe(false);
    expect(res.headers.has("x-bishop-upstream-key")).toBe(false);
    expect(res.headers.has("operator-key")).toBe(false);
    expect(res.headers.get("content-type")).toBe("application/json");
  }, 30000);

  // ---- W38-S970: NATIVE Gemini generateContent route ----

  const NATIVE_PATH = "/v1beta/models/gemini-2.5-flash:generateContent";
  const NATIVE_BODY = JSON.stringify({
    contents: [{ role: "user", parts: [{ text: "hi" }] }],
  });

  it("gemini-native: the daemon's native generateContent URL hits a REAL route (not the 404 default)", async () => {
    // Anti-fixture-mask: the W9.7-class regression was that the daemon spoke
    // native :generateContent while the proxy served only the OpenAI-compat path,
    // so every native call fell through to the catch-all 404. Asserting 200 here
    // (a managed call against a real upstream) proves the URL shapes MATCH.
    const res = await worker.fetch(NATIVE_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: NATIVE_BODY,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { candidates?: unknown[]; error?: string };
    expect(body.error).toBeUndefined();
    expect(Array.isArray(body.candidates)).toBe(true);
  }, 30000);

  it("gemini-native: byok without X-Bishop-Upstream-Key → 400 byok_key_missing", async () => {
    const res = await worker.fetch(NATIVE_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
      },
      body: NATIVE_BODY,
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 30000);

  it("gemini-native: managed forwards operator key as x-goog-api-key (native auth), inbound key ignored", async () => {
    const res = await worker.fetch(NATIVE_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
        "x-bishop-upstream-key": "should-be-ignored",
      },
      body: NATIVE_BODY,
    });
    expect(res.status).toBe(200);
    // Native auth header — NOT Bearer; carries the operator key, never the inbound one.
    const keyRes = await mock.fetch(mockUrl + "/__last_goog_key");
    const { key } = (await keyRes.json()) as { key: string | null };
    expect(key).toBe("op-gemini-zzz");
    const authRes = await mock.fetch(mockUrl + "/__last_auth");
    const { auth } = (await authRes.json()) as { auth: string | null };
    expect(auth).toBeNull(); // native leg sends no Authorization upstream
  }, 30000);

  it("gemini-native: an unparseable model segment is not routed (no host injection)", async () => {
    // A path that does not match the anchored {model}:generateContent shape must
    // fall through — the model id can never carry a slash/host.
    const res = await worker.fetch("/v1beta/models/evil%2F..%2Fhost:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: NATIVE_BODY,
    });
    expect(res.status).toBe(404); // unmatched → default handler, never an upstream call
  }, 30000);

  it("gemini-native: Pillar-1 — managed 200 response carries no auth/key leak", async () => {
    const res = await worker.fetch(NATIVE_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: NATIVE_BODY,
    });
    expect(res.status).toBe(200);
    expect(res.headers.has("authorization")).toBe(false);
    expect(res.headers.has("x-goog-api-key")).toBe(false);
    expect(res.headers.has("x-bishop-upstream-key")).toBe(false);
  }, 30000);
});
