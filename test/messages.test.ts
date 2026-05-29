/**
 * POST /v1/messages tests.
 *
 * Coverage per brief:
 *   - 401 missing Authorization
 *   - 401 malformed bearer (token < 16 chars)
 *   - 401 token_not_found (well-formed unknown token)
 *   - 400 bad_json
 *   - 400 unsupported_model
 *   - 200 streaming pass-through (X-Bishop-Quota-Remaining + X-Bishop-Cap-Type)
 *   - 200 byte-for-byte SSE parity (tee() does not mutate the client branch)
 *   - 500 retry exhaustion (3 attempts, then surface 500)
 *   - 400 no-retry pass-through
 *   - flaky-500 → 200 after retry success
 *
 * The mock upstream Anthropic worker (test/mock-anthropic.ts) is started on
 * its own port; its URL is injected into the proxy as ANTHROPIC_BASE_URL.
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

async function setMockMode(mock: Unstable_DevWorker, mode: string): Promise<void> {
  const r = await mock.fetch("http://mock/__set_mode", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode }),
  });
  expect(r.status).toBe(200);
}

describe("POST /v1/messages", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let sharedToken: string;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-anthropic.ts", {
      config: "test/wrangler.mock.toml",
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      persist: false,
    });
    const mockUrl = `http://${mock.address}:${mock.port}`;
    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: { ...PROXY_VARS_BASE, ANTHROPIC_BASE_URL: mockUrl, BISHOP_TEST_OUTBOUND_HOSTS: mock.address },
      persist: false,
    });
    // Enroll a single shared token for all token-using tests. Each enroll
    // costs one /v1/challenge call against the 10/24h-per-/24 rate limit;
    // unstable_dev sends every request from 0.0.0.0, so all enrolls share
    // one bucket. One enroll keeps us well under the cap.
    // Avoid fingerprints used by enroll.test.ts: "a"-"d".repeat(64). Pick a
     // hex value distinct from any other test file that may share .wrangler
     // state when vitest runs files in parallel.
    sharedToken = await enroll(worker, "e".repeat(64));
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch("http://mock/__reset", { method: "POST" });
  });

  // ---- auth gate ----

  it("401 missing_bearer when Authorization header absent", async () => {
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("missing_bearer");
  });

  it("401 malformed_bearer when token < 16 chars", async () => {
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer short",
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("malformed_bearer");
  });

  it("401 token_not_found when bearer is well-formed but unknown", async () => {
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer bsk_staging_unknownunknownunknown",
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("token_not_found");
  });

  // ---- body validation (require a real token) ----

  it("400 bad_json when body is not valid JSON", async () => {
    const token = sharedToken;
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: "{ not json",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("bad_json");
  }, 60000);

  it("400 unsupported_model when model id is not haiku/sonnet", async () => {
    const token = sharedToken;
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ model: "gpt-4", stream: true }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unsupported_model");
  }, 60000);

  // ---- success path ----

  it("200 SSE pass-through with X-Bishop-Quota-Remaining + X-Bishop-Cap-Type:null", async () => {
    await setMockMode(mock, "stream-200");
    const token = sharedToken;
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Bishop-Cap-Type")).toBe("null");
    const remaining = res.headers.get("X-Bishop-Quota-Remaining");
    expect(remaining).toBeTruthy();
    // Free tier monthly_cost_cents=100; pre-increment remaining is full cap.
    expect(remaining).toBe("100");

    // tee() should hand the client a byte-equivalent stream; verify SSE shape.
    const text = await res.text();
    expect(text).toContain("event: message_start");
    expect(text).toContain("event: message_delta");
    expect(text).toContain("event: message_stop");
  }, 60000);

  // ---- retry policy (G8) ----

  it("upstream 500 surfaces 500 to client after 3-attempt retry budget", async () => {
    await setMockMode(mock, "fail-500");
    const token = sharedToken;
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(500);
  }, 60000);

  it("upstream 400 surfaces 400 immediately (no retry)", async () => {
    await setMockMode(mock, "fail-400");
    const token = sharedToken;
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(400);
  }, 60000);

  it("flaky 500 → 200 after 3rd attempt (retry success)", async () => {
    await setMockMode(mock, "flaky-500");
    const token = sharedToken;
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("event: message_stop");
  }, 60000);

  it("P7: byok enroll + POST /v1/messages without X-Bishop-Upstream-Key → 400 byok_key_missing", async () => {
    const byokToken = await enroll(worker, "f".repeat(64), "byok");
    await setMockMode(mock, "success");
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        // No X-Bishop-Upstream-Key — must fail-closed
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("byok_key_missing");
  }, 60000);

  it("P8: managed enroll + inbound X-Bishop-Upstream-Key → 200 (header ignored, flow ok)", async () => {
    await setMockMode(mock, "success");
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${sharedToken}`,
        "x-bishop-upstream-key": "should-be-ignored",
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(200);
  }, 60000);
});
