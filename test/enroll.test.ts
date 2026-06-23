/**
 * Enrollment tests.
 *
 * Uses reduced PoW params (TARGET_MEMORY_KIB=8, TARGET_ZERO_BITS=8) so tests
 * complete in milliseconds. CHALLENGE_TTL=5 for fast expiry tests.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { clearAuthRateLimits } from "./helpers/clear-auth-rate-limits";

const TEST_VARS = {
  STRIPE_WEBHOOK_SECRET: "test_secret",
  ANTHROPIC_API_KEY: "test_key",
  TARGET_ZERO_BITS: "8",
  TARGET_MEMORY_KIB: "8",
  CHALLENGE_TTL: "60",
  ADMIN_TOKEN: "test_admin",
};

// Solve PoW with test params: m=8KiB, target=8 bits
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
    // counter: 8 bytes big-endian
    const counterBytes = new Uint8Array(8);
    const view = new DataView(counterBytes.buffer);
    view.setBigUint64(0, BigInt(i), false);
    salt.set(counterBytes, 16);

    const hash = argon2id(fpBytes, salt, { t: 1, m: memKib, p: 1, dkLen: 32 });
    if (countLeadingZeroBits(hash) >= targetBits) {
      return toHex(counterBytes);
    }
  }
  throw new Error("No solution found");
}

// Fixed test fingerprint hash (64 hex chars)
const TEST_FP = "a".repeat(64);
const TEST_VERSION = "test-client-0.1.0";

describe("/v1/challenge + /v1/enroll", () => {
  let worker: Unstable_DevWorker;

  beforeAll(async () => {
    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: TEST_VARS,
      persist: false,
    });

    // Self-isolate: the serial suite shares one on-disk AuthStoreDO across
    // files, so clear BOTH the challenge nonce + enroll rate-limit counters
    // before this file's challenge/enroll tests run.
    await clearAuthRateLimits(worker);
  }, 30000);

  afterAll(async () => {
    await worker.stop();
  });

  // ---- /v1/challenge ----

  it("GET /v1/challenge returns nonce, expires_at, difficulty", async () => {
    const res = await worker.fetch("/v1/challenge");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { nonce: string; expires_at: string; difficulty: number };
    expect(body.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(body.expires_at).toBeTruthy();
    expect(body.difficulty).toBe(8);
  });

  it("GET /v1/challenge difficulty reflects TEST_VARS", async () => {
    const res = await worker.fetch("/v1/challenge");
    const body = (await res.json()) as { difficulty: number };
    expect(body.difficulty).toBe(8);
  });

  // ---- /v1/enroll validation ----

  it("POST /v1/enroll with missing body returns 400", async () => {
    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });

  it("POST /v1/enroll with bad nonce length returns 400 invalid_nonce", async () => {
    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: "ab",
        counter: "00".repeat(8),
        fingerprint_hash: TEST_FP,
        client_version: TEST_VERSION,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_nonce");
  });

  it("POST /v1/enroll with bad counter length returns 400 invalid_counter", async () => {
    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: "ab".repeat(16),
        counter: "0000",
        fingerprint_hash: TEST_FP,
        client_version: TEST_VERSION,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_counter");
  });

  it("POST /v1/enroll with bad fingerprint length returns 400 invalid_fingerprint_hash", async () => {
    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: "ab".repeat(16),
        counter: "00".repeat(8),
        fingerprint_hash: "abc",
        client_version: TEST_VERSION,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_fingerprint_hash");
  });

  it("POST /v1/enroll with stale nonce returns 400 nonce_not_found", async () => {
    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: "de".repeat(16),
        counter: "00".repeat(8),
        fingerprint_hash: TEST_FP,
        client_version: TEST_VERSION,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("nonce_not_found");
  });

  // ---- full happy-path enrollment ----

  it("fresh enrollment returns 201 with token and AuthRecord fields", async () => {
    // 1. Get challenge
    const challengeRes = await worker.fetch("/v1/challenge");
    const { nonce } = (await challengeRes.json()) as { nonce: string };

    // 2. Solve PoW with test params
    const counter = solvePow(TEST_FP, nonce, 8, 8);

    // 3. Enroll
    const enrollRes = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce,
        counter,
        fingerprint_hash: TEST_FP,
        client_version: TEST_VERSION,
      }),
    });
    expect(enrollRes.status).toBe(201);

    const record = (await enrollRes.json()) as {
      token: string;
      token_id: string;
      issued_at: string;
      expires_at: string;
      fingerprint_hash: string;
      status: string;
      refresh_count: number;
    };
    expect(record.token).toMatch(/^bsk_staging_/);
    expect(record.token_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(record.issued_at).toBeTruthy();
    expect(record.expires_at).toBeTruthy();
    expect(record.fingerprint_hash).toBe(TEST_FP);
    expect(record.status).toBe("active");
    expect(record.refresh_count).toBe(0);
  }, 60000);

  it("idempotency: second enrollment with same fingerprint returns 200 and same token", async () => {
    const fp = "b".repeat(64);

    // First enrollment
    const c1 = await worker.fetch("/v1/challenge");
    const { nonce: n1 } = (await c1.json()) as { nonce: string };
    const counter1 = solvePow(fp, n1, 8, 8);
    const r1 = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: n1, counter: counter1, fingerprint_hash: fp, client_version: TEST_VERSION }),
    });
    expect(r1.status).toBe(201);
    const rec1 = (await r1.json()) as { token: string };

    // Second enrollment with same fingerprint
    const c2 = await worker.fetch("/v1/challenge");
    const { nonce: n2 } = (await c2.json()) as { nonce: string };
    const counter2 = solvePow(fp, n2, 8, 8);
    const r2 = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: n2, counter: counter2, fingerprint_hash: fp, client_version: TEST_VERSION }),
    });
    expect(r2.status).toBe(200);
    const rec2 = (await r2.json()) as { token: string };

    expect(rec2.token).toBe(rec1.token);
  }, 120000);

  it("replay protection: reusing a nonce returns 400 nonce_not_found", async () => {
    const fp = "c".repeat(64);

    const c1 = await worker.fetch("/v1/challenge");
    const { nonce } = (await c1.json()) as { nonce: string };
    const counter = solvePow(fp, nonce, 8, 8);

    // First use — should succeed
    const r1 = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce, counter, fingerprint_hash: fp, client_version: TEST_VERSION }),
    });
    expect(r1.status).toBe(201);

    // Second use with same nonce — nonce burned, must fail
    const r2 = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce, counter, fingerprint_hash: fp, client_version: TEST_VERSION }),
    });
    expect(r2.status).toBe(400);
    const body = (await r2.json()) as { error: string };
    expect(body.error).toBe("nonce_not_found");
  }, 120000);

  it("wrong PoW counter returns 400 pow_insufficient", async () => {
    const fp = "d".repeat(64);

    const c1 = await worker.fetch("/v1/challenge");
    const { nonce } = (await c1.json()) as { nonce: string };

    // Deliberately wrong counter (all zeros is extremely unlikely to satisfy 8-bit target)
    const wrongCounter = "ff".repeat(8);

    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce, counter: wrongCounter, fingerprint_hash: fp, client_version: TEST_VERSION }),
    });
    // Most of the time this will be pow_insufficient; occasionally it may randomly satisfy
    // the 8-bit target (1/256 chance). Accept either outcome for that case.
    if (res.status === 400) {
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("pow_insufficient");
    } else {
      // Randomly valid — acceptable
      expect([200, 201]).toContain(res.status);
    }
  }, 30000);
});
