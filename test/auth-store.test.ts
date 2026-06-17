/**
 * AuthStoreDO real-surface coverage for revoked + expired verdicts.
 *
 * not_found / valid / tier-free-seed remain covered in messages.test.ts
 * (188 / 236-259 / 252) — this file now owns the two formerly-unreachable verdicts:
 *   - revoked: reachable via /admin/token/revoke → /v1/messages 401 token_revoked
 *   - expired: reachable via BISHOP_TEST_TOKEN_TTL_MS test seam → /v1/messages 401 token_expired
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import type { AuthRecord } from "../src/durable-objects/auth-store";

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
  throw new Error("No PoW solution found");
}

async function enrollFull(worker: Unstable_DevWorker, fp: string): Promise<AuthRecord> {
  const challengeRes = await worker.fetch("/v1/challenge");
  if (challengeRes.status !== 200) {
    throw new Error(`challenge failed: ${challengeRes.status}`);
  }
  const { nonce } = (await challengeRes.json()) as { nonce: string };
  const counter = solvePow(fp, nonce, 8, 8);
  const enrollRes = await worker.fetch("/v1/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce, counter, fingerprint_hash: fp, client_version: TEST_VERSION }),
  });
  expect([200, 201]).toContain(enrollRes.status);
  return (await enrollRes.json()) as AuthRecord;
}

describe("AuthStoreDO: revoked verdict + admin gate", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let record: AuthRecord;

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
      vars: {
        ...PROXY_VARS_BASE,
        ANTHROPIC_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
        ADMIN_TOKEN: "test_admin",
        USER_INDEX_HMAC_KEY: "test_hmac_key",
      },
      persist: false,
    });
    // .wrangler/state persists across unstable_dev workers even with persist:false;
    // clear rate-limit counters before enrolling to stay under the 10/day cap.
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

    // Fresh fingerprint not used by other test files (brief §3: use "1a".repeat(32))
    record = await enrollFull(worker, "1a".repeat(32));
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  it("revoked end-to-end: valid token → revoke → 401 token_revoked", async () => {
    // Pre-revoke: token is active → /v1/messages returns 200
    const preRes = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${record.token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(preRes.status).toBe(200);
    await preRes.body?.cancel();

    // Revoke via admin endpoint keyed by token_id (non-secret)
    const revokeRes = await worker.fetch("/admin/token/revoke", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": "test_admin" },
      body: JSON.stringify({ token_id: record.token_id }),
    });
    expect(revokeRes.status).toBe(200);
    const revokeBody = (await revokeRes.json()) as { revoked: boolean; existed: boolean };
    expect(revokeBody.revoked).toBe(true);
    expect(revokeBody.existed).toBe(true);

    // Post-revoke: formerly-dead branch is now live → 401 token_revoked
    const postRes = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${record.token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(postRes.status).toBe(401);
    const postBody = (await postRes.json()) as { error: string };
    expect(postBody.error).toBe("token_revoked");
  }, 30000);

  it("admin gate: missing or wrong X-Admin-Token → 401 unauthorized", async () => {
    const noHeader = await worker.fetch("/admin/token/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token_id: "00000000-0000-0000-0000-000000000000" }),
    });
    expect(noHeader.status).toBe(401);
    expect(((await noHeader.json()) as { error: string }).error).toBe("unauthorized");

    const wrongHeader = await worker.fetch("/admin/token/revoke", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": "wrong_secret" },
      body: JSON.stringify({ token_id: "00000000-0000-0000-0000-000000000000" }),
    });
    expect(wrongHeader.status).toBe(401);
    expect(((await wrongHeader.json()) as { error: string }).error).toBe("unauthorized");
  });

  it("admin gate: valid admin token + non-UUID token_id → 400 invalid_parameters", async () => {
    const res = await worker.fetch("/admin/token/revoke", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": "test_admin" },
      body: JSON.stringify({ token_id: "not-a-uuid" }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_parameters");
  });

  it("unknown token_id: well-formed UUID but not enrolled → 200 {revoked:false, existed:false}", async () => {
    const res = await worker.fetch("/admin/token/revoke", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": "test_admin" },
      body: JSON.stringify({ token_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { revoked: boolean; existed: boolean };
    expect(body.revoked).toBe(false);
    expect(body.existed).toBe(false);
  });
});

describe("AuthStoreDO: expired verdict via TTL seam", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-anthropic.ts", {
      config: "test/wrangler.mock.toml",
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      persist: false,
    });
    const mockUrl = `http://${mock.address}:${mock.port}`;
    // Separate worker instance: BISHOP_TEST_TOKEN_TTL_MS="-60000" issues tokens
    // already expired at issuance (born 60s in the past; no sleep needed).
    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: {
        ...PROXY_VARS_BASE,
        ANTHROPIC_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
        ADMIN_TOKEN: "test_admin",
        USER_INDEX_HMAC_KEY: "test_hmac_key",
        BISHOP_TEST_TOKEN_TTL_MS: "-60000",
      },
      persist: false,
    });

    // .wrangler/state persists; clear rate-limit counters before enrolling.
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
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  it("expired: negative TTL token → 401 token_expired on /v1/messages", async () => {
    // Fresh fingerprint for expired suite (brief §3: use "2b".repeat(32))
    const rec = await enrollFull(worker, "2b".repeat(32));
    const res = await worker.fetch("/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${rec.token}`,
      },
      body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("token_expired");
  }, 30000);
});

describe("AuthStoreDO: FREE→CONNECTED relabel on re-enroll (W38-S872g)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;

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
      vars: {
        ...PROXY_VARS_BASE,
        ANTHROPIC_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
        ADMIN_TOKEN: "test_admin",
        USER_INDEX_HMAC_KEY: "test_hmac_key",
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
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  async function enrollMode(
    fp: string,
    accountMode?: "managed" | "byok",
  ): Promise<{ status: number; rec: AuthRecord }> {
    const { nonce } = (await (await worker.fetch("/v1/challenge")).json()) as { nonce: string };
    const counter = solvePow(fp, nonce, 8, 8);
    const body: Record<string, unknown> = {
      nonce,
      counter,
      fingerprint_hash: fp,
      client_version: TEST_VERSION,
    };
    if (accountMode) body.account_mode = accountMode;
    const res = await worker.fetch("/v1/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: res.status, rec: (await res.json()) as AuthRecord };
  }

  it("managed device that connects a key (re-enrolls byok) is relabeled byok — same token, no new enrollment", async () => {
    const fp = "3c".repeat(32);

    // First enrollment with no account_mode → FREE/managed (free-tier default).
    const first = await enrollMode(fp);
    expect([200, 201]).toContain(first.status);
    expect(first.rec.account_mode).toBe("managed");

    // User connects a BYOK key → daemon re-enrolls with account_mode="byok".
    // The free tier ends; the existing device is relabeled in place.
    const second = await enrollMode(fp, "byok");
    expect(second.status).toBe(200); // existing fingerprint → not a new issuance
    expect(second.rec.account_mode).toBe("byok"); // relabeled
    expect(second.rec.token_id).toBe(first.rec.token_id); // same device/token
    expect(second.rec.token).toBe(first.rec.token);
  }, 40000);

  it("does NOT auto-downgrade byok→managed on re-enroll (billing-safe; fail-closed)", async () => {
    const fp = "4d".repeat(32);
    const byokFirst = await enrollMode(fp, "byok");
    expect([200, 201]).toContain(byokFirst.status);
    expect(byokFirst.rec.account_mode).toBe("byok");

    // A managed re-enroll must NOT silently flip a connected device back to
    // Bishop's operator key (that would let it spend on the managed key).
    const managedReenroll = await enrollMode(fp, "managed");
    expect(managedReenroll.rec.account_mode).toBe("byok"); // unchanged
    expect(managedReenroll.rec.token_id).toBe(byokFirst.rec.token_id);
  }, 40000);
});
