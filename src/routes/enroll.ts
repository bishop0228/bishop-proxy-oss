/**
 * POST /v1/enroll
 *
 * Ratified schema: { nonce: string (32 hex), counter: string (16 hex),
 *                    fingerprint_hash: string (64 hex), client_version: string }
 *
 * Flow:
 *   1. Validate field shapes
 *   2. KV nonce lookup then DELETE (before PoW verification — one-time-use)
 *   3. argon2id(fingerprint_bytes, nonce_bytes||counter_bytes, {t:1, m, p:1, dkLen:32})
 *   4. Check leading TARGET_ZERO_BITS zero bits
 *   5. Rate-limit check (10/24h per /24)
 *   6. AuthStoreDO issue/lookup
 *   7. Return 201 (new) or 200 (existing)
 */

import { argon2id } from "@noble/hashes/argon2.js";
import type { AuthRecord } from "../durable-objects/auth-store";

export interface EnrollEnv {
  ENROLL_KV: KVNamespace;
  AUTH_STORE: DurableObjectNamespace;
  TARGET_ZERO_BITS?: string;
  TARGET_MEMORY_KIB?: string;
}

interface EnrollRequest {
  nonce: string;
  counter: string;
  fingerprint_hash: string;
  client_version: string;
}

function isHex(s: string, expectedLen: number): boolean {
  return typeof s === "string" && s.length === expectedLen && /^[0-9a-f]+$/i.test(s);
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
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

function getIp24(request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP") ?? "0.0.0.0";
  const parts = ip.split(".");
  if (parts.length === 4) return parts.slice(0, 3).join(".");
  return ip.split(":").slice(0, 3).join(":");
}

export async function handleEnroll(
  request: Request,
  env: EnrollEnv,
): Promise<Response> {
  let body: EnrollRequest;
  try {
    body = (await request.json()) as EnrollRequest;
  } catch {
    return new Response(
      JSON.stringify({ error: "invalid_json" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  const { nonce, counter, fingerprint_hash, client_version } = body;

  // 1. Validate field shapes
  if (!isHex(nonce, 32)) {
    return new Response(
      JSON.stringify({ error: "invalid_nonce" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }
  if (!isHex(counter, 16)) {
    return new Response(
      JSON.stringify({ error: "invalid_counter" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }
  if (!isHex(fingerprint_hash, 64)) {
    return new Response(
      JSON.stringify({ error: "invalid_fingerprint_hash" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }
  if (typeof client_version !== "string" || client_version.length === 0 || client_version.length > 64) {
    return new Response(
      JSON.stringify({ error: "invalid_client_version" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  // 2. KV nonce lookup then DELETE — one-time-use, burn before verify
  const kvKey = `nonce:${nonce}`;
  const kvValue = await env.ENROLL_KV.get(kvKey);
  if (!kvValue) {
    return new Response(
      JSON.stringify({ error: "nonce_not_found" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }
  await env.ENROLL_KV.delete(kvKey);

  // 3. argon2id verification
  const targetBits = parseInt(env.TARGET_ZERO_BITS ?? "22", 10);
  const memoryKib = parseInt(env.TARGET_MEMORY_KIB ?? "65536", 10);

  const fingerprintBytes = fromHex(fingerprint_hash);
  const nonceBytes = fromHex(nonce);       // 16 bytes
  const counterBytes = fromHex(counter);   // 8 bytes
  const salt = new Uint8Array(24);
  salt.set(nonceBytes, 0);
  salt.set(counterBytes, 16);

  let hashOutput: Uint8Array;
  try {
    hashOutput = argon2id(fingerprintBytes, salt, {
      t: 1,
      m: memoryKib,
      p: 1,
      dkLen: 32,
    });
  } catch {
    return new Response(
      JSON.stringify({ error: "pow_computation_failed" }),
      { status: 500, headers: { "content-type": "application/json" } },
    );
  }

  // 4. Check leading zero bits
  if (countLeadingZeroBits(hashOutput) < targetBits) {
    return new Response(
      JSON.stringify({ error: "pow_insufficient" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  // 5. Rate-limit check (10/24h per /24 for /v1/enroll)
  const ip24 = getIp24(request);
  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const rlResp = await stub.fetch("https://auth-store/rate-limit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ip24, endpoint: "enroll", max: 10 }),
  });
  if (!rlResp.ok) {
    return new Response(
      JSON.stringify({ error: "rate_limited", retry_after: 86400 }),
      { status: 429, headers: { "content-type": "application/json" } },
    );
  }

  // 6. Issue or retrieve token from AuthStoreDO
  const issueResp = await stub.fetch("https://auth-store/issue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ fingerprint_hash, client_version }),
  });
  const record = (await issueResp.json()) as AuthRecord;

  // 7. Return 201 (new) or 200 (existing)
  return new Response(JSON.stringify(record), {
    status: issueResp.status,
    headers: { "content-type": "application/json" },
  });
}
