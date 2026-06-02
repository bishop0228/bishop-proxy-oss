#!/usr/bin/env node
/**
 * scripts/dev-mint-token.mjs — DEV-ONLY device-token minter (W38-S729).
 *
 * NOT production code. NEVER imported by src/ (the worker). Its sole purpose is
 * the founder-run MCP live smoke (docs/MCP_LIVE_SMOKE.md): mint a real device
 * token against a LOCAL `wrangler dev` proxy so a `/mcp/github` JSON-RPC call can
 * be driven by hand. It speaks the live /v1/challenge + /v1/enroll routes exactly
 * as written (src/routes/challenge.ts, src/routes/enroll.ts) — it does NOT
 * re-implement or guess their shapes.
 *
 * Flow (mirrors enroll.ts):
 *   1. GET  /v1/challenge            → { nonce (32 hex), expires_at, difficulty }
 *   2. mine an 8-byte counter so argon2id(fingerprint, nonce16||counter8,
 *      {t:1, m, p:1, dkLen:32}) has >= `difficulty` leading zero bits
 *      (params identical to enroll.ts:140-145).
 *   3. POST /v1/enroll { nonce, counter, fingerprint_hash, client_version }
 *   4. print the returned AuthRecord JSON to STDOUT (so `| jq -r .token` works);
 *      all diagnostics go to STDERR.
 *
 * Flags:
 *   --url   proxy base URL           (default http://127.0.0.1:8787)
 *   --bits  target PoW zero-bits     (default 8; auto-tracks the live challenge
 *                                     `difficulty` unless explicitly passed)
 *   --mem   argon2id memory in KiB   (default 65536 = enroll.ts TARGET_MEMORY_KIB
 *                                     default; MUST match the proxy's
 *                                     TARGET_MEMORY_KIB if you override it)
 *
 * argon2id: m=65536 KiB is ~0.75s/hash here, so 8 bits (1/256) averages ~1-3 min.
 * To go faster, lower BOTH sides together: set TARGET_MEMORY_KIB in .dev.vars and
 * pass the same value via --mem (the salt content is unchanged, only cost drops).
 */

import { argon2id } from "@noble/hashes/argon2.js";
import { Buffer } from "node:buffer";

// ── arg parsing ────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const out = { url: "http://127.0.0.1:8787", bits: 8, bitsExplicit: false, mem: 65536 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--url") out.url = argv[++i];
    else if (a === "--bits") { out.bits = parseInt(argv[++i], 10); out.bitsExplicit = true; }
    else if (a === "--mem") out.mem = parseInt(argv[++i], 10);
    else if (a === "--help" || a === "-h") { printUsage(); process.exit(0); }
    else { log(`unknown flag: ${a}`); printUsage(); process.exit(2); }
  }
  return out;
}

function printUsage() {
  log("usage: node scripts/dev-mint-token.mjs [--url http://127.0.0.1:8787] [--bits 8] [--mem 65536]");
}

// ── helpers ────────────────────────────────────────────────────────────────
const log = (...m) => process.stderr.write(m.join(" ") + "\n");

function fromHex(hex) {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

// 8-byte big-endian counter → 16 hex chars (the enroll `counter` field shape).
function counterHex(n) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(n));
  return buf.toString("hex");
}

// Identical to enroll.ts countLeadingZeroBits.
function countLeadingZeroBits(bytes) {
  let count = 0;
  for (const byte of bytes) {
    if (byte === 0) { count += 8; }
    else { count += Math.clz32(byte) - 24; break; }
  }
  return count;
}

function halt(msg) {
  log(`HALT — ${msg}`);
  log("(challenge/enroll route shapes diverged from this script's assumptions; do NOT guess — re-author against the live routes.)");
  process.exit(1);
}

// ── main ───────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const base = args.url.replace(/\/+$/, "");

  // 1. GET /v1/challenge
  log(`→ GET ${base}/v1/challenge`);
  let chalResp;
  try {
    chalResp = await fetch(`${base}/v1/challenge`, { method: "GET" });
  } catch (e) {
    halt(`could not reach the proxy at ${base} — is \`wrangler dev\` up? (${e.message})`);
  }
  if (!chalResp.ok) {
    const body = await chalResp.text().catch(() => "");
    halt(`/v1/challenge returned ${chalResp.status} ${body}`);
  }
  const chal = await chalResp.json();
  if (typeof chal.nonce !== "string" || !/^[0-9a-f]{32}$/i.test(chal.nonce)) {
    halt(`/v1/challenge response has no 32-hex \`nonce\` field (got: ${JSON.stringify(chal)})`);
  }
  const nonce = chal.nonce;

  // bits: track the live challenge `difficulty` unless --bits was passed.
  let bits = args.bits;
  if (!args.bitsExplicit && Number.isInteger(chal.difficulty)) {
    bits = chal.difficulty;
    log(`  using challenge difficulty = ${bits} bits (pass --bits to override)`);
  } else {
    log(`  target = ${bits} bits` + (Number.isInteger(chal.difficulty) && chal.difficulty !== bits
      ? `  (WARNING: live challenge difficulty is ${chal.difficulty}; enroll will reject a mismatch)` : ""));
  }
  log(`  nonce = ${nonce}`);

  // 2. mine the counter — argon2id(fingerprint, nonce16||counter8, {t,m,p,dkLen}).
  const fingerprintHex = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"); // 64 hex
  const fingerprintBytes = fromHex(fingerprintHex);
  const nonceBytes = fromHex(nonce); // 16 bytes
  log(`  mining PoW (m=${args.mem} KiB, ~0.75s/hash at 64MiB) ...`);

  let counter = -1;
  let counterHexStr = "";
  const t0 = Date.now();
  for (let n = 0; ; n++) {
    counterHexStr = counterHex(n);
    const counterBytes = fromHex(counterHexStr); // 8 bytes
    const salt = new Uint8Array(24);
    salt.set(nonceBytes, 0);
    salt.set(counterBytes, 16);
    const out = argon2id(fingerprintBytes, salt, { t: 1, m: args.mem, p: 1, dkLen: 32 });
    if (countLeadingZeroBits(out) >= bits) { counter = n; break; }
    if (n > 0 && n % 64 === 0) log(`    ... ${n} attempts (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  }
  log(`  solved: counter=${counterHexStr} after ${counter + 1} attempts (${((Date.now() - t0) / 1000).toFixed(0)}s)`);

  // 3. POST /v1/enroll
  const enrollBody = {
    nonce,
    counter: counterHexStr,
    fingerprint_hash: fingerprintHex,
    client_version: "bishop-dev-mint/1",
  };
  log(`→ POST ${base}/v1/enroll`);
  const enrollResp = await fetch(`${base}/v1/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(enrollBody),
  });
  const record = await enrollResp.json().catch(() => null);
  if (!enrollResp.ok) {
    halt(`/v1/enroll returned ${enrollResp.status}: ${JSON.stringify(record)}`);
  }
  if (!record || typeof record.token !== "string") {
    halt(`/v1/enroll succeeded (${enrollResp.status}) but response has no \`token\` field: ${JSON.stringify(record)}`);
  }
  log(`✓ enrolled (HTTP ${enrollResp.status}), token_id=${record.token_id}`);

  // 4. AuthRecord JSON → STDOUT (clean, for `| jq -r .token`).
  process.stdout.write(JSON.stringify(record) + "\n");
}

main().catch((e) => {
  log(`error: ${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
