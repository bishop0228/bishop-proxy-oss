/**
 * Integration probes for the OAuth subscription legs.
 *
 * 26 probes total:
 *   token-forward             ×5  (one per seg: POST /oauth/<seg>/token → 200 + access_token)
 *   token auth-required       ×1  (no bearer → 401 missing_bearer)
 *   token unknown-provider    ×1  (unknown seg → 404 unknown_provider)
 *   completion byok fail-closed ×5 (no X-Bishop-Upstream-Key → 400 byok_key_missing)
 *   completion managed fail-closed ×5 (THE never-operator-fallback proof: managedToken → 400 managed_key_unavailable)
 *   completion byok-forward   ×5  (byokToken + upstream-key → 200; mock sees Bearer user-oauth-token-<seg>)
 *   qwen extra-header         ×1  (qwen_alibaba byok-forward → mock sees X-DashScope-AuthType: qwen-oauth)
 *   Pillar-1 no-leak          ×1  (200 response headers carry no credential; content-type forwarded)
 *   completion unknown-seg    ×1  (POST /v1/unknown-xyz/... → 404 not_found; dispatch boundary)
 *   allowlist-coverage        ×1  (all spec.tokenHost + spec.completionHost ∈ ALLOWED_OUTBOUND_HOSTS)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { ALLOWED_OUTBOUND_HOSTS } from "../src/lib/outbound-allowlist";
import { OAUTH_UPSTREAM_SPECS } from "../src/lib/oauth-specs";

const PROXY_VARS_BASE = {
  STRIPE_WEBHOOK_SECRET: "test_secret",
  ANTHROPIC_API_KEY: "test_key",
  TARGET_ZERO_BITS: "8",
  TARGET_MEMORY_KIB: "8",
  CHALLENGE_TTL: "60",
  MOCK_AI: "1",
};

const TEST_VERSION = "test-client-0.1.0";

interface OAuthSegment {
  seg: string;
  completionPath: string;
  tokenPath: string;
}

const OAUTH_SEGMENTS: OAuthSegment[] = [
  { seg: "openai_codex",   completionPath: "/backend-api/codex/responses",          tokenPath: "/oauth/token"              },
  { seg: "xai_grok",       completionPath: "/v1/chat/completions",                   tokenPath: "/oauth/token"              },
  { seg: "github_copilot", completionPath: "/chat/completions",                      tokenPath: "/login/oauth/access_token" },
  { seg: "qwen_alibaba",   completionPath: "/compatible-mode/v1/chat/completions",   tokenPath: "/api/v1/oauth2/token"      },
  { seg: "nous_portal",    completionPath: "/v1/chat/completions",                   tokenPath: "/oauth/token"              },
];

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

describe("OAuth legs (/oauth/<seg>/token + /v1/<seg>/...)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let managedToken: string;
  let byokToken: string;

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-oauth-upstream.ts", {
      config: "test/wrangler.mock.toml",
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      persist: false,
    });
    mockUrl = `http://${mock.address}:${mock.port}`;

    // All 10 base-URL env vars point to the mock server.
    const oauthBaseUrls = Object.fromEntries(
      OAUTH_SEGMENTS.flatMap((s) => {
        const upper = s.seg.toUpperCase();
        return [
          [`${upper}_TOKEN_BASE_URL`, mockUrl],
          [`${upper}_COMPLETION_BASE_URL`, mockUrl],
        ];
      }),
    );

    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: {
        ...PROXY_VARS_BASE,
        ADMIN_TOKEN: "test_admin",
        ...oauthBaseUrls,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
      },
      persist: false,
    });

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

    const clearEnrollRes = await worker.fetch("/admin/rate-limit/clear", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": "test_admin" },
      body: JSON.stringify({ ip_prefix: "127.0.0", endpoint: "enroll", date: today }),
    });
    if (!clearEnrollRes.ok) {
      const errBody = await clearEnrollRes.text();
      throw new Error(`enroll rate-limit clear failed: ${clearEnrollRes.status} ${errBody}`);
    }
    await clearEnrollRes.json();

    managedToken = await enroll(worker, "6".repeat(64));
    byokToken = await enroll(worker, "5".repeat(64), "byok");
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(mockUrl + "/__reset", { method: "POST" });
  });

  // ---- token-forward ×5 ----

  for (const { seg, tokenPath } of OAUTH_SEGMENTS) {
    it(`${seg}: token-forward → 200, access_token present, body forwarded`, async () => {
      const grantBody = `grant_type=authorization_code&code=test-code-${seg}`;
      const res = await worker.fetch(`/oauth/${seg}/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Bearer ${byokToken}`,
        },
        body: grantBody,
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { access_token?: string };
      expect(json.access_token).toBe("upstream-minted-xyz");

      // Verify grant body was forwarded unmodified.
      const lastBodyRes = await mock.fetch(mockUrl + "/__last_body");
      const { body } = (await lastBodyRes.json()) as { body: string | null };
      expect(body).toBe(grantBody);
      void tokenPath; // seg.tokenPath is the upstream path; proxy routes via spec
    }, 30000);
  }

  // ---- token auth-required ×1 ----

  it("token auth-required: no bearer → 401 missing_bearer", async () => {
    const res = await worker.fetch("/oauth/openai_codex/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=test",
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("missing_bearer");
  }, 30000);

  // ---- token unknown-provider ×1 ----

  it("token unknown-provider: POST /oauth/unknown-xyz/token → 404 unknown_provider", async () => {
    const res = await worker.fetch("/oauth/unknown-xyz/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${byokToken}`,
      },
      body: "grant_type=authorization_code&code=test",
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unknown_provider");
  }, 30000);

  // ---- completion byok fail-closed ×5 ----

  for (const { seg } of OAUTH_SEGMENTS) {
    it(`${seg}: byok without X-Bishop-Upstream-Key → 400 byok_key_missing`, async () => {
      const res = await worker.fetch(`/v1/${seg}/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${byokToken}`,
        },
        body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("byok_key_missing");
    }, 30000);
  }

  // ---- completion managed fail-closed ×5 (THE never-operator-fallback proof) ----

  for (const { seg } of OAUTH_SEGMENTS) {
    it(`${seg}: managed + upstream-key should-be-ignored → 400 managed_key_unavailable`, async () => {
      const res = await worker.fetch(`/v1/${seg}/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${managedToken}`,
          "x-bishop-upstream-key": "should-be-ignored",
        },
        body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("managed_key_unavailable");
    }, 30000);
  }

  // ---- completion byok-forward ×5 ----

  for (const { seg } of OAUTH_SEGMENTS) {
    it(`${seg}: byok-forward → 200; mock sees Bearer user-oauth-token-${seg}`, async () => {
      const res = await worker.fetch(`/v1/${seg}/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${byokToken}`,
          "x-bishop-upstream-key": `user-oauth-token-${seg}`,
        },
        body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
      });
      expect(res.status).toBe(200);
      const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
      const { auth } = (await lastAuthRes.json()) as { auth: string | null };
      expect(auth).toBe(`Bearer user-oauth-token-${seg}`);
    }, 30000);
  }

  // ---- qwen extra-header ×1 ----

  it("qwen_alibaba byok-forward: mock sees X-DashScope-AuthType: qwen-oauth", async () => {
    const res = await worker.fetch("/v1/qwen_alibaba/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": "user-oauth-token-qwen_alibaba",
      },
      body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    const lastHeadersRes = await mock.fetch(mockUrl + "/__last_headers");
    const { authType } = (await lastHeadersRes.json()) as { authType: string | null };
    expect(authType).toBe("qwen-oauth");
  }, 30000);

  // ---- Pillar-1 no-leak ×1 ----

  it("Pillar-1: byok-forward 200 response headers carry no credential; content-type forwarded", async () => {
    const res = await worker.fetch("/v1/nous_portal/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
        "x-bishop-upstream-key": "user-oauth-token-nous_portal",
      },
      body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.has("authorization")).toBe(false);
    expect(res.headers.has("x-bishop-upstream-key")).toBe(false);
    expect(res.headers.has("x-api-key")).toBe(false);
    expect(res.headers.get("content-type")).toBe("application/json");
  }, 30000);

  // ---- completion unknown-seg ×1 ----

  it("completion unknown-seg: POST /v1/unknown-xyz/responses → 404 not_found (dispatch boundary)", async () => {
    const res = await worker.fetch("/v1/unknown-xyz/responses", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${byokToken}`,
      },
      body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("not_found");
  }, 30000);

  // ---- allowlist-coverage ×1 ----

  it("allowlist-coverage: all spec.tokenHost + spec.completionHost in ALLOWED_OUTBOUND_HOSTS", () => {
    const allowedSet = new Set<string>(ALLOWED_OUTBOUND_HOSTS as readonly string[]);
    for (const [seg, spec] of Object.entries(OAUTH_UPSTREAM_SPECS)) {
      expect(
        allowedSet.has(spec.tokenHost),
        `seg=${seg} tokenHost=${spec.tokenHost} not in ALLOWED_OUTBOUND_HOSTS`,
      ).toBe(true);
      expect(
        allowedSet.has(spec.completionHost),
        `seg=${seg} completionHost=${spec.completionHost} not in ALLOWED_OUTBOUND_HOSTS`,
      ).toBe(true);
    }
  });
});
