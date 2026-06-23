/**
 * Integration probes for the generalized BYOK leg (POST /byok/<seg>/...).
 *
 * Per-segment probes scale with the SEGMENTS table (20 segs after W38-S966):
 *   byok fail-closed    ×N   (no X-Bishop-Upstream-Key → 400 byok_key_missing, one per seg)
 *   managed-forwarded   ×N   (bearer: mock sees Bearer op-<seg>-zzz)
 *   Pillar-1 no-leak    ×1   (response headers carry no credential)
 *   unknown-provider    ×1   (POST /byok/unknown-xyz/... → 404 unknown_provider)
 *   allowlist-coverage  ×1   (every BYOK upstreamHost + regionHosts value in ALLOWED_OUTBOUND_HOSTS)
 *   region-selection    ×3   (W38-S966 resolveByokUpstreamHost: single/dual/fallback)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { ALLOWED_OUTBOUND_HOSTS } from "../src/lib/outbound-allowlist";
import { BYOK_UPSTREAM_SPECS, resolveByokUpstreamHost } from "../src/lib/byok-specs";
import { clearAuthRateLimits } from "./helpers/clear-auth-rate-limits";

const PROXY_VARS_BASE = {
  STRIPE_WEBHOOK_SECRET: "test_secret",
  ANTHROPIC_API_KEY: "test_key",
  TARGET_ZERO_BITS: "8",
  TARGET_MEMORY_KIB: "8",
  CHALLENGE_TTL: "60",
  MOCK_AI: "1",
};

const TEST_VERSION = "test-client-0.1.0";

interface Segment {
  seg: string;
  keyVar: string;
  opKey: string;
  path: string;
}

const SEGMENTS: Segment[] = [
  { seg: "grok",        keyVar: "XAI_API_KEY",        opKey: "op-grok-zzz",        path: "/byok/grok/v1/chat/completions"                     },
  { seg: "mistral",     keyVar: "MISTRAL_API_KEY",     opKey: "op-mistral-zzz",     path: "/byok/mistral/v1/chat/completions"                   },
  { seg: "deepseek",    keyVar: "DEEPSEEK_API_KEY",    opKey: "op-deepseek-zzz",    path: "/byok/deepseek/v1/chat/completions"                  },
  { seg: "minimax",     keyVar: "MINIMAX_API_KEY",     opKey: "op-minimax-zzz",     path: "/byok/minimax/v1/text/chatcompletion_v2"             },
  { seg: "zhipu",       keyVar: "ZHIPU_API_KEY",       opKey: "op-zhipu-zzz",       path: "/byok/zhipu/api/paas/v4/chat/completions"            },
  { seg: "perplexity",  keyVar: "PERPLEXITY_API_KEY",  opKey: "op-perplexity-zzz",  path: "/byok/perplexity/v1/chat/completions"                },
  { seg: "cohere",      keyVar: "COHERE_API_KEY",      opKey: "op-cohere-zzz",      path: "/byok/cohere/v1/chat"                                },
  { seg: "moonshot",    keyVar: "MOONSHOT_API_KEY",    opKey: "op-moonshot-zzz",    path: "/byok/moonshot/v1/chat/completions"                  },
  { seg: "openrouter",  keyVar: "OPENROUTER_API_KEY",  opKey: "op-openrouter-zzz",  path: "/byok/openrouter/api/v1/chat/completions"            },
  { seg: "vercel",      keyVar: "VERCEL_API_KEY",      opKey: "op-vercel-zzz",      path: "/byok/vercel/v1/chat/completions"                    },
  { seg: "huggingface", keyVar: "HUGGINGFACE_API_KEY", opKey: "op-huggingface-zzz", path: "/byok/huggingface/v1/chat/completions"               },
  { seg: "groq",        keyVar: "GROQ_API_KEY",        opKey: "op-groq-zzz",        path: "/byok/groq/openai/v1/chat/completions"               },
  { seg: "together",    keyVar: "TOGETHER_API_KEY",    opKey: "op-together-zzz",    path: "/byok/together/v1/chat/completions"                  },
  { seg: "fireworks",   keyVar: "FIREWORKS_API_KEY",   opKey: "op-fireworks-zzz",   path: "/byok/fireworks/inference/v1/chat/completions"       },
  // W38-S964 — Sakana Fugu (cloud-only, OpenAI-compatible). Exercises the new
  // /byok/sakana/ leg: fail-closed without an upstream key + operator-key forward.
  { seg: "sakana",      keyVar: "SAKANA_API_KEY",      opKey: "op-sakana-zzz",      path: "/byok/sakana/v1/chat/completions"                    },
  // W38-S966 — 6 OpenAI-compatible open-weights-serving clouds. Each exercises its
  // new /byok/<seg>/ leg (fail-closed + operator-forward). Meta uses /compat/v1/;
  // DeepInfra /v1/openai/. The SiliconFlow per-connection region selection is unit-
  // tested separately (the base-URL test-override masks it in the live harness).
  { seg: "meta_llama",   keyVar: "META_LLAMA_API_KEY",   opKey: "op-meta_llama-zzz",   path: "/byok/meta_llama/compat/v1/chat/completions"     },
  { seg: "deepinfra",    keyVar: "DEEPINFRA_API_KEY",    opKey: "op-deepinfra-zzz",    path: "/byok/deepinfra/v1/openai/chat/completions"      },
  { seg: "baseten",      keyVar: "BASETEN_API_KEY",      opKey: "op-baseten-zzz",      path: "/byok/baseten/v1/chat/completions"               },
  { seg: "inference_net", keyVar: "INFERENCE_NET_API_KEY", opKey: "op-inference_net-zzz", path: "/byok/inference_net/v1/chat/completions"      },
  { seg: "siliconflow",  keyVar: "SILICONFLOW_API_KEY",  opKey: "op-siliconflow-zzz",  path: "/byok/siliconflow/v1/chat/completions"           },
  { seg: "featherless",  keyVar: "FEATHERLESS_API_KEY",  opKey: "op-featherless-zzz",  path: "/byok/featherless/v1/chat/completions"           },
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

describe("BYOK legs (/byok/<seg>/...)", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let managedToken: string;
  let byokToken: string;

  const operatorVars = Object.fromEntries(
    SEGMENTS.map((s) => [s.keyVar, s.opKey]),
  );

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-openai-compat.ts", {
      config: "test/wrangler.mock.toml",
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      persist: false,
    });
    mockUrl = `http://${mock.address}:${mock.port}`;

    const byokBaseUrls = Object.fromEntries(
      SEGMENTS.map((s) => [s.keyVar.replace("_API_KEY", "_BASE_URL"), mockUrl]),
    );

    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: {
        ...PROXY_VARS_BASE,
        ADMIN_TOKEN: "test_admin",
        ...operatorVars,
        ...byokBaseUrls,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
      },
      persist: false,
    });

    // Self-isolate against the serial suite's shared on-disk AuthStoreDO:
    // clear BOTH the challenge nonce + enroll rate-limit counters.
    await clearAuthRateLimits(worker);

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

  // ---- byok fail-closed ×14 ----

  for (const { seg, path } of SEGMENTS) {
    it(`${seg}: byok without X-Bishop-Upstream-Key → 400 byok_key_missing`, async () => {
      const res = await worker.fetch(path, {
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

  // ---- managed: operator key forwarded ×14 (all bearer) ----

  for (const { seg, path, opKey } of SEGMENTS) {
    it(`${seg}: managed → mock sees Bearer ${opKey}`, async () => {
      const res = await worker.fetch(path, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${managedToken}`,
          "x-bishop-upstream-key": "should-be-ignored",
        },
        body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
      });
      expect(res.status).toBe(200);
      const lastAuthRes = await mock.fetch(mockUrl + "/__last_auth");
      const { auth } = (await lastAuthRes.json()) as { auth: string | null };
      expect(auth).toBe(`Bearer ${opKey}`);
    }, 30000);
  }

  // ---- Pillar-1: response headers carry no credential leak ----

  it("Pillar-1: managed 200 response headers carry no auth leak; content-type forwarded", async () => {
    const res = await worker.fetch("/byok/mistral/v1/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.has("authorization")).toBe(false);
    expect(res.headers.has("x-bishop-upstream-key")).toBe(false);
    expect(res.headers.has("x-api-key")).toBe(false);
    expect(res.headers.has("operator-key")).toBe(false);
    expect(res.headers.get("content-type")).toBe("application/json");
  }, 30000);

  // ---- unknown-provider 404 ----

  it("unknown-provider: POST /byok/unknown-xyz/v1/chat → 404 unknown_provider", async () => {
    const res = await worker.fetch("/byok/unknown-xyz/v1/chat", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${managedToken}`,
      },
      body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unknown_provider");
  }, 30000);

  // ---- allowlist-coverage ----

  it("allowlist-coverage: all BYOK upstreamHost values are in ALLOWED_OUTBOUND_HOSTS", () => {
    const allowedSet = new Set<string>(ALLOWED_OUTBOUND_HOSTS as readonly string[]);
    for (const [seg, spec] of Object.entries(BYOK_UPSTREAM_SPECS)) {
      expect(allowedSet.has(spec.upstreamHost),
        `seg=${seg} upstreamHost=${spec.upstreamHost} not in ALLOWED_OUTBOUND_HOSTS`
      ).toBe(true);
      // W38-S966 — every enumerated region host (SiliconFlow .com/.cn) must ALSO be
      // allowlisted, so the per-connection selector can never pick an off-allowlist host.
      for (const [region, host] of Object.entries(spec.regionHosts ?? {})) {
        expect(allowedSet.has(host),
          `seg=${seg} region=${region} host=${host} not in ALLOWED_OUTBOUND_HOSTS`
        ).toBe(true);
      }
    }
  });
});

// ── W38-S966 — SiliconFlow dual-region host selection (resolveByokUpstreamHost) ──
// The live worker harness overrides the base URL (SILICONFLOW_BASE_URL → mock), so
// the region→host mapping is exercised directly against the pure resolver.
describe("resolveByokUpstreamHost (W38-S966 multi-region)", () => {
  const single = BYOK_UPSTREAM_SPECS.featherless;       // no regionHosts
  const dual = BYOK_UPSTREAM_SPECS.siliconflow;          // regionHosts {com,cn}

  it("single-region leg ignores the region token", () => {
    for (const r of [null, "", "cn", "anything", "evil.example.com"]) {
      expect(resolveByokUpstreamHost(single, r)).toBe(single.upstreamHost);
    }
  });

  it("dual-region leg selects the enumerated host by the constrained token", () => {
    expect(resolveByokUpstreamHost(dual, "com")).toBe("api.siliconflow.com");
    expect(resolveByokUpstreamHost(dual, "cn")).toBe("api.siliconflow.cn");
    // case-insensitive + whitespace-tolerant
    expect(resolveByokUpstreamHost(dual, "  CN ")).toBe("api.siliconflow.cn");
  });

  it("an unknown/absent region falls back to the primary (.com), never an injected host", () => {
    for (const bad of [null, undefined, "", "ap", "us-west", "api.evil.cn", "../x"]) {
      expect(resolveByokUpstreamHost(dual, bad)).toBe(dual.upstreamHost);
    }
    // the resolved host is ALWAYS one of the spec's enumerated (allowlisted) hosts
    const enumerated = new Set(Object.values(dual.regionHosts ?? {}));
    for (const probe of ["com", "cn", "garbage", null]) {
      expect(enumerated.has(resolveByokUpstreamHost(dual, probe))).toBe(true);
    }
  });
});
