/**
 * Interceptor-level floor-change guards for §1.17.18/§1.17.19 (ENTERPRISE_HOST_PATTERNS)
 * and §H-DYNAMIC 2026-05-30 (5 new BYOK upstream hosts) + W38-S731 Block 4
 * (42 remote MCP egress hosts) + W38-S736 (+2 fixed-host MCP egress, length 74→76)
 * + B1 (+1 model-registry egress host registry.ollama.ai, length 76→77).
 *
 * §1.17.18 Azure guards:
 *   (8a) myresource.openai.azure.com NOT rejected post-install (resolves via mock prior)
 *   (8b) evil.com + suffix-bypass host rejected with OutboundHostNotAllowed
 *   (8c) ALLOWED_OUTBOUND_HOSTS.length === 80 — 32 provider + 44 MCP + 1 model-registry + 3 S6b worker-egress
 *
 * §1.17.19 Vertex guards:
 *   (9a) us-central1-aiplatform.googleapis.com accepted (isAnchoredEnterpriseHost)
 *   (9b) suffix-spoof rejected; oauth2.googleapis.com sibling rejected
 *   (9c) ALLOWED_OUTBOUND_HOSTS.length === 80 — 32 provider + 44 MCP + 1 model-registry + 3 S6b worker-egress
 *
 * §H-DYNAMIC BYOK expansion guards (founder-signed-off 2026-05-30):
 *   (10a) Each of 5 new hosts is in ALLOWED_OUTBOUND_HOSTS
 *   (10b) Attacker-variant of each new host rejected (suffix-spoof still blocked)
 *   (10c) Drop-a-host mutation: _setAllowlistForTesting without the host → request blocked
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  installFetchAllowlist,
  _resetForTesting,
  _setAllowlistForTesting,
  ALLOWED_OUTBOUND_HOSTS,
  OutboundHostNotAllowed,
  isAnchoredEnterpriseHost,
} from "../src/lib/outbound-allowlist";

type G = { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> };

const NEW_BYOK_HOSTS = [
  "api.cerebras.ai",
  "integrate.api.nvidia.com",
  "gateway.ai.cloudflare.com",
  "api.hunyuan.cloud.tencent.com",
  "ark.cn-beijing.volces.com",
] as const;

describe("outbound-allowlist: §1.17.18 enterprise-host floor guards", () => {
  const originalFetch = (globalThis as unknown as G).fetch;

  beforeEach(() => {
    _resetForTesting();
  });

  afterEach(() => {
    _resetForTesting();
    (globalThis as unknown as G).fetch = originalFetch;
  });

  // ── Guard 8a ─────────────────────────────────────────────────────────────

  it("8a: myresource.openai.azure.com not rejected post-install (enterprise floor resolves)", async () => {
    const mockPrior = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    (globalThis as unknown as G).fetch = mockPrior as unknown as G["fetch"];
    installFetchAllowlist();

    const res = await (globalThis as unknown as G).fetch(
      "https://myresource.openai.azure.com/openai/deployments/gpt-4/chat/completions",
    );
    expect(res.status).toBe(200);
    expect(mockPrior).toHaveBeenCalledOnce();
  });

  // ── Guard 8b ─────────────────────────────────────────────────────────────

  it("8b: evil.com and suffix-bypass host rejected with OutboundHostNotAllowed", async () => {
    installFetchAllowlist();

    await expect(
      (globalThis as unknown as G).fetch("https://evil.com/steal"),
    ).rejects.toThrow(OutboundHostNotAllowed);

    await expect(
      (globalThis as unknown as G).fetch("https://foo.openai.azure.com.attacker.com/path"),
    ).rejects.toThrow(OutboundHostNotAllowed);
  });

  // ── Guard 8c ─────────────────────────────────────────────────────────────

  it("8c: ALLOWED_OUTBOUND_HOSTS.length === 89 — 40 provider + 44 MCP + 1 model-registry + 3 S6b worker-egress + 1 HF (W38-S966 +7)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(89);
  });

  it("8d: oauth2.googleapis.com is in ALLOWED_OUTBOUND_HOSTS (§1.17.19 exact-match add)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("oauth2.googleapis.com");
  });

  // ── §1.17.19 Vertex AI floor guards ──────────────────────────────────────

  it("9a: us-central1-aiplatform.googleapis.com accepted (Vertex floor pattern)", () => {
    expect(isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com")).toBe(true);
  });

  it("9b: suffix-spoof and oauth2.googleapis.com sibling rejected (floor not widened)", () => {
    // Suffix-spoof: trailing attacker domain must not pass.
    expect(isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com.attacker.com")).toBe(false);
    // Sibling service: proves floor did NOT widen to bare *.googleapis.com.
    expect(isAnchoredEnterpriseHost("oauth2.googleapis.com")).toBe(false);
  });

  it("9c: ALLOWED_OUTBOUND_HOSTS.length === 89 — 40 provider + 44 MCP + 1 model-registry + 3 S6b worker-egress + 1 HF (exact-match; W38-S966 +7)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(89);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// W38-S868 §9.3.8c — governed HuggingFace BYO-model egress guards.
//
// `huggingface.co` is the +1 frozen exact-match host (length 80→81); its
// LFS/Xet download CDN is the anchored HUGGINGFACE_CDN_HOST_PATTERN (NOT an
// exact-match — it adds nothing to the length). The interceptor backstop must
// admit huggingface.co + a valid .hf.co CDN host and reject every suffix-spoof.
// ─────────────────────────────────────────────────────────────────────────────

describe("outbound-allowlist: W38-S868 §9.3.8c HuggingFace BYO-model guards", () => {
  it("12a: huggingface.co is in ALLOWED_OUTBOUND_HOSTS (frozen exact-match host)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("huggingface.co");
  });

  it("12b: a valid HF LFS/Xet CDN host (.hf.co) is admitted by isAnchoredEnterpriseHost", () => {
    expect(isAnchoredEnterpriseHost("cdn-lfs-us-1.hf.co")).toBe(true);
    expect(isAnchoredEnterpriseHost("cas-bridge.xethub.hf.co")).toBe(true);
  });

  it("12c: the HF CDN pattern is a CDN-domain floor — NOT broadened off .hf.co", () => {
    // Suffix-spoof: trailing attacker domain must not pass.
    expect(isAnchoredEnterpriseHost("cdn-lfs-us-1.hf.co.attacker.com")).toBe(false);
    // Bare CDN domain (no subdomain label) is not a real CDN host and is rejected.
    expect(isAnchoredEnterpriseHost("hf.co")).toBe(false);
    // The CDN pattern must NOT admit arbitrary huggingface.co subdomains.
    expect(isAnchoredEnterpriseHost("api.huggingface.co")).toBe(false);
  });

  it("12d: the HF CDN host is NOT an exact-allowlist entry (length stays 89 = pattern-only)", () => {
    expect((ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes("cdn-lfs-us-1.hf.co")).toBe(false);
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(89);
  });
});

describe("outbound-allowlist: §H-DYNAMIC BYOK expansion guards (2026-05-30)", () => {
  const originalFetch = (globalThis as unknown as G).fetch;

  beforeEach(() => {
    _resetForTesting();
  });

  afterEach(() => {
    _resetForTesting();
    (globalThis as unknown as G).fetch = originalFetch;
  });

  // ── Guard 10a — each new host is allowlisted ──────────────────────────────

  for (const host of NEW_BYOK_HOSTS) {
    it(`10a: ${host} is in ALLOWED_OUTBOUND_HOSTS`, () => {
      expect(ALLOWED_OUTBOUND_HOSTS).toContain(host);
    });
  }

  // ── Guard 10b — attacker-variant of each new host rejected ───────────────

  for (const host of NEW_BYOK_HOSTS) {
    it(`10b: ${host}.attacker.com suffix-spoof rejected`, async () => {
      installFetchAllowlist();
      await expect(
        (globalThis as unknown as G).fetch(`https://${host}.attacker.com/steal`),
      ).rejects.toThrow(OutboundHostNotAllowed);
    });
  }

  // ── Guard 10c — drop-a-host mutation: request blocked without the host ───

  for (const host of NEW_BYOK_HOSTS) {
    it(`10c: drop ${host} from allowlist → fetch to that host blocked`, async () => {
      // Build allowlist without the target host
      const truncated = (ALLOWED_OUTBOUND_HOSTS as readonly string[]).filter((h) => h !== host);
      _setAllowlistForTesting(truncated);
      installFetchAllowlist();
      await expect(
        (globalThis as unknown as G).fetch(`https://${host}/v1/chat/completions`),
      ).rejects.toThrow(OutboundHostNotAllowed);
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// W38-S735 — per-account remote MCP enterprise-host pattern guards.
//
// The 4 per-account MCP vendor host shapes are anchored ENTERPRISE_HOST_PATTERNS
// conjuncts (NOT exact-allowlist entries — they add nothing to the exact length;
// the length is 77 after B1's +1 model-registry exact-match add). The interceptor
// backstop must admit a valid per-account host and reject every suffix-spoof.
// (The /mcp route's spec-bound check — that a snowflake spec admits ONLY a
// snowflake host — is exercised in mcp.test.ts.)
// ─────────────────────────────────────────────────────────────────────────────

describe("outbound-allowlist: W38-S735 per-account MCP host pattern guards", () => {
  const ENTERPRISE_OK = [
    "acme-marketing.snowflakecomputing.com",
    "1234567.suitetalk.api.netsuite.com",
    "acme-store.myshopify.com",
    "dbc-a1b2c3d4-e5f6.cloud.databricks.com",
    "adb-984752964297111.11.azuredatabricks.net",
    "1234567890123456.7.gcp.databricks.com",
  ] as const;

  for (const host of ENTERPRISE_OK) {
    it(`11a: ${host} accepted by isAnchoredEnterpriseHost`, () => {
      expect(isAnchoredEnterpriseHost(host)).toBe(true);
    });
  }

  for (const host of ENTERPRISE_OK) {
    it(`11b: ${host}.attacker.com suffix-spoof rejected`, () => {
      expect(isAnchoredEnterpriseHost(`${host}.attacker.com`)).toBe(false);
    });
  }

  it("11c: the per-account hosts are NOT added to ALLOWED_OUTBOUND_HOSTS (length 89 = exact-match only)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(89);
    for (const host of ENTERPRISE_OK) {
      expect((ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(host)).toBe(false);
    }
  });

  it("11d: a bare-domain spoof of each vendor (no per-account label) is rejected", () => {
    for (const bare of [
      "snowflakecomputing.com",
      "suitetalk.api.netsuite.com",
      "myshopify.com",
      "cloud.databricks.com",
      "azuredatabricks.net",
      "gcp.databricks.com",
    ]) {
      expect(isAnchoredEnterpriseHost(bare)).toBe(false);
    }
  });
});
