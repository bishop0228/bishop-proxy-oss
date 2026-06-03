/**
 * Interceptor-level floor-change guards for §1.17.18/§1.17.19 (ENTERPRISE_HOST_PATTERNS)
 * and §H-DYNAMIC 2026-05-30 (5 new BYOK upstream hosts) + W38-S731 Block 4
 * (42 remote MCP egress hosts, length 32→74 after W38-S734 unwired 7 → native-covered).
 *
 * §1.17.18 Azure guards:
 *   (8a) myresource.openai.azure.com NOT rejected post-install (resolves via mock prior)
 *   (8b) evil.com + suffix-bypass host rejected with OutboundHostNotAllowed
 *   (8c) ALLOWED_OUTBOUND_HOSTS.length === 74 — 32 provider + 42 MCP egress
 *
 * §1.17.19 Vertex guards:
 *   (9a) us-central1-aiplatform.googleapis.com accepted (isAnchoredEnterpriseHost)
 *   (9b) suffix-spoof rejected; oauth2.googleapis.com sibling rejected
 *   (9c) ALLOWED_OUTBOUND_HOSTS.length === 74 — 32 provider + 42 MCP egress
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

  it("8c: ALLOWED_OUTBOUND_HOSTS.length === 74 — 32 provider + 42 MCP egress (W38-S734 unwired 7)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(74);
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

  it("9c: ALLOWED_OUTBOUND_HOSTS.length === 74 — 32 provider + 42 MCP egress (exact-match)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(74);
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
