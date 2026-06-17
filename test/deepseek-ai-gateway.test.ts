/**
 * W38-S872i — DeepSeek routed via Cloudflare AI Gateway.
 *
 * DeepSeek 451s the proxy's direct Worker egress IP (datacenter-IP block) but
 * accepts AI Gateway's managed egress (architect-verified live, HTTP 200 through
 * the authenticated bishop-prod gateway, 2026-06-16). byok.ts routes the deepseek
 * upstream through gateway.ai.cloudflare.com when CF_AIG_* is configured.
 */
import { describe, it, expect } from "vitest";
import { BYOK_UPSTREAM_SPECS } from "../src/lib/byok-specs";
import { ALLOWED_OUTBOUND_HOSTS } from "../src/lib/outbound-allowlist";

describe("DeepSeek via AI Gateway routing (W38-S872i)", () => {
  it("the deepseek spec carries aiGatewayProvider='deepseek'", () => {
    expect(BYOK_UPSTREAM_SPECS.deepseek.aiGatewayProvider).toBe("deepseek");
  });

  it("non-AI-Gateway providers do NOT set aiGatewayProvider (opt-in only)", () => {
    expect(BYOK_UPSTREAM_SPECS.groq.aiGatewayProvider).toBeUndefined();
    expect(BYOK_UPSTREAM_SPECS.mistral.aiGatewayProvider).toBeUndefined();
  });

  it("gateway.ai.cloudflare.com is already in ALLOWED_OUTBOUND_HOSTS (no allowlist widening)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("gateway.ai.cloudflare.com");
  });

  it("AI Gateway path mapping strips exactly one leading /v1 segment", () => {
    const strip = (p: string) => p.replace(/^\/v1(?=\/|$)/, "");
    expect(strip("/v1/chat/completions")).toBe("/chat/completions"); // deepseek inbound → AIG path
    expect(strip("/chat/completions")).toBe("/chat/completions");    // already-native, untouched
    expect(strip("/v1")).toBe("");
    expect(strip("/v1beta/x")).toBe("/v1beta/x");                    // only the exact /v1 segment
  });
});
