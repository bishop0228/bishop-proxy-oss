/**
 * Interceptor-level floor-change guards for §1.17.18 (ENTERPRISE_HOST_PATTERNS).
 *
 * 3 guards:
 *   (8a) myresource.openai.azure.com NOT rejected post-install (resolves via mock prior)
 *   (8b) evil.com + suffix-bypass host rejected with OutboundHostNotAllowed
 *   (8c) ALLOWED_OUTBOUND_HOSTS.length === 26 — exact set unchanged
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  installFetchAllowlist,
  _resetForTesting,
  ALLOWED_OUTBOUND_HOSTS,
  OutboundHostNotAllowed,
} from "../src/lib/outbound-allowlist";

type G = { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> };

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

  it("8c: ALLOWED_OUTBOUND_HOSTS.length === 26 — exact set unchanged", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(26);
  });
});
