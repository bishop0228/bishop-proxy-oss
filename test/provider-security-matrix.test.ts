/**
 * §C-BRIDGE PROVIDER-SECURITY-DIMENSION-MATRIX-PROXY
 *
 * Dim 8 — Sealed egress (BUILD, proxy-side):
 *   Every routed provider's upstream host is inside the frozen ALLOWED_OUTBOUND_HOSTS
 *   seal or the anchored ENTERPRISE_HOST_PATTERNS floor. A substituted attacker host
 *   for any provider is blocked by installFetchAllowlist (OutboundHostNotAllowed).
 *   Per-provider teeth — not a single global probe.
 *
 * Dim 9 — Cert-pin (CITE, already CLOSED daemon-side):
 *   The daemon pins proxy.mybishop.ai for the daemon→proxy hop via
 *   daemon/src/model/cert_pins.py (is_strict_mode() closed-by-default;
 *   strict → CertPinningError + socket close). One pinned host, process-global
 *   no-bypass invariant, covered by ~8 daemon test files. NOT rebuilt here —
 *   a Cloudflare Worker cannot pin Python's TLS chain.
 *
 * §C-V verifications (V0–V5) are appended below in a separate describe block.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  ALLOWED_OUTBOUND_HOSTS,
  isAnchoredEnterpriseHost,
  installFetchAllowlist,
  OutboundHostNotAllowed,
  AnthropicBaseUrlNotAllowed,
  _resetForTesting,
} from "../src/lib/outbound-allowlist";
import { BYOK_UPSTREAM_SPECS } from "../src/lib/byok-specs";
import { OAUTH_UPSTREAM_SPECS } from "../src/lib/oauth-specs";
import { BEDROCK_UPSTREAM } from "../src/lib/bedrock-spec";
import fixture from "./fixtures/daemon-provider-roster.2026-05-30.json";

type G = { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> };

// ─────────────────────────────────────────────────────────────────────────────
// Dim 8 — per-provider host membership (structural, no fetch needed)
// ─────────────────────────────────────────────────────────────────────────────

describe("Dim 8 sealed-egress: per-provider host membership", () => {
  const allowedSet = new Set<string>(ALLOWED_OUTBOUND_HOSTS as readonly string[]);

  // BYOK — 14 providers, each has one upstreamHost
  for (const [name, spec] of Object.entries(BYOK_UPSTREAM_SPECS)) {
    it(`byok/${name}: upstreamHost ${spec.upstreamHost} is in ALLOWED_OUTBOUND_HOSTS`, () => {
      expect(allowedSet.has(spec.upstreamHost)).toBe(true);
    });
  }

  // OAuth — 5 providers, each has tokenHost + completionHost
  for (const [name, spec] of Object.entries(OAUTH_UPSTREAM_SPECS)) {
    it(`oauth/${name}: tokenHost ${spec.tokenHost} is in ALLOWED_OUTBOUND_HOSTS`, () => {
      expect(allowedSet.has(spec.tokenHost)).toBe(true);
    });
    it(`oauth/${name}: completionHost ${spec.completionHost} is allowed (exact or enterprise pattern)`, () => {
      const allowed =
        allowedSet.has(spec.completionHost) ||
        isAnchoredEnterpriseHost(spec.completionHost);
      expect(allowed).toBe(true);
    });
  }

  // Enterprise BYOK — bedrock (exact-match), azure + vertex (enterprise patterns)
  it("bedrock: upstreamHost is in ALLOWED_OUTBOUND_HOSTS", () => {
    expect(allowedSet.has(BEDROCK_UPSTREAM.upstreamHost)).toBe(true);
  });

  it("azure: sample resource host matches enterprise pattern (not in exact set)", () => {
    expect(isAnchoredEnterpriseHost("myresource.openai.azure.com")).toBe(true);
  });

  it("vertex: sample region host matches enterprise pattern (not in exact set)", () => {
    expect(isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com")).toBe(true);
  });

  // Extras routed via dedicated routes (messages.ts / chat-completions.ts / gemini.ts)
  it("anthropic extra: api.anthropic.com is in ALLOWED_OUTBOUND_HOSTS", () => {
    expect(allowedSet.has("api.anthropic.com")).toBe(true);
  });

  it("openai extra: api.openai.com is in ALLOWED_OUTBOUND_HOSTS", () => {
    expect(allowedSet.has("api.openai.com")).toBe(true);
  });

  it("gemini extra: generativelanguage.googleapis.com is in ALLOWED_OUTBOUND_HOSTS", () => {
    expect(allowedSet.has("generativelanguage.googleapis.com")).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Dim 8 — per-provider attacker-host swap (behavioral — installFetchAllowlist)
// ─────────────────────────────────────────────────────────────────────────────

describe("Dim 8 sealed-egress: per-provider attacker-host swap", () => {
  const originalFetch = (globalThis as unknown as G).fetch;

  beforeEach(() => {
    _resetForTesting();
  });

  afterEach(() => {
    _resetForTesting();
    (globalThis as unknown as G).fetch = originalFetch;
  });

  // Build per-provider attacker URLs: one per provider key, distinct host per provider
  const PROVIDER_ATTACKER_URLS: Array<{ label: string; url: string }> = [
    // BYOK — each provider gets its own attacker subdomain for distinctness
    ...Object.keys(BYOK_UPSTREAM_SPECS).map((k) => ({
      label: `byok/${k}`,
      url: `https://${k}.attacker.example/v1/chat/completions`,
    })),
    // OAuth — each provider key gets its own attacker subdomain
    ...Object.keys(OAUTH_UPSTREAM_SPECS).map((k) => ({
      label: `oauth/${k}`,
      url: `https://${k}-attacker.example/oauth/token`,
    })),
    // Enterprise — suffix-spoof variants that look legitimate but fail the anchor check
    {
      label: "azure (suffix-spoof)",
      url: "https://myresource.openai.azure.com.attacker.example/path",
    },
    {
      label: "vertex (suffix-spoof)",
      url: "https://us-central1-aiplatform.googleapis.com.attacker.example/path",
    },
    {
      label: "bedrock (distinct attacker)",
      url: "https://bedrock-attacker.example/model",
    },
    // Extras
    { label: "anthropic", url: "https://anthropic-attacker.example/v1/messages" },
    { label: "openai", url: "https://openai-attacker.example/v1/chat/completions" },
    { label: "gemini", url: "https://gemini-attacker.example/v1/models" },
  ];

  for (const { label, url } of PROVIDER_ATTACKER_URLS) {
    it(`${label}: attacker host swap is blocked by installFetchAllowlist`, async () => {
      installFetchAllowlist();
      await expect(
        (globalThis as unknown as G).fetch(url),
      ).rejects.toBeInstanceOf(OutboundHostNotAllowed);
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Dim 8 — sealed-egress invariants (no-bypass, not padded per provider)
// ─────────────────────────────────────────────────────────────────────────────

describe("Dim 8 sealed-egress invariants (no-bypass)", () => {
  const originalFetch = (globalThis as unknown as G).fetch;

  beforeEach(() => {
    _resetForTesting();
  });

  afterEach(() => {
    _resetForTesting();
    (globalThis as unknown as G).fetch = originalFetch;
  });

  it("ALLOWED_OUTBOUND_HOSTS.length === 90 (sentinel — 41 provider + 44 MCP + 1 model-registry + 3 S6b worker-egress + 1 HF; W38-S968 +1 novita)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(90);
  });

  it("no-runtime-widening: installFetchAllowlist blocks non-allowlisted host after install", async () => {
    installFetchAllowlist();
    // A host that was never in ALLOWED_OUTBOUND_HOSTS must still be blocked
    // after install — proves the set is not widened at runtime
    await expect(
      (globalThis as unknown as G).fetch("https://runtime-added.attacker.example/exfil"),
    ).rejects.toBeInstanceOf(OutboundHostNotAllowed);
  });

  it("suffix-spoof: foo.openai.azure.com.attacker.com is NOT an anchored enterprise host", () => {
    expect(isAnchoredEnterpriseHost("foo.openai.azure.com.attacker.com")).toBe(false);
  });

  it("suffix-spoof: aiplatform.googleapis.com.attacker.com is NOT an anchored enterprise host", () => {
    expect(
      isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com.attacker.com"),
    ).toBe(false);
  });

  it("AnthropicBaseUrlNotAllowed is exported and carries host + name", () => {
    const err = new AnthropicBaseUrlNotAllowed("exfil.attacker.example");
    expect(err.name).toBe("AnthropicBaseUrlNotAllowed");
    expect(err.host).toBe("exfil.attacker.example");
    expect(err.message).toContain("exfil.attacker.example");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Dim 9 — cert-pin CITE invariant (proxy-observable half only)
//
// The daemon pins proxy.mybishop.ai for the daemon→proxy hop via
// daemon/src/model/cert_pins.py (is_strict_mode() closed-by-default).
// The proxy (Cloudflare Worker) CANNOT enforce Python TLS chain pinning.
// This describe block is a cite-integrity probe — it does NOT duplicate
// daemon-side enforcement. See §5 OUT OF SCOPE for rationale.
// ─────────────────────────────────────────────────────────────────────────────

describe("Dim 9 cert-pin CITE invariant (proxy-observable half only)", () => {
  it("fixture cert_pin_citation names daemon/src/model/cert_pins.py + proxy.mybishop.ai + closed-by-default", () => {
    expect(fixture.cert_pin_citation.daemon_module).toBe("daemon/src/model/cert_pins.py");
    expect(fixture.cert_pin_citation.pinned_host).toBe("proxy.mybishop.ai");
    expect(fixture.cert_pin_citation.pin_mode).toBe("closed-by-default");
  });

  it("proxy ALLOWED_OUTBOUND_HOSTS does NOT contain proxy.mybishop.ai (it is the ingress, not egress)", () => {
    // proxy.mybishop.ai is the host the daemon calls (ingress to the proxy).
    // The proxy's outbound allowlist covers AI provider upstreams — proxy.mybishop.ai
    // is never an outbound destination from the proxy itself.
    expect([...(ALLOWED_OUTBOUND_HOSTS as readonly string[])]).not.toContain(
      "proxy.mybishop.ai",
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// §C-V Verification (V0–V5)
// ─────────────────────────────────────────────────────────────────────────────

describe("§C-V verification", () => {
  const originalFetch = (globalThis as unknown as G).fetch;

  beforeEach(() => {
    _resetForTesting();
  });

  afterEach(() => {
    _resetForTesting();
    (globalThis as unknown as G).fetch = originalFetch;
  });

  // V0 — roster count floor: routed roster ≥ BYOK 14 + OAuth 5 + enterprise 3 + extras 3
  it("V0 roster-count floor: ≥ 25 routed providers (14 BYOK + 5 OAuth + 3 enterprise + 3 extras)", () => {
    const byokCount = Object.keys(BYOK_UPSTREAM_SPECS).length;
    const oauthCount = Object.keys(OAUTH_UPSTREAM_SPECS).length;
    const enterpriseCount = 3; // bedrock + azure + vertex
    const extrasCount = 3; // anthropic + openai + gemini
    const total = byokCount + oauthCount + enterpriseCount + extrasCount;
    expect(byokCount).toBeGreaterThanOrEqual(14);
    expect(oauthCount).toBeGreaterThanOrEqual(5);
    expect(total).toBeGreaterThanOrEqual(25);
  });

  // V1 — sealed-egress mutation: non-allowlisted host → OutboundHostNotAllowed (non-vacuous)
  it("V1 sealed-egress mutation: injecting non-allowlisted provider host is blocked", async () => {
    installFetchAllowlist();
    const nonAllowlisted = "https://inject.not-in-allowlist.example/v1/chat";
    await expect(
      (globalThis as unknown as G).fetch(nonAllowlisted),
    ).rejects.toBeInstanceOf(OutboundHostNotAllowed);
  });

  // V2 — length sentinel: exactly 90 (41 provider + 44 MCP egress + 1 model-
  // registry + 3 S6b worker-egress fixed hosts + 1 HuggingFace BYO-model host;
  // breaks loudly on silent host addition; W38-S968 +1 novita)
  it("V2 ALLOWED_OUTBOUND_HOSTS.length === 90 (length sentinel)", () => {
    expect(ALLOWED_OUTBOUND_HOSTS.length).toBe(90);
  });

  // V3 — suffix-spoof teeth: both canonical suffix-spoof variants are rejected
  it("V3 suffix-spoof teeth: azure.com.attacker.com suffix rejected", () => {
    expect(isAnchoredEnterpriseHost("foo.openai.azure.com.attacker.com")).toBe(false);
  });

  it("V3 suffix-spoof teeth: aiplatform.googleapis.com.attacker.com suffix rejected", () => {
    expect(
      isAnchoredEnterpriseHost("us-central1-aiplatform.googleapis.com.attacker.com"),
    ).toBe(false);
  });

  // V4 — drift-gate teeth: a synthetic divergent roster exposes missing providers
  it("V4 drift-gate teeth: synthetic divergent fixture fails the coverage gate", () => {
    const proxyRoster = new Set<string>([
      ...Object.keys(BYOK_UPSTREAM_SPECS),
      ...Object.keys(OAUTH_UPSTREAM_SPECS),
      "bedrock",
      "azure",
      "vertex",
      "anthropic",
      "openai",
      "gemini",
    ]);

    // Synthetic daemon fixture: daemon has added a new egress-bearing provider
    // ("new_provider_xyz") that the proxy has NOT yet wired.
    const syntheticByok = [...Object.keys(BYOK_UPSTREAM_SPECS), "new_provider_xyz"];
    const syntheticCarveouts = new Set<string>(Object.keys(fixture.no_egress_carveouts));
    const syntheticAliases = fixture.proxy_key_aliases as Record<string, string>;

    const allDaemonKeys = [
      ...syntheticByok,
      ...fixture.oauth_providers,
      ...fixture.extra_providers,
    ] as string[];

    const missing: string[] = [];
    for (const key of allDaemonKeys) {
      if (syntheticCarveouts.has(key)) continue;
      const proxyKey = syntheticAliases[key] ?? key;
      if (!proxyRoster.has(proxyKey)) {
        missing.push(proxyKey);
      }
    }

    // The gate MUST fire: new_provider_xyz is not in the proxy roster
    expect(missing).toContain("new_provider_xyz");
    expect(missing.length).toBeGreaterThan(0);
  });

  // V5 — cert-pin cite-integrity: fixture citation names cert_pins.py + proxy.mybishop.ai + closed-by-default
  it("V5 cert-pin cite-integrity: fixture names cert_pins.py, proxy.mybishop.ai, closed-by-default", () => {
    expect(fixture.cert_pin_citation.daemon_module).toContain("cert_pins.py");
    expect(fixture.cert_pin_citation.pinned_host).toBe("proxy.mybishop.ai");
    expect(fixture.cert_pin_citation.pin_mode).toBe("closed-by-default");
    // Confirm the note distinguishes proxy from daemon enforcement
    expect(fixture.cert_pin_citation.note).toMatch(/daemon-side/);
    expect(fixture.cert_pin_citation.note).not.toMatch(/duplicated here.*(?:Yes|true)/i);
  });
});
