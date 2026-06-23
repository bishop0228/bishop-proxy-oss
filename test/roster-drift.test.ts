/**
 * CI DRIFT GATE — proxy roster ⊇ daemon universe − carve-outs
 *
 * Fails if the daemon provider universe (fixture) contains an egress-bearing
 * provider that the proxy has not yet wired. Closes the cross-repo
 * silent-divergence hole: a daemon provider added without a matching proxy
 * route would silently pass through without the sealed-egress guarantee.
 *
 * Fixture: test/fixtures/daemon-provider-roster.2026-05-30.json
 * Refresh cadence: quarterly + before each major launch.
 * Bidirectional live daemon-side drift detection folds into §H-DYNAMIC.
 *
 * This file is the assertion surface — .github/workflows/provider-roster-drift.yml
 * is the enforcement surface that runs npm test on every push/PR.
 */

import { describe, it, expect } from "vitest";
import { BYOK_UPSTREAM_SPECS } from "../src/lib/byok-specs";
import { OAUTH_UPSTREAM_SPECS } from "../src/lib/oauth-specs";
import fixture from "./fixtures/daemon-provider-roster.2026-05-30.json";

// Build the proxy's current routed roster from live source files
function buildProxyRoster(): Set<string> {
  const roster = new Set<string>();
  // 14 BYOK providers
  for (const key of Object.keys(BYOK_UPSTREAM_SPECS)) {
    roster.add(key);
  }
  // 5 OAuth providers
  for (const key of Object.keys(OAUTH_UPSTREAM_SPECS)) {
    roster.add(key);
  }
  // 3 enterprise BYOK legs (distinct auth mechanisms — not in the spec tables above)
  roster.add("bedrock"); // AWS Bedrock SigV4 — src/lib/bedrock-spec.ts
  roster.add("azure");   // Azure OpenAI api-key — src/lib/azure-spec.ts
  roster.add("vertex");  // Google Vertex Bearer — src/lib/vertex-spec.ts
  // 3 extra routes (dedicated route files, not in BYOK/OAuth tables)
  roster.add("anthropic"); // daemon key: claude — src/routes/messages.ts
  roster.add("openai");    // src/routes/chat-completions.ts
  roster.add("gemini");    // src/routes/gemini.ts
  return roster;
}

// Build the set of proxy keys the daemon universe requires the proxy to cover
function buildRequiredKeys(
  fixt: typeof fixture,
  proxyRoster: Set<string>,
): { required: Set<string>; missing: string[] } {
  const carveouts = new Set<string>(Object.keys(fixt.no_egress_carveouts));
  const aliases = fixt.proxy_key_aliases as Record<string, string>;

  const allDaemonKeys = [
    ...(fixt.byok_providers as string[]),
    ...(fixt.oauth_providers as string[]),
    ...(fixt.extra_providers as string[]),
  ];

  const required = new Set<string>();
  const missing: string[] = [];

  for (const daemonKey of allDaemonKeys) {
    if (carveouts.has(daemonKey)) continue; // local-only, no proxy egress needed
    const proxyKey: string = (aliases as Record<string, string>)[daemonKey] ?? daemonKey;
    required.add(proxyKey);
    if (!proxyRoster.has(proxyKey)) {
      missing.push(`daemon:${daemonKey} → proxy:${proxyKey}`);
    }
  }

  return { required, missing };
}

describe("roster-drift: proxy routed roster ⊇ daemon universe − carve-outs", () => {
  it("proxy roster covers every non-carveout daemon provider", () => {
    const proxyRoster = buildProxyRoster();
    const { missing } = buildRequiredKeys(fixture, proxyRoster);
    // If this fails, the proxy is missing egress coverage for daemon providers.
    // Add the missing providers to the proxy and update ALLOWED_OUTBOUND_HOSTS.
    expect(missing).toEqual([]);
  });

  it("fixture no_egress_carveouts documents at least one local-only provider", () => {
    // Sanity: the carveouts list is not accidentally empty (would silently weaken the gate)
    const carveouts = Object.keys(fixture.no_egress_carveouts);
    expect(carveouts.length).toBeGreaterThan(0);
  });

  it("fixture byok_providers count matches daemon universe (27 BYOK)", () => {
    // W38-S964 added sakana_fugu (26 → 27).
    expect((fixture.byok_providers as string[]).length).toBe(27);
  });

  it("fixture oauth_providers count matches daemon universe (5 OAuth)", () => {
    expect((fixture.oauth_providers as string[]).length).toBe(5);
  });

  it("fixture extra_providers count matches daemon universe (3 extras)", () => {
    expect((fixture.extra_providers as string[]).length).toBe(3);
  });

  it("proxy roster total: ≥ 25 routed providers", () => {
    const proxyRoster = buildProxyRoster();
    expect(proxyRoster.size).toBeGreaterThanOrEqual(25);
  });
});
