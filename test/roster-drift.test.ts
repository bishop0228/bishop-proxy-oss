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
 * W38-S1306 (a), 2026-11-07: the fixture lists the daemon's 71 BYOK providers, and marks in
 * daemon_direct_providers the 37 of its extended catalog, each with the host the daemon reaches it at.
 * 68 and 34 since the founder's decision of 2026-11-08 removed inference, github_models and iflowcn.
 * The daemon reaches those directly through its egress clerk and the proxy routes none of them, so the
 * gate leaves them out as it leaves out the carve-outs.
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
  const daemonDirect = new Set<string>(Object.keys(fixt.daemon_direct_providers));
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
    if (daemonDirect.has(daemonKey)) continue; // reached daemon-direct, never through the proxy
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

  it("fixture byok_providers count matches daemon universe (68 BYOK)", () => {
    // W38-S964 added sakana_fugu (26 → 27); W38-S966 added 6 OpenAI-compatible
    // open-weights-serving clouds (meta_llama, deepinfra, baseten, inference_net,
    // siliconflow, featherless) → 33; W38-S968 added novita → 34; the daemon's extended
    // catalog (DIM 9, models.dev) added 37, each reached daemon-direct → 71 (W38-S1306 (a)); the founder's
    // decision of 2026-11-08 removed inference, github_models and iflowcn → 68.
    expect((fixture.byok_providers as string[]).length).toBe(68);
  });

  it("fixture daemon_direct_providers: the 34 BYOK providers the daemon reaches directly, each with its host", () => {
    const byok = new Set<string>(fixture.byok_providers as string[]);
    const carveouts = new Set<string>(Object.keys(fixture.no_egress_carveouts));
    const direct = Object.entries(fixture.daemon_direct_providers as Record<string, string>);
    expect(direct.length).toBe(34);
    for (const [daemonKey, host] of direct) {
      expect(byok.has(daemonKey), `${daemonKey} is not a daemon BYOK provider`).toBe(true);
      expect(carveouts.has(daemonKey), `${daemonKey} is also a carve-out`).toBe(false);
      expect(host).toMatch(/^[a-z0-9.-]+\.[a-z]+$/);
    }
  });

  it("the proxy routes none of the daemon-direct providers", () => {
    // A provider the proxy also routes is not one the gate may leave out unread.
    const proxyRoster = buildProxyRoster();
    const aliases = fixture.proxy_key_aliases as Record<string, string>;
    const routed = Object.keys(fixture.daemon_direct_providers).filter((k) => proxyRoster.has(aliases[k] ?? k));
    expect(routed).toEqual([]);
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
