/**
 * Outbound fetch allowlist — no-exfiltration enforcement boundary.
 *
 * The allowlist is a fixed constant — no extraHosts, no operator-configurable
 * widening via ANTHROPIC_BASE_URL. A misconfigured ANTHROPIC_BASE_URL fails
 * closed on the first request (AnthropicBaseUrlNotAllowed, HTTP 500), not
 * silently.
 *
 * This module enforces the claim: "Bishop's Worker only fetches
 * api.anthropic.com — there is no exfiltration surface." It patches
 * globalThis.fetch at Worker startup so any future code regression that calls
 * fetch against a non-allowlisted host fails closed at runtime, not in
 * production traffic.
 *
 * §1.17.18/§1.17.19 enterprise-host floor: ENTERPRISE_HOST_PATTERNS carries anchored
 * single-label regexes for Azure OpenAI (<resource>.openai.azure.com) and Vertex AI
 * (<region>-aiplatform.googleapis.com). This is a floor-not-ceiling ADDED conjunct —
 * completion legs: §1.17.19 added oauth2.googleapis.com (length→27); §H-DYNAMIC
 * (2026-05-30, founder-signed-off) adds 5 BYOK upstreams (length→32): api.cerebras.ai,
 * integrate.api.nvidia.com, gateway.ai.cloudflare.com, api.hunyuan.cloud.tencent.com,
 * ark.cn-beijing.volces.com. Ollama model INFERENCE (local) NOT added — no proxy
 * egress for inference; but the Ollama model REGISTRY (registry.ollama.ai) IS added
 * below (B1 governed model-registry egress — read-only GET, operational not inference).
 * Each pattern is fully anchored, single DNS label, lowercase-only, no `i` flag, no
 * .*, no unanchored alternation. Reviewed founder-approved 2026-05-29/2026-05-30.
 *
 * §1.18.15 / W38-S731 Block 4 MCP egress (founder-approved 2026-06-02, length→76
 * after W38-S736): the 42 verified static-host remote MCP servers add their single
 * static upstream hosts here (32→74). These are operational-egress MCP destinations
 * routed via the §3.2 proxy /mcp/<server_id> leg — NOT model inference upstreams.
 * github reused api.githubcopilot.com (already present, +0).
 *
 * W38-S734 unwire (founder-approved 2026-06-02, length 81→74): the 7 replace-market
 * connectors granola/fireflies/fathom (meeting, UC1 native local capture) +
 * zapier/make/ifttt/workato (automation, UC16 native governed workflows) are
 * NATIVE-COVERED — their hosts are REMOVED here (narrows §3.2 egress; Pillar-2
 * positive). otter + n8n were catalog-only (never wired), so no host change.
 *
 * W38-S735 per-account remote MCP (founder-reviewed 2026-06-02, length UNCHANGED 74):
 * the 4 per-account-host remote MCP servers (snowflake, netsuite, databricks,
 * shopify) cannot freeze a single upstream host — their host is per-customer
 * (<org>.snowflakecomputing.com, <acct>.suitetalk.api.netsuite.com, the databricks
 * per-cloud workspace host, <shop>.myshopify.com). They are NOT added to
 * ALLOWED_OUTBOUND_HOSTS; instead each named, founder-reviewed vendor host shape
 * is an anchored ENTERPRISE_HOST_PATTERNS conjunct (same mechanism + floor-not-
 * ceiling property as the Azure/Vertex per-customer hosts). The /mcp route admits
 * a per-account host ONLY when it matches the SPECIFIC vendor pattern bound to the
 * requested spec (src/lib/mcp-specs.ts hostPattern), daemon-supplied + spec-bound +
 * SSRF-bounded to the vendor domain. Databricks is MULTI-CLOUD: 3 anchored patterns
 * (cloud.databricks.com AWS / azuredatabricks.net Azure / gcp.databricks.com GCP).
 * Each pattern is fully anchored, no `i` flag, no `.*`, no unanchored alternation.
 *
 * W38-S736 fixed-host remote MCP (founder-reviewed 2026-06-03, length 74→76): the
 * last 3 deferred "templated" servers are FIXED-host after all. microsoft-365 +
 * onedrive-sharepoint share the single frozen Microsoft Agent 365 host
 * `agent365.svc.cloud.microsoft` (the per-tenant id is in the PATH, not the host —
 * a daemon-supplied, GUID-validated `{tenantId}` segment the /mcp route substitutes
 * server-side; a path segment cannot redirect egress off a frozen allow-listed host).
 * salesforce uses the frozen Hosted-MCP host `api.salesforce.com` (org identified by
 * the OAuth token, NOT the URL). Both are EXACT-match entries (NOT patterns) added
 * below — none of the 3 is per-account, and none remains deferred.
 *
 * Modifications to ALLOWED_OUTBOUND_HOSTS or the interceptor logic require
 * explicit security review (floor-not-ceiling rule and defense-in-depth review).
 * See README "Outbound fetch allowlist" section.
 */

/** Single source of truth for permitted outbound hosts. Fixed — no runtime widening. */
export const ALLOWED_OUTBOUND_HOSTS = Object.freeze([
  "api.anthropic.com",
  "api.openai.com",
  "api.x.ai",
  "dashscope-intl.aliyuncs.com",
  "generativelanguage.googleapis.com",
  // §1.17.15 BYOK upstream vendors — see docs/PROVIDER_MATRIX.md §4
  "ai-gateway.vercel.sh",
  "api.cohere.com",
  "api.deepseek.com",
  "api.fireworks.ai",
  "api.groq.com",
  "api.minimax.chat",
  "api.mistral.ai",
  "api.moonshot.ai",
  "api.perplexity.ai",
  "api.together.xyz",
  "open.bigmodel.cn",
  "openrouter.ai",
  "router.huggingface.co",
  // §1.17.16 OAuth subscription upstreams
  "auth.openai.com",
  "chatgpt.com",
  "accounts.x.ai",
  "github.com",
  "api.githubcopilot.com",
  "chat.qwen.ai",
  "portal.nousresearch.com",
  // api.x.ai + dashscope-intl.aliyuncs.com already present above; api.github.com OMITTED (secondary Copilot token mint is daemon-side)
  // §1.17.17 enterprise BYOK — AWS Bedrock SigV4
  "bedrock-runtime.us-east-1.amazonaws.com",
  // §1.17.19 Vertex SA-token mint — Google OAuth2 token endpoint
  "oauth2.googleapis.com",
  // §H-DYNAMIC 2026-05-30 — OpenClaw-parity BYOK upstreams (founder-signed-off)
  "api.cerebras.ai",
  "integrate.api.nvidia.com",
  "gateway.ai.cloudflare.com",
  "api.hunyuan.cloud.tencent.com",
  "ark.cn-beijing.volces.com",
  // ── W38-S731 Block 4 (founder-approved 2026-06-02): 42 remote MCP egress hosts ──
  // (W38-S734 removed 7: granola/fireflies/fathom + zapier/make/ifttt/workato → native-covered)
  // Named, reviewed additions (Pillar 2). Each is the SINGLE static upstream
  // host of a verified vendor-hosted MCP server (W38-S730 VERIFIED FINAL),
  // reached only via the §3.2 proxy /mcp/<server_id> leg (src/routes/mcp.ts).
  // MCP is operational egress, NOT model inference — no classifier/cost meter
  // on this leg, only the flat abuse-bound quota. (Formerly-deferred note now
  // false: snowflake + netsuite are per-account-wired (W38-S735); salesforce +
  // microsoft-365 + onedrive-sharepoint are fixed-host-wired (W38-S736). None
  // of the original "templated" servers remains deferred.)
  "mcp.amplitude.com",
  "mcp.asana.com",
  "mcp.atlassian.com",
  "mcp.attio.com",
  "app.base44.com",
  "bigquery.googleapis.com",
  "mcp.box.com",
  "api.brex.com",
  "mcp.canva.com",
  "mcp.close.com",
  "mcp.cloudflare.com",
  "mcp.context7.com",
  "mcp.datadoghq.com",
  "mcp.dropbox.com",
  "mcp.exa.ai",
  "mcp.figma.com",
  "mcp.firecrawl.dev",
  "gitlab.com",
  "gmailmcp.googleapis.com",
  "calendarmcp.googleapis.com",
  "drivemcp.googleapis.com",
  "mcp.grafana.com",
  "mcp.honeycomb.io",
  "mcp.hubspot.com",
  "mcp.linear.app",
  "mcp.lovable.dev",
  "mcp.mixpanel.com",
  "mcp.monday.com",
  "mcp.neon.tech",
  "mcp.notion.com",
  "mcp.pagerduty.com",
  "mcp.paypal.com",
  "mcp.posthog.com",
  "mcp.ramp.com",
  "mcp.sentry.dev",
  "mcp.slack.com",
  "mcp.squareup.com",
  "mcp.stripe.com",
  "mcp.supabase.com",
  "mcp.tavily.com",
  "mcp.vercel.com",
  "mcp-us.zoom.us",
  // ── W38-S736 (founder-reviewed 2026-06-03): 2 fixed-host remote MCP egress ──
  // The last 3 deferred "templated" servers are FIXED-host. microsoft-365 +
  // onedrive-sharepoint share ONE frozen Microsoft Agent 365 host (per-tenant id
  // lives in the daemon-supplied, GUID-validated PATH segment — see mcp-specs.ts
  // pathTenantFromUpstream + src/routes/mcp.ts); salesforce uses the frozen Hosted
  // MCP host (org via OAuth token, not the URL). EXACT-match (NOT patterns).
  "agent365.svc.cloud.microsoft",
  "api.salesforce.com",
  // ── B1 (founder-approved): 1 governed model-registry egress host (length 76→77) ──
  // The Ollama public model REGISTRY (read-only GET, reached only via the §3.2
  // proxy /model-registry/ leg, src/routes/model-registry.ts). Operational egress,
  // NOT model inference — no classifier/cost meter, only the flat abuse-bound quota.
  // Frozen host; every redirect hop is re-checked against this allowlist (B2 daemon
  // content-pin is the integrity backstop). Total now 77 = 32 provider + 44 MCP + 1
  // model-registry.
  "registry.ollama.ai",
] as const);

/**
 * §1.17.18/§1.17.19 enterprise anchored patterns (founder-approved 2026-05-29;
 * floor-not-ceiling preserved). Each is fully anchored, single DNS label,
 * lowercase-only, no `i` flag, no .*, no unanchored alternation.
 */
// ── W38-S735 per-account remote MCP vendor host patterns (founder-reviewed
// 2026-06-02) ──────────────────────────────────────────────────────────────
// Each is a NAMED, spec-bound vendor host shape. The /mcp route validates a
// daemon-supplied X-Bishop-Upstream-Host against the SPECIFIC pattern bound to
// the requested spec (never merely "any enterprise pattern") — a snowflake spec
// admits ONLY *.snowflakecomputing.com. Exported individually so mcp-specs.ts
// binds the exact pattern(s) per server (spec-bind, §3.2 SSRF).
// Snowflake: modern org-account is a single label (<orgname>-<account>); the
// legacy account-locator-with-region + privatelink MULTI-label forms are NOT
// admitted by this single-label pattern (flagged — not broadened to .*).
export const SNOWFLAKE_HOST_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.snowflakecomputing\.com$/;
export const NETSUITE_HOST_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.suitetalk\.api\.netsuite\.com$/;
export const SHOPIFY_HOST_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.myshopify\.com$/;
// Databricks is MULTI-CLOUD. AWS = single label before .cloud.databricks.com.
// Azure = adb-<workspace-id-digits>.<random-digits>.azuredatabricks.net (2 labels).
// GCP = <workspace-id>.<digits>.gcp.databricks.com (2 labels). Each is fully
// anchored with explicit digit structure — NOT broadened to .*.
export const DATABRICKS_AWS_HOST_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloud\.databricks\.com$/;
export const DATABRICKS_AZURE_HOST_PATTERN =
  /^adb-[0-9]{1,20}\.[0-9]{1,3}\.azuredatabricks\.net$/;
export const DATABRICKS_GCP_HOST_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[0-9]{1,3}\.gcp\.databricks\.com$/;

export const ENTERPRISE_HOST_PATTERNS: RegExp[] = [
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.openai\.azure\.com$/,
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?-aiplatform\.googleapis\.com$/,
  // W38-S735 per-account remote MCP vendor hosts (the runtime fetch backstop
  // admits these; the /mcp route's spec-bound check is the explicit gate).
  SNOWFLAKE_HOST_PATTERN,
  NETSUITE_HOST_PATTERN,
  SHOPIFY_HOST_PATTERN,
  DATABRICKS_AWS_HOST_PATTERN,
  DATABRICKS_AZURE_HOST_PATTERN,
  DATABRICKS_GCP_HOST_PATTERN,
];

/** Returns true if host matches an anchored enterprise-host pattern. */
export function isAnchoredEnterpriseHost(host: string): boolean {
  return ENTERPRISE_HOST_PATTERNS.some((re) => re.test(host));
}

type FetchFn = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** Thrown when fetch is called against a host not in the effective allowlist. */
export class OutboundHostNotAllowed extends Error {
  readonly host: string;
  constructor(host: string) {
    super(`Outbound fetch blocked: host '${host}' is not in ALLOWED_OUTBOUND_HOSTS`);
    this.name = "OutboundHostNotAllowed";
    this.host = host;
  }
}

/** Thrown when ANTHROPIC_BASE_URL is set to a host outside the effective allowlist. */
export class AnthropicBaseUrlNotAllowed extends Error {
  readonly host: string;
  constructor(host: string) {
    super(`ANTHROPIC_BASE_URL hostname '${host}' is not in ALLOWED_OUTBOUND_HOSTS`);
    this.name = "AnthropicBaseUrlNotAllowed";
    this.host = host;
  }
}

let _installed = false;
// Runtime allowlist — initialized from ALLOWED_OUTBOUND_HOSTS; only
// _setAllowlistForTesting may replace it (never in production traffic).
let _allowedSet: Set<string> = new Set([...(ALLOWED_OUTBOUND_HOSTS as readonly string[])]);
let _preInstallFetch: FetchFn | null = null;

/**
 * Install the fetch allowlist interceptor. Idempotent — calling twice
 * installs only one wrapper layer. Must be called before any request handling
 * begins. The allowlist is fixed to ALLOWED_OUTBOUND_HOSTS; use
 * _setAllowlistForTesting for test environments that need additional hosts.
 */
export function installFetchAllowlist(): void {
  if (_installed) return;
  _installed = true;

  const g = globalThis as unknown as { fetch: FetchFn };
  _preInstallFetch = g.fetch;
  const prior = g.fetch.bind(globalThis);

  g.fetch = function allowlistFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const urlStr = input instanceof Request ? input.url : String(input);
    let host: string;
    try {
      host = new URL(urlStr).hostname;
    } catch {
      return Promise.reject(new OutboundHostNotAllowed(urlStr));
    }
    if (!_allowedSet.has(host) && !isAnchoredEnterpriseHost(host)) {
      return Promise.reject(new OutboundHostNotAllowed(host));
    }
    return prior(input, init);
  };
}

/**
 * The §3.2 leg-4 (sandboxed-browser egress) raw-forward seam.
 *
 * Returns the pre-install (un-intercepted) fetch so the `/browser-egress` route
 * (src/routes/browser-egress.ts) can reach an SSRF-validated PUBLIC host that
 * is — BY DESIGN — not on the static ALLOWED_OUTBOUND_HOSTS allowlist. This is
 * the ONE sanctioned bypass of the no-exfiltration interceptor and exists SOLELY
 * for the sandboxed-browser class: the caller (a VM-isolated, data-empty browser
 * worker, per strongest_claims_security.md §3.2 leg 4) reaches the open web it is
 * directed to. The data-residency guarantee holds for THIS leg by VM isolation +
 * SSRF-gating rather than by allowlisting (which a general browser cannot
 * express). The CALLER MUST SSRF-gate the URL first (browser-egress.ts
 * `isPublicHttpUrl`) — this function performs NO host check. Every OTHER (host-
 * fixed) leg still flows through the intercepted globalThis.fetch, so the
 * no-exfiltration backstop is unchanged for them. Before installFetchAllowlist
 * has run there is no captured fetch, so this falls back to the live global
 * fetch (in production the interceptor is installed before any route dispatch).
 *
 * Modifying this seam or its single caller requires explicit security review
 * (it is the only allowlist bypass in the codebase — the Anchor carve).
 */
export function rawBrowserEgressFetch(): FetchFn {
  return _preInstallFetch ?? (globalThis as unknown as { fetch: FetchFn }).fetch;
}

/**
 * For testing only: replaces the runtime allowlist. Never call from production
 * code. Callers must include "api.anthropic.com" if they want standard traffic
 * to pass through.
 */
export function _setAllowlistForTesting(hosts: readonly string[]): void {
  _allowedSet = new Set(hosts);
}

/** For testing only: resets wrapper state and restores the pre-install fetch. */
export function _resetForTesting(): void {
  if (_preInstallFetch !== null) {
    (globalThis as unknown as { fetch: FetchFn }).fetch = _preInstallFetch;
  }
  _installed = false;
  _preInstallFetch = null;
  _allowedSet = new Set([...(ALLOWED_OUTBOUND_HOSTS as readonly string[])]);
}
