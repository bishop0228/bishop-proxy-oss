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
 * ark.cn-beijing.volces.com. Ollama (local) NOT added — no proxy egress.
 * Each pattern is fully anchored, single DNS label, lowercase-only, no `i` flag, no
 * .*, no unanchored alternation. Reviewed founder-approved 2026-05-29/2026-05-30.
 *
 * §1.18.15 / W38-S731 Block 4 MCP egress (founder-approved 2026-06-02, length→74):
 * the 42 verified static-host remote MCP servers add their single static upstream
 * hosts here (32→74). These are operational-egress MCP destinations routed via the
 * §3.2 proxy /mcp/<server_id> leg — NOT model inference upstreams. github reused
 * api.githubcopilot.com (already present, +0).
 *
 * W38-S734 unwire (founder-approved 2026-06-02, length 81→74): the 7 replace-market
 * connectors granola/fireflies/fathom (meeting, UC1 native local capture) +
 * zapier/make/ifttt/workato (automation, UC16 native governed workflows) are
 * NATIVE-COVERED — their hosts are REMOVED here (narrows §3.2 egress; Pillar-2
 * positive). otter + n8n were catalog-only (never wired), so no host change.
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
  // on this leg, only the flat abuse-bound quota. The 5 per-tenant/templated
  // servers (snowflake/salesforce/microsoft-365/onedrive-sharepoint/netsuite)
  // are DEFERRED — their per-account hosts break the frozen-host model.
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
] as const);

/**
 * §1.17.18/§1.17.19 enterprise anchored patterns (founder-approved 2026-05-29;
 * floor-not-ceiling preserved). Each is fully anchored, single DNS label,
 * lowercase-only, no `i` flag, no .*, no unanchored alternation.
 */
export const ENTERPRISE_HOST_PATTERNS: RegExp[] = [
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.openai\.azure\.com$/,
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?-aiplatform\.googleapis\.com$/,
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
