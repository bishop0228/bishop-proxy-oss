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
 * the exact ALLOWED_OUTBOUND_HOSTS set is unchanged (length stays 26) for completion
 * legs; §1.17.19 adds exactly one exact-match host (oauth2.googleapis.com, length now
 * 27) for the SA-token mint leg — the aiplatform/azure wildcards remain floor patterns.
 * Each pattern is fully anchored, single DNS label, lowercase-only, no `i` flag, no
 * .*, no unanchored alternation. Reviewed founder-approved 2026-05-29.
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
