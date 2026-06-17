/**
 * OAUTH_UPSTREAM_SPECS — frozen per-provider descriptor table for OAuth subscription legs.
 *
 * Data-not-code: per-provider variation is DATA; one generalized handler reads this table.
 * NO operatorKeyVar by design — OAuth is byok-class. The user's OAuth access token IS
 * their upstream credential; operator fallback is structurally unrepresentable here.
 * completionPath is FIXED (never derived from the inbound request) — preserves the
 * §3.2 single-seal boundary; client cannot pick the upstream path.
 *
 * Keyed by URL segment appearing at position [2] of /oauth/<seg>/token (token leg)
 * and /v1/<seg>/... (completion leg). Five segs: ToS-permitted subscription sign-ins only.
 * Anthropic + Google Gemini are intentionally absent (subscription OAuth banned Feb–Apr 2026).
 *
 * Do NOT add an entry without a corresponding host addition in src/lib/outbound-allowlist.ts.
 */

export interface OAuthUpstreamSpec {
  tokenHost: string;
  tokenPath: string;
  tokenBaseUrlVar: string;       // env override for tests; prod uses https://${tokenHost}
  completionHost: string;
  completionPath: string;        // FIXED upstream path — proxy NEVER derives it from the inbound request
  completionBaseUrlVar: string;
  extraUpstreamHeaders?: Readonly<Record<string, string>>;
  // Per-request account-id passthrough header (e.g. "chatgpt-account-id" for openai_codex). The
  // daemon sends the Bishop-namespaced X-Bishop-Upstream-Account-Id; the route maps its value to
  // THIS header upstream. Distinct from extraUpstreamHeaders (a FIXED value) — the account-id is
  // per-user/per-request data. Omitted for providers that need no account header.
  accountIdHeader?: string;
  // Per-request session-id passthrough header (e.g. "session_id" for openai_codex). The daemon
  // sends the Bishop-namespaced X-Bishop-Upstream-Session-Id (a fresh non-secret UUID per
  // completion); the route maps its value to THIS header upstream. Like accountIdHeader, the
  // value is per-request (NOT a FIXED extraUpstreamHeaders value). Omitted when not required.
  sessionIdHeader?: string;
}

export const OAUTH_UPSTREAM_SPECS: Readonly<Record<string, OAuthUpstreamSpec>> = Object.freeze({

  // openai_codex — OpenAI Codex subscription.
  // The chatgpt.com/backend-api/codex/responses backend is an SSE endpoint that whitelists the
  // first-party Codex client FINGERPRINT — a request missing it is held (the daemon then times
  // out). These FIXED headers reproduce that fingerprint (codex-rs
  // codex-rs/core/src/client.rs::stream_responses, tag rust-v0.20.0): originator identifies the
  // client (the backend 403s a wrong/missing value), OpenAI-Beta selects the Responses beta, and
  // Accept declares SSE. session_id is per-request (sessionIdHeader, below) — never frozen here.
  openai_codex: {
    tokenHost: "auth.openai.com",
    tokenPath: "/oauth/token",
    tokenBaseUrlVar: "OPENAI_CODEX_TOKEN_BASE_URL",
    completionHost: "chatgpt.com",
    completionPath: "/backend-api/codex/responses",
    completionBaseUrlVar: "OPENAI_CODEX_COMPLETION_BASE_URL",
    extraUpstreamHeaders: Object.freeze({
      "originator": "codex_cli_rs",
      "OpenAI-Beta": "responses=experimental",
      "Accept": "text/event-stream",
    }),
    accountIdHeader: "chatgpt-account-id",
    sessionIdHeader: "session_id",
  },

  // xai_grok — xAI Grok subscription.
  xai_grok: {
    tokenHost: "accounts.x.ai",
    tokenPath: "/oauth/token",
    tokenBaseUrlVar: "XAI_GROK_TOKEN_BASE_URL",
    completionHost: "api.x.ai",
    completionPath: "/v1/chat/completions",
    completionBaseUrlVar: "XAI_GROK_COMPLETION_BASE_URL",
  },

  // github_copilot — GitHub Copilot subscription. Secondary token mint (api.github.com) is
  // owned by the daemon token-lifecycle; proxy forwards whatever final credential the daemon
  // supplies as X-Bishop-Upstream-Key. api.github.com is therefore not in the proxy allowlist.
  github_copilot: {
    tokenHost: "github.com",
    tokenPath: "/login/oauth/access_token",
    tokenBaseUrlVar: "GITHUB_COPILOT_TOKEN_BASE_URL",
    completionHost: "api.githubcopilot.com",
    completionPath: "/chat/completions",
    completionBaseUrlVar: "GITHUB_COPILOT_COMPLETION_BASE_URL",
  },

  // qwen_alibaba — Alibaba Qwen subscription.
  qwen_alibaba: {
    tokenHost: "chat.qwen.ai",
    tokenPath: "/api/v1/oauth2/token",
    tokenBaseUrlVar: "QWEN_ALIBABA_TOKEN_BASE_URL",
    completionHost: "dashscope-intl.aliyuncs.com",
    completionPath: "/compatible-mode/v1/chat/completions",
    completionBaseUrlVar: "QWEN_ALIBABA_COMPLETION_BASE_URL",
    extraUpstreamHeaders: Object.freeze({ "X-DashScope-AuthType": "qwen-oauth" }),
  },

  // nous_portal — Nous Research portal subscription.
  nous_portal: {
    tokenHost: "portal.nousresearch.com",
    tokenPath: "/oauth/token",
    tokenBaseUrlVar: "NOUS_PORTAL_TOKEN_BASE_URL",
    completionHost: "portal.nousresearch.com",
    completionPath: "/v1/chat/completions",
    completionBaseUrlVar: "NOUS_PORTAL_COMPLETION_BASE_URL",
  },
});
