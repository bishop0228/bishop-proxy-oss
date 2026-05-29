/**
 * BYOK_UPSTREAM_SPECS — frozen per-provider descriptor table for the /byok/ leg.
 *
 * Keyed by the URL path segment that appears in position [2] of /byok/<seg>/...
 * Each entry is the sole source of truth for the upstream host and the
 * env-var names for the operator key and base-URL override. All 14 legs use
 * Bearer auth. The handler (src/routes/byok.ts) reads this table at request
 * time; it NEVER derives upstreamHost from the inbound request.
 *
 * Do NOT add entries here without a corresponding host addition in
 * src/lib/outbound-allowlist.ts and env fields in src/index.ts Env.
 */

export interface ByokUpstreamSpec {
  upstreamHost: string;
  operatorKeyVar: string;
  baseUrlVar: string;
}

export const BYOK_UPSTREAM_SPECS: Readonly<Record<string, ByokUpstreamSpec>> = Object.freeze({

  // grok — xAI. XAI_API_KEY / XAI_BASE_URL already present for /v1/grok/ leg.
  grok: {
    upstreamHost: "api.x.ai",
    operatorKeyVar: "XAI_API_KEY",
    baseUrlVar: "XAI_BASE_URL",
  },

  // mistral — Mistral AI.
  mistral: {
    upstreamHost: "api.mistral.ai",
    operatorKeyVar: "MISTRAL_API_KEY",
    baseUrlVar: "MISTRAL_BASE_URL",
  },

  // deepseek — DeepSeek.
  deepseek: {
    upstreamHost: "api.deepseek.com",
    operatorKeyVar: "DEEPSEEK_API_KEY",
    baseUrlVar: "DEEPSEEK_BASE_URL",
  },

  // minimax — MiniMax. // SECURITY-REVIEW: [SR] China-based; data-residency policy applies.
  minimax: {
    upstreamHost: "api.minimax.chat",
    operatorKeyVar: "MINIMAX_API_KEY",
    baseUrlVar: "MINIMAX_BASE_URL",
  },

  // zhipu — Zhipu AI (GLM). // SECURITY-REVIEW: [SR] .cn TLD; data-residency policy applies.
  zhipu: {
    upstreamHost: "open.bigmodel.cn",
    operatorKeyVar: "ZHIPU_API_KEY",
    baseUrlVar: "ZHIPU_BASE_URL",
  },

  // perplexity — Perplexity AI.
  perplexity: {
    upstreamHost: "api.perplexity.ai",
    operatorKeyVar: "PERPLEXITY_API_KEY",
    baseUrlVar: "PERPLEXITY_BASE_URL",
  },

  // cohere — Cohere. Host api.cohere.com (official current domain; .ai is a legacy alias). Operator accepts Cohere data-processing terms.
  cohere: {
    upstreamHost: "api.cohere.com",
    operatorKeyVar: "COHERE_API_KEY",
    baseUrlVar: "COHERE_BASE_URL",
  },

  // moonshot — Moonshot AI (Kimi). Host api.moonshot.ai (international platform default; .cn is the China-region endpoint and 401s for intl keys).
  moonshot: {
    upstreamHost: "api.moonshot.ai",
    operatorKeyVar: "MOONSHOT_API_KEY",
    baseUrlVar: "MOONSHOT_BASE_URL",
  },

  // openrouter — OpenRouter aggregator. // SECURITY-REVIEW: [SR] aggregator; routes to many backends; operator accepts routing policy.
  openrouter: {
    upstreamHost: "openrouter.ai",
    operatorKeyVar: "OPENROUTER_API_KEY",
    baseUrlVar: "OPENROUTER_BASE_URL",
  },

  // vercel — Vercel AI Gateway. Host ai-gateway.vercel.sh (OpenAI-compatible base ai-gateway.vercel.sh/v1, vendor-confirmed).
  vercel: {
    upstreamHost: "ai-gateway.vercel.sh",
    operatorKeyVar: "VERCEL_API_KEY",
    baseUrlVar: "VERCEL_BASE_URL",
  },

  // huggingface — Hugging Face Inference API.
  huggingface: {
    upstreamHost: "router.huggingface.co",
    operatorKeyVar: "HUGGINGFACE_API_KEY",
    baseUrlVar: "HUGGINGFACE_BASE_URL",
  },

  // groq — Groq. // SECURITY-REVIEW: [SR-path] derivedPath starts with /openai/; path prefix differs from seg.
  groq: {
    upstreamHost: "api.groq.com",
    operatorKeyVar: "GROQ_API_KEY",
    baseUrlVar: "GROQ_BASE_URL",
  },

  // together — Together AI.
  together: {
    upstreamHost: "api.together.xyz",
    operatorKeyVar: "TOGETHER_API_KEY",
    baseUrlVar: "TOGETHER_BASE_URL",
  },

  // fireworks — Fireworks AI.
  fireworks: {
    upstreamHost: "api.fireworks.ai",
    operatorKeyVar: "FIREWORKS_API_KEY",
    baseUrlVar: "FIREWORKS_BASE_URL",
  },
});
