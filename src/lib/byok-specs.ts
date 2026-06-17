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
  // When set, route this provider's upstream through Cloudflare AI Gateway
  // (gateway.ai.cloudflare.com/v1/<acct>/<gw>/<aiGatewayProvider>/...) instead of
  // a direct fetch to upstreamHost. Required for providers that block the
  // proxy's raw Worker egress IP — e.g. DeepSeek returns HTTP 451 to Cloudflare
  // datacenter IPs on a direct fetch, but accepts AI Gateway's managed egress.
  // The value is the AI Gateway provider slug. Falls back to the direct path
  // when the CF_AIG_* env is unset (no regression). gateway.ai.cloudflare.com is
  // already in ALLOWED_OUTBOUND_HOSTS (§H-DYNAMIC), so this widens nothing.
  aiGatewayProvider?: string;
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

  // deepseek — DeepSeek. Routed via Cloudflare AI Gateway: DeepSeek 451s the
  // proxy's direct Worker egress IP (datacenter-IP block), but accepts AI
  // Gateway's egress (architect-verified 2026-06-16, HTTP 200 through bishop-prod).
  deepseek: {
    upstreamHost: "api.deepseek.com",
    operatorKeyVar: "DEEPSEEK_API_KEY",
    baseUrlVar: "DEEPSEEK_BASE_URL",
    aiGatewayProvider: "deepseek",
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

  // §H-DYNAMIC 2026-05-30 — OpenClaw-parity expansion (founder-signed-off)
  // cerebras — Cerebras Inference (fast LLM inference).
  cerebras: {
    upstreamHost: "api.cerebras.ai",
    operatorKeyVar: "CEREBRAS_API_KEY",
    baseUrlVar: "CEREBRAS_BASE_URL",
  },

  // cloudflare — Cloudflare AI Gateway.
  cloudflare: {
    upstreamHost: "gateway.ai.cloudflare.com",
    operatorKeyVar: "CLOUDFLARE_AI_API_KEY",
    baseUrlVar: "CLOUDFLARE_AI_BASE_URL",
  },

  // nvidia — NVIDIA NIM.
  nvidia: {
    upstreamHost: "integrate.api.nvidia.com",
    operatorKeyVar: "NVIDIA_API_KEY",
    baseUrlVar: "NVIDIA_BASE_URL",
  },

  // tencent — Tencent Hunyuan. // SECURITY-REVIEW: [SR] China-based; data-residency policy applies.
  tencent: {
    upstreamHost: "api.hunyuan.cloud.tencent.com",
    operatorKeyVar: "TENCENT_HUNYUAN_API_KEY",
    baseUrlVar: "TENCENT_HUNYUAN_BASE_URL",
  },

  // volcengine — Volcengine Ark (ByteDance Doubao). // SECURITY-REVIEW: [SR] China-based; data-residency policy applies.
  volcengine: {
    upstreamHost: "ark.cn-beijing.volces.com",
    operatorKeyVar: "VOLCENGINE_ARK_API_KEY",
    baseUrlVar: "VOLCENGINE_ARK_BASE_URL",
  },
});
