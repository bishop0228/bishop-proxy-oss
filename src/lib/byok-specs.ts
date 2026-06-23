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
  // W38-S966 — multi-region leg (e.g. SiliconFlow .com/.cn). When set, the active
  // upstream host is selected from THIS frozen map by a constrained region token
  // (X-Bishop-Upstream-Region, validated against these keys); an unknown/absent
  // region falls back to `upstreamHost` (the primary). EVERY value here is in
  // ALLOWED_OUTBOUND_HOSTS, so selection NEVER yields a non-enumerated host — the
  // host stays spec-derived, never request-derived (the inbound token only chooses
  // WHICH frozen-allowlisted host, it cannot inject one). See resolveByokUpstreamHost.
  regionHosts?: Readonly<Record<string, string>>;
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

  // W38-S964 — sakana — Sakana Fugu (cloud-only, OpenAI-compatible, subscription).
  // Host api.sakana.ai (the single published API host — base_url
  // https://api.sakana.ai/v1, Bearer key from the Sakana console; live-verified
  // vs console.sakana.ai/get-started 2026-06-23). Added to ALLOWED_OUTBOUND_HOSTS.
  sakana: {
    upstreamHost: "api.sakana.ai",
    operatorKeyVar: "SAKANA_API_KEY",
    baseUrlVar: "SAKANA_BASE_URL",
  },

  // ── W38-S966 — 6 OpenAI-compatible open-weights-serving clouds (founder-approved
  // 2026-06-23). Hosts/paths live-verified vs vendor docs 2026-06-23; all added to
  // ALLOWED_OUTBOUND_HOSTS. The daemon /byok/<seg>/... route maps here; host is
  // spec-derived, never request-controlled (SiliconFlow's region token only selects
  // among its OWN enumerated regionHosts). ──

  // meta_llama — Meta Llama API (PREVIEW). OpenAI-compat ONLY via the daemon's
  // /compat/v1/ path (the bare /v1/ is Meta's own shape; the daemon never routes it).
  meta_llama: {
    upstreamHost: "api.llama.com",
    operatorKeyVar: "META_LLAMA_API_KEY",
    baseUrlVar: "META_LLAMA_BASE_URL",
  },

  // deepinfra — DeepInfra. OpenAI-compat under /v1/openai/ (path carried by the
  // daemon completion_route /byok/deepinfra/v1/openai/...).
  deepinfra: {
    upstreamHost: "api.deepinfra.com",
    operatorKeyVar: "DEEPINFRA_API_KEY",
    baseUrlVar: "DEEPINFRA_BASE_URL",
  },

  // baseten — Baseten Model APIs. PINNED to the unified inference.baseten.co host;
  // per-model model-<id>.api.baseten.co + white-label workspace domains are NOT on
  // the frozen path (only this unified host is allowlisted/supported).
  baseten: {
    upstreamHost: "inference.baseten.co",
    operatorKeyVar: "BASETEN_API_KEY",
    baseUrlVar: "BASETEN_BASE_URL",
  },

  // inference_net — inference.net. The "Catalyst" gateway headers (x-inference-
  // provider*) forward to 3rd-party backends through THIS same host and are NEVER
  // enabled (rebuildByokHeaders strips all client identifiers, so they cannot be
  // forwarded). No freshness leg (its /v1/models was unconfirmed → curated-only).
  inference_net: {
    upstreamHost: "api.inference.net",
    operatorKeyVar: "INFERENCE_NET_API_KEY",
    baseUrlVar: "INFERENCE_NET_BASE_URL",
  },

  // siliconflow — DUAL-REGION. Keys are region-bound (a .com key won't auth .cn)
  // and the host is NOT key-inferable, so the region is selected per-connection by
  // the X-Bishop-Upstream-Region token (validated against regionHosts; default = the
  // .com international host). BOTH hosts are in ALLOWED_OUTBOUND_HOSTS. // SECURITY-REVIEW: [SR] .cn region is China-hosted; data-residency policy applies.
  siliconflow: {
    upstreamHost: "api.siliconflow.com",
    operatorKeyVar: "SILICONFLOW_API_KEY",
    baseUrlVar: "SILICONFLOW_BASE_URL",
    regionHosts: { com: "api.siliconflow.com", cn: "api.siliconflow.cn" },
  },

  // featherless — Featherless AI. Clean OpenAI-compat /v1/. HF-style ids.
  featherless: {
    upstreamHost: "api.featherless.ai",
    operatorKeyVar: "FEATHERLESS_API_KEY",
    baseUrlVar: "FEATHERLESS_BASE_URL",
  },
});

/**
 * Resolve the upstream host for a /byok/ leg (W38-S966).
 *
 * Single-region spec → always `spec.upstreamHost`. Multi-region spec
 * (`regionHosts` set, e.g. SiliconFlow .com/.cn) → the host selected from the
 * FROZEN `regionHosts` map by the constrained `region` token, validated against
 * the map's keys; an unknown/absent token falls back to `spec.upstreamHost` (the
 * primary). The return is ALWAYS one of the spec's enumerated hosts (every one of
 * which is in ALLOWED_OUTBOUND_HOSTS) — the inbound token chooses WHICH frozen
 * host, it can NEVER inject a new one. Keeps the "host is spec-derived, never
 * request-derived" SSRF invariant intact for the multi-region case.
 */
export function resolveByokUpstreamHost(
  spec: ByokUpstreamSpec,
  region: string | null | undefined,
): string {
  if (!spec.regionHosts) return spec.upstreamHost;
  const r = (region ?? "").trim().toLowerCase();
  if (r && Object.prototype.hasOwnProperty.call(spec.regionHosts, r)) {
    return spec.regionHosts[r];
  }
  return spec.upstreamHost;
}
