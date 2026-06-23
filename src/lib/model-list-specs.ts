/**
 * MODEL_LIST_SPECS — frozen per-provider descriptor for the live-freshness
 * model-list leg (GET, W38-S935: the keystone that makes `[live]` real).
 *
 * Keyed by the DAEMON provider name carried in the `X-Bishop-Provider` header
 * (the keys of daemon/src/model/capability_catalog.PROVIDER_MODEL_LIST_ENDPOINTS),
 * NOT the /byok/<seg> path segment. Each entry is the SOLE source of truth for the
 * upstream host + the model-list path + the upstream auth shape: the route
 * (src/routes/model-list.ts) NEVER derives any of them from the inbound request
 * (the W9.7 SSRF discipline — host + path are server-side, the request is
 * untrusted, exactly like /byok/, /mcp/<server_id> and /model-registry/).
 *
 * `modelListPath` MUST MIRROR the daemon's PROVIDER_MODEL_LIST_ENDPOINTS[provider]
 * (the daemon is the alignment reference). The BYOK upstream hosts are pulled from
 * BYOK_UPSTREAM_SPECS so there is ONE host source-of-truth (no cross-table drift);
 * every host here is ALREADY in ALLOWED_OUTBOUND_HOSTS — this leg adds ZERO egress
 * hosts (it reuses the completion legs' hosts for a read-only GET).
 *
 * credentialSource — where the upstream credential comes from:
 *   "operator"  — managed providers (openai/claude/gemini): the operator key from
 *                 env[operatorKeyVar]. The user's own key is NEVER spent on a
 *                 managed model-list. Fail-closed managed_key_unavailable if unset.
 *   "forwarded" — BYOK/subscription: the user's own key, forwarded by the daemon in
 *                 `X-Bishop-Upstream-Key`. Fail-closed byok_key_missing if absent
 *                 (→ the daemon degrades THAT provider to its bundled catalog, which
 *                 is the honest `[bundled]` surface rather than a masqueraded fresh).
 *
 * auth — how the resolved key is presented upstream:
 *   "bearer"    — Authorization: Bearer <key>   (OpenAI-compatible; the majority)
 *   "anthropic" — x-api-key: <key> + anthropic-version
 *   "query"     — ?key=<key> (Gemini native /v1beta/models)
 *
 * Providers NOT listed here (openai_codex, the BUNDLED_ONLY set, and local
 * ollama/lmstudio/vllm/litellm) resolve unknown_provider → the daemon degrades to
 * the bundled catalog (no regression; they were never freshness-discoverable).
 *
 * Do NOT add an entry whose upstreamHost is not already in
 * src/lib/outbound-allowlist.ts ALLOWED_OUTBOUND_HOSTS (or an anchored enterprise
 * pattern) — a new egress host is a separate, founder-reviewed allowlist add.
 */
import { BYOK_UPSTREAM_SPECS } from "./byok-specs";

export type ModelListAuth = "bearer" | "anthropic" | "query";
export type ModelListCredentialSource = "operator" | "forwarded";

export interface ModelListSpec {
  upstreamHost: string;
  /** MIRRORS daemon capability_catalog.PROVIDER_MODEL_LIST_ENDPOINTS[provider]. */
  modelListPath: string;
  auth: ModelListAuth;
  credentialSource: ModelListCredentialSource;
  /** Required when credentialSource === "operator". */
  operatorKeyVar?: string;
  /** Only for auth === "anthropic". */
  anthropicVersion?: string;
  /** Datacenter-IP-blocked providers routed via Cloudflare AI Gateway (deepseek). */
  aiGatewayProvider?: string;
}

/** Host of a /byok/ provider, single-sourced from BYOK_UPSTREAM_SPECS (no drift). */
function byokHost(seg: string): string {
  const s = BYOK_UPSTREAM_SPECS[seg];
  if (!s) throw new Error(`model-list-specs: unknown byok seg '${seg}'`);
  return s.upstreamHost;
}

export const MODEL_LIST_SPECS: Readonly<Record<string, ModelListSpec>> = Object.freeze({
  // ── Managed (operator key; the user's key is never spent on the managed list) ──
  openai: {
    upstreamHost: "api.openai.com",
    modelListPath: "/v1/models",
    auth: "bearer",
    credentialSource: "operator",
    operatorKeyVar: "OPENAI_API_KEY",
  },
  claude: {
    upstreamHost: "api.anthropic.com",
    modelListPath: "/v1/models",
    auth: "anthropic",
    credentialSource: "operator",
    operatorKeyVar: "ANTHROPIC_API_KEY",
    anthropicVersion: "2023-06-01",
  },
  gemini: {
    upstreamHost: "generativelanguage.googleapis.com",
    modelListPath: "/v1beta/models",
    auth: "query",
    credentialSource: "operator",
    operatorKeyVar: "GEMINI_API_KEY",
  },

  // ── BYOK / subscription (forwarded user key in X-Bishop-Upstream-Key) ──
  grok:          { upstreamHost: byokHost("grok"),       modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  // xai_grok is the subscription bridge to the SAME xAI host (api.x.ai).
  xai_grok:      { upstreamHost: byokHost("grok"),       modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  mistral:       { upstreamHost: byokHost("mistral"),    modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  // deepseek 451s the proxy's direct Worker egress IP — route via Cloudflare AI
  // Gateway when CF_AIG_* is configured, exactly as byok.ts does (gateway host is
  // already allowlisted; falls back to the direct host when AI Gateway is unset).
  deepseek:      { upstreamHost: byokHost("deepseek"),   modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded", aiGatewayProvider: BYOK_UPSTREAM_SPECS.deepseek.aiGatewayProvider },
  together:      { upstreamHost: byokHost("together"),   modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  fireworks:     { upstreamHost: byokHost("fireworks"),  modelListPath: "/inference/v1/models", auth: "bearer", credentialSource: "forwarded" },
  openrouter:    { upstreamHost: byokHost("openrouter"), modelListPath: "/api/v1/models",       auth: "bearer", credentialSource: "forwarded" },
  perplexity:    { upstreamHost: byokHost("perplexity"), modelListPath: "/models",              auth: "bearer", credentialSource: "forwarded" },
  cerebras:      { upstreamHost: byokHost("cerebras"),   modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  moonshot_kimi: { upstreamHost: byokHost("moonshot"),   modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  nvidia_nim:    { upstreamHost: byokHost("nvidia"),     modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  zhipu_glm:     { upstreamHost: byokHost("zhipu"),      modelListPath: "/api/paas/v4/models",  auth: "bearer", credentialSource: "forwarded" },
  groq:          { upstreamHost: byokHost("groq"),       modelListPath: "/openai/v1/models",    auth: "bearer", credentialSource: "forwarded" },
  // W38-S964 — Sakana Fugu exposes an OpenAI-compatible Models API (host single-
  // sourced from the byok sakana leg → api.sakana.ai; zero new egress here).
  sakana_fugu:   { upstreamHost: byokHost("sakana"),     modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  // W38-S966 — 5 OpenAI-compatible open-weights-serving clouds (hosts single-sourced
  // from their byok legs → zero new egress; each path MIRRORS the daemon
  // PROVIDER_MODEL_LIST_ENDPOINTS entry). inference_net is OMITTED — its /v1/models
  // was unconfirmed in docs → BUNDLED_ONLY on the daemon (curated-set only).
  meta_llama:    { upstreamHost: byokHost("meta_llama"),  modelListPath: "/compat/v1/models",    auth: "bearer", credentialSource: "forwarded" },
  deepinfra:     { upstreamHost: byokHost("deepinfra"),   modelListPath: "/v1/openai/models",    auth: "bearer", credentialSource: "forwarded" },
  baseten:       { upstreamHost: byokHost("baseten"),     modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  // SiliconFlow freshness uses the primary (.com) host (default region) — the
  // dual-region selection applies to the completion leg, not the read-only list.
  siliconflow:   { upstreamHost: byokHost("siliconflow"), modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  featherless:   { upstreamHost: byokHost("featherless"), modelListPath: "/v1/models",           auth: "bearer", credentialSource: "forwarded" },
  // W38-S968 — Novita AI exposes an OpenAI-compatible Models API under the same
  // /openai/v1/ prefix as its completion leg (host single-sourced from the byok
  // novita leg → api.novita.ai; zero new egress). MIRRORS the daemon
  // PROVIDER_MODEL_LIST_ENDPOINTS["novita"] entry (no cross-table drift).
  novita:        { upstreamHost: byokHost("novita"),      modelListPath: "/openai/v1/models",    auth: "bearer", credentialSource: "forwarded" },
  // qwen_alibaba: dashscope is NOT a /byok/ leg (its OAuth path is qwen.ts); the
  // host dashscope-intl.aliyuncs.com is already allowlisted for the qwen completion.
  qwen_alibaba:  { upstreamHost: "dashscope-intl.aliyuncs.com", modelListPath: "/compatible-mode/v1/models", auth: "bearer", credentialSource: "forwarded" },
});
