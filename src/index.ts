/**
 * Bishop proxy entrypoint.
 *
 * Routes:
 *   /v1/tier, /stripe/webhook
 *   /v1/challenge, /v1/enroll, /v1/messages, /v1/tier/bind, /v1/quota
 */

// No-exfiltration enforcement: block outbound fetches to any host other than
// api.anthropic.com. Lazily installed on first request (env not available at
// module load time). ANTHROPIC_BASE_URL must point to an allowed host or the
// first request fails closed with AnthropicBaseUrlNotAllowed (HTTP 500).
import {
  installFetchAllowlist,
  AnthropicBaseUrlNotAllowed,
  ALLOWED_OUTBOUND_HOSTS,
  _setAllowlistForTesting,
} from "./lib/outbound-allowlist";
let _allowlistInstalled = false;

import { handleTierGet } from "./routes/tier";
import { handleStripeWebhook } from "./routes/stripe";
import { handleChallenge } from "./routes/challenge";
import { handleEnroll } from "./routes/enroll";
import { handleMessages } from "./routes/messages";
import { handleChatCompletions } from "./routes/chat-completions";
import { handleGrok } from "./routes/grok";
import { handleQwen } from "./routes/qwen";
import { handleGemini } from "./routes/gemini";
import { handleTierBind } from "./routes/tier-bind";
import { handleQuotaGet } from "./routes/quota";
import { handleAdminRateLimitClear } from "./routes/admin-rate-limit-clear";
import { handleAdminTokenRevoke } from "./routes/admin-token-revoke";
import { handleByok } from "./routes/byok";
import { handleBedrock } from "./routes/bedrock";
import { handleAzure } from "./routes/azure";
import { handleVertex } from "./routes/vertex";
import { handleVertexToken } from "./routes/vertex-token";
import { handleOAuthToken, handleOAuthCompletion } from "./routes/oauth";
import { OAUTH_UPSTREAM_SPECS } from "./lib/oauth-specs";
import { handleMcp } from "./routes/mcp";
import { handleModelRegistry } from "./routes/model-registry";
import { handleEgress } from "./routes/egress";
import { handleBrowserEgress } from "./routes/browser-egress";

export interface Env {
  TIER_CACHE: DurableObjectNamespace;
  AUTH_STORE: DurableObjectNamespace; // AuthStoreDO
  QUOTA_STORE: DurableObjectNamespace; // QuotaStoreDO
  ENROLL_KV: KVNamespace;
  STRIPE_WEBHOOK_SECRET: string;
  ANTHROPIC_API_KEY: string;
  OPENAI_API_KEY?: string;
  OPENAI_BASE_URL?: string;
  XAI_API_KEY?: string;
  XAI_BASE_URL?: string;
  QWEN_API_KEY?: string;
  QWEN_BASE_URL?: string;
  GEMINI_API_KEY?: string;
  GEMINI_BASE_URL?: string;
  MISTRAL_API_KEY?: string;
  MISTRAL_BASE_URL?: string;
  DEEPSEEK_API_KEY?: string;
  DEEPSEEK_BASE_URL?: string;
  MINIMAX_API_KEY?: string;
  MINIMAX_BASE_URL?: string;
  ZHIPU_API_KEY?: string;
  ZHIPU_BASE_URL?: string;
  PERPLEXITY_API_KEY?: string;
  PERPLEXITY_BASE_URL?: string;
  COHERE_API_KEY?: string;
  COHERE_BASE_URL?: string;
  MOONSHOT_API_KEY?: string;
  MOONSHOT_BASE_URL?: string;
  OPENROUTER_API_KEY?: string;
  OPENROUTER_BASE_URL?: string;
  VERCEL_API_KEY?: string;
  VERCEL_BASE_URL?: string;
  HUGGINGFACE_API_KEY?: string;
  HUGGINGFACE_BASE_URL?: string;
  GROQ_API_KEY?: string;
  GROQ_BASE_URL?: string;
  TOGETHER_API_KEY?: string;
  TOGETHER_BASE_URL?: string;
  FIREWORKS_API_KEY?: string;
  FIREWORKS_BASE_URL?: string;
  // §1.17.16 OAuth subscription leg base-URL overrides (test seam)
  OPENAI_CODEX_TOKEN_BASE_URL?: string;
  OPENAI_CODEX_COMPLETION_BASE_URL?: string;
  XAI_GROK_TOKEN_BASE_URL?: string;
  XAI_GROK_COMPLETION_BASE_URL?: string;
  GITHUB_COPILOT_TOKEN_BASE_URL?: string;
  GITHUB_COPILOT_COMPLETION_BASE_URL?: string;
  QWEN_ALIBABA_TOKEN_BASE_URL?: string;
  QWEN_ALIBABA_COMPLETION_BASE_URL?: string;
  NOUS_PORTAL_TOKEN_BASE_URL?: string;
  NOUS_PORTAL_COMPLETION_BASE_URL?: string;
  // §1.17.17 AWS Bedrock SigV4 BYOK leg base-URL override (test seam)
  BEDROCK_BASE_URL?: string;
  // §1.17.18 Azure OpenAI BYOK leg base-URL override (test seam)
  AZURE_BASE_URL?: string;
  // §1.17.19 Google Vertex AI BYOK leg base-URL override (test seam)
  VERTEX_BASE_URL?: string;
  // §1.17.19 Vertex SA-token mint leg base-URL override (test seam)
  VERTEX_TOKEN_BASE_URL?: string;
  // §1.18.15 MCP-forward leg per-server base-URL override (test seam)
  MCP_GITHUB_BASE_URL?: string;
  // W38-S735 per-account remote MCP per-server base-URL overrides (test seam only)
  MCP_SNOWFLAKE_BASE_URL?: string;
  MCP_NETSUITE_BASE_URL?: string;
  MCP_DATABRICKS_BASE_URL?: string;
  MCP_SHOPIFY_BASE_URL?: string;
  // W38-S736 fixed-host remote MCP per-server base-URL overrides (test seam only)
  MCP_MICROSOFT_365_BASE_URL?: string;
  MCP_ONEDRIVE_SHAREPOINT_BASE_URL?: string;
  MCP_SALESFORCE_BASE_URL?: string;
  // B1 governed model-registry egress base-URL override (test seam only)
  OLLAMA_REGISTRY_BASE_URL?: string;
  USER_INDEX_HMAC_KEY: string;
  ADMIN_TOKEN: string;
  CHALLENGE_TTL?: string;
  TARGET_ZERO_BITS?: string;
  TARGET_MEMORY_KIB?: string;
  AI: Ai;
  MOCK_AI?: string;
  CLASSIFIER_MODEL?: string;
  CLASSIFIER_URL?: string;
  // Test-only: comma-separated extra hostnames added to the outbound allowlist
  // via _setAllowlistForTesting. Never set in production. Mirrors the MOCK_AI
  // pattern — present in the bundle but only activated in test deployments.
  BISHOP_TEST_OUTBOUND_HOSTS?: string;
  // Test-only: override token TTL in ms for expired-verdict testing. Negative
  // value produces a token already expired at issuance. Never set in production.
  BISHOP_TEST_TOKEN_TTL_MS?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!_allowlistInstalled) {
      installFetchAllowlist();

      // Test seam: widen allowlist to include mock server hosts when
      // BISHOP_TEST_OUTBOUND_HOSTS is set. Never set in production.
      const testHostsStr = env.BISHOP_TEST_OUTBOUND_HOSTS;
      if (testHostsStr) {
        const extra = testHostsStr.split(",").map((h) => h.trim()).filter(Boolean);
        _setAllowlistForTesting([...(ALLOWED_OUTBOUND_HOSTS as readonly string[]), ...extra]);
      }

      // Fail closed if ANTHROPIC_BASE_URL is misconfigured to a host outside
      // the effective allowlist. Catches env var mistakes before the first
      // upstream fetch, not after a partial request completes.
      const baseUrlStr = (env as Env & { ANTHROPIC_BASE_URL?: string }).ANTHROPIC_BASE_URL;
      if (baseUrlStr) {
        let baseHost: string;
        try {
          baseHost = new URL(baseUrlStr).hostname;
        } catch {
          return new Response(
            JSON.stringify({ error: "invalid_anthropic_base_url" }),
            { status: 500, headers: { "content-type": "application/json" } },
          );
        }
        const testHosts = testHostsStr?.split(",").map((h) => h.trim()).filter(Boolean) ?? [];
        const effectiveHosts = new Set<string>([
          ...(ALLOWED_OUTBOUND_HOSTS as readonly string[]),
          ...testHosts,
        ]);
        if (!effectiveHosts.has(baseHost)) {
          const err = new AnthropicBaseUrlNotAllowed(baseHost);
          return new Response(
            JSON.stringify({ error: "anthropic_base_url_not_allowed", host: err.host }),
            { status: 500, headers: { "content-type": "application/json" } },
          );
        }
      }

      _allowlistInstalled = true;
    }

    const url = new URL(request.url);

    // Admin routes — registered before public routes to prevent shadowing.
    if (request.method === "POST" && url.pathname === "/admin/rate-limit/clear") {
      return handleAdminRateLimitClear(request, env);
    }
    if (request.method === "POST" && url.pathname === "/admin/token/revoke") {
      return handleAdminTokenRevoke(request, env);
    }

    if (request.method === "GET" && url.pathname === "/v1/tier") {
      return handleTierGet(request, env);
    }
    if (request.method === "POST" && url.pathname === "/stripe/webhook") {
      return handleStripeWebhook(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v1/challenge") {
      return handleChallenge(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v1/enroll") {
      return handleEnroll(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v1/messages") {
      return handleMessages(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
      return handleChatCompletions(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname === "/v1/grok/chat/completions") {
      return handleGrok(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname === "/v1/qwen/chat/completions") {
      return handleQwen(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname === "/v1/gemini/chat/completions") {
      return handleGemini(request, env, ctx);
    }
    // W38-S822-FIX (S5b-1) — server_id-keyed generic forward egress route. The
    // worker-microVM's vsock relay forwards a guest's outbound request here; the
    // proxy forwards on, with the upstream host derived SERVER-SIDE from the
    // frozen CLASS_B_EGRESS_SPECS entry keyed by <server_id> (never the request,
    // SSRF-safe — the W9.7 /mcp/<server_id> discipline).
    if (request.method === "POST" && url.pathname.startsWith("/egress/")) {
      return handleEgress(request, env, ctx);
    }
    // W38-S827 (S5c-3b) — the §3.2 leg-4 sandboxed-browser egress route. UNLIKE
    // /egress/<server_id> (host server-side from a frozen spec), the destination
    // is REQUEST-determined (the open web the browser is driven to) — made safe
    // by VM isolation (the browser holds no user data) + SSRF-gating, not by an
    // allowlist. See strongest_claims_security.md §3.2 leg 4.
    if (request.method === "POST" && url.pathname === "/browser-egress") {
      return handleBrowserEgress(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname === "/v1/tier/bind") {
      return handleTierBind(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v1/quota") {
      return handleQuotaGet(request, env, ctx);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response(JSON.stringify({ ok: true, service: "bishop-proxy" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname.startsWith("/byok/bedrock/")) {
      return handleBedrock(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname.startsWith("/byok/azure/")) {
      return handleAzure(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname === "/byok/vertex/token") {
      return handleVertexToken(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname.startsWith("/byok/vertex/")) {
      return handleVertex(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname.startsWith("/byok/")) {
      return handleByok(request, env, ctx);
    }

    // §1.18.15 — MCP-forward egress route (operational, not inference).
    if (request.method === "POST" && url.pathname.startsWith("/mcp/")) {
      return handleMcp(request, env, ctx);
    }

    // B1 — governed model-registry egress (read-only GET; frozen Ollama registry
    // host; operational, not inference).
    if (request.method === "GET" && url.pathname.startsWith("/model-registry/")) {
      return handleModelRegistry(request, env, ctx);
    }

    if (request.method === "POST" && url.pathname.startsWith("/oauth/")) {
      return handleOAuthToken(request, env, ctx);
    }
    if (request.method === "POST" && url.pathname.startsWith("/v1/")
        && OAUTH_UPSTREAM_SPECS[url.pathname.split("/")[2] ?? ""]) {
      return handleOAuthCompletion(request, env, ctx);
    }

    return new Response(JSON.stringify({ error: "not_found", path: url.pathname }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  },
};

export { TierCacheDO } from "./durable-objects/tier-cache";
export { AuthStoreDO } from "./durable-objects/auth-store";
export { QuotaStoreDO } from "./durable-objects/quota-store";
