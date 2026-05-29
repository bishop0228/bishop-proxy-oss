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

    return new Response(JSON.stringify({ error: "not_found", path: url.pathname }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  },
};

export { TierCacheDO } from "./durable-objects/tier-cache";
export { AuthStoreDO } from "./durable-objects/auth-store";
export { QuotaStoreDO } from "./durable-objects/quota-store";
