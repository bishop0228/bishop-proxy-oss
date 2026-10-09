/**
 * W38-S1047 — every route that sends a credential or a token-exchange body follows a redirect only
 * on the same host (founder decision 2026-10-09, option (a)).
 *
 * One entry per upstream call site: all sixteen credential-carrying routes, the OAuth route twice
 * (completion and token). Each entry drives the route's real handler through the three legs in
 * test/helpers/redirect-legs.ts: another host refused by name and never contacted, the same host
 * followed with the same credential, no Location refused. The three anonymous model routes keep
 * their own allowlisted hop loop and are covered by their own tests; the sandboxed-browser leg
 * sends no credential.
 */
import { describe, beforeEach, afterEach, vi } from "vitest";
import { redirectLegs, type RouteUnderTest } from "./helpers/redirect-legs";
import { handleMessages } from "../src/routes/messages";
import { handleChatCompletions } from "../src/routes/chat-completions";
import { handleGemini } from "../src/routes/gemini";
import { handleGeminiNative } from "../src/routes/gemini-native";
import { handleGrok } from "../src/routes/grok";
import { handleQwen } from "../src/routes/qwen";
import { handleByok } from "../src/routes/byok";
import { handleOAuthCompletion, handleOAuthToken } from "../src/routes/oauth";
import { handleVertexToken } from "../src/routes/vertex-token";
import { handleMcp } from "../src/routes/mcp";
import { handleEgress } from "../src/routes/egress";
import { handleProviderFiles } from "../src/routes/provider-files";
import { handleGeminiFiles } from "../src/routes/gemini-files";
import { handleAzure } from "../src/routes/azure";
import { handleBedrock } from "../src/routes/bedrock";
import { handleVertex } from "../src/routes/vertex";
import type { Env } from "../src/index";

const DEVICE = "bsk_staging_" + "v".repeat(24);

function namespace(handler: (req: Request) => Response): DurableObjectNamespace {
  const stub = {
    fetch: async (input: RequestInfo, init?: RequestInit) =>
      handler(input instanceof Request ? input : new Request(input as string, init)),
  };
  return {
    idFromName: () => ({ toString: () => "id" }),
    idFromString: () => ({ toString: () => "id" }),
    newUniqueId: () => ({ toString: () => "id" }),
    get: () => stub,
  } as unknown as DurableObjectNamespace;
}

const json = (v: unknown) =>
  new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });

/** An environment that lets a request through to its upstream: a valid device, quota, classifier. */
function makeEnv(accountMode: "managed" | "byok", extra: Record<string, string> = {}): Env {
  const record = {
    token: DEVICE,
    token_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-s1047",
    account_mode: accountMode,
  };
  return {
    AUTH_STORE: namespace(() => json({ valid: true, record, reason: null })),
    TIER_CACHE: namespace(() => json({ tier: "free" })),
    QUOTA_STORE: namespace(() => json({ ok: true })),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
    ANTHROPIC_API_KEY: "op-anthropic-key",
    OPENAI_API_KEY: "op-openai-key",
    GEMINI_API_KEY: "op-gemini-key",
    XAI_API_KEY: "op-xai-key",
    QWEN_API_KEY: "op-qwen-key",
    ...extra,
  } as unknown as Env;
}

function makeCtx(): ExecutionContext {
  return { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
}

function post(url: string, headers: Record<string, string>, body: string): Request {
  return new Request(url, {
    method: "POST",
    headers: { authorization: `Bearer ${DEVICE}`, "content-type": "application/json", ...headers },
    body,
  });
}

const CHAT_BODY = JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "hi" }] });
const chatOk = () =>
  json({ id: "x", object: "chat.completion", choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });

const ROUTES: Array<[string, () => RouteUnderTest]> = [
  ["messages (managed, operator key)", () => ({
    host: "api.anthropic.com",
    invoke: () => handleMessages(post("http://proxy/v1/messages", {},
      JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 16, messages: [{ role: "user", content: "hi" }] })),
      makeEnv("managed"), makeCtx()),
    ok: () => json({ id: "msg_1", type: "message", role: "assistant", content: [], model: "claude-haiku-4-5",
      usage: { input_tokens: 1, output_tokens: 1 } }),
  })],
  ["chat-completions (managed)", () => ({
    host: "api.openai.com",
    invoke: () => handleChatCompletions(post("http://proxy/v1/chat/completions", {}, CHAT_BODY), makeEnv("managed"), makeCtx()),
    ok: chatOk,
  })],
  ["gemini, OpenAI shape (managed)", () => ({
    host: "generativelanguage.googleapis.com",
    invoke: () => handleGemini(post("http://proxy/gemini/v1/chat/completions", {}, CHAT_BODY), makeEnv("managed"), makeCtx()),
    ok: chatOk,
  })],
  ["gemini native (managed)", () => ({
    host: "generativelanguage.googleapis.com",
    invoke: () => handleGeminiNative(post("http://proxy/v1beta/models/gemini-2.5-flash:generateContent", {},
      JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] })), makeEnv("managed"), makeCtx()),
    ok: () => json({ candidates: [], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 } }),
  })],
  ["grok (managed)", () => ({
    host: "api.x.ai",
    invoke: () => handleGrok(post("http://proxy/grok/v1/chat/completions", {}, CHAT_BODY), makeEnv("managed"), makeCtx()),
    ok: chatOk,
  })],
  ["qwen (managed)", () => ({
    host: "dashscope-intl.aliyuncs.com",
    invoke: () => handleQwen(post("http://proxy/qwen/v1/chat/completions", {}, CHAT_BODY), makeEnv("managed"), makeCtx()),
    ok: chatOk,
  })],
  ["byok spec leg (grok, managed)", () => ({
    host: "api.x.ai",
    invoke: () => handleByok(post("http://proxy/byok/grok/chat/completions", {}, CHAT_BODY), makeEnv("managed"), makeCtx()),
    ok: chatOk,
  })],
  ["oauth completion (openai_codex, the user's access token)", () => ({
    host: "chatgpt.com",
    invoke: () => handleOAuthCompletion(post("http://proxy/v1/openai_codex/responses",
      { "x-bishop-upstream-key": "user-oauth-access-token" }, JSON.stringify({ model: "gpt-6.1-sol", input: "hi" })),
      makeEnv("byok"), makeCtx()),
    ok: () => json({ id: "resp_1", output: [] }),
  })],
  ["oauth token leg (openai_codex, the refresh token in the body)", () => ({
    host: "auth.openai.com",
    credentialIn: "body",
    invoke: () => handleOAuthToken(post("http://proxy/oauth/openai_codex/token",
      { "content-type": "application/x-www-form-urlencoded" },
      "grant_type=refresh_token&refresh_token=user-refresh-token&client_id=app"), makeEnv("byok"), makeCtx()),
    ok: () => json({ access_token: "at", token_type: "Bearer", expires_in: 3600 }),
  })],
  ["vertex token leg (the signed assertion in the body)", () => ({
    host: "oauth2.googleapis.com",
    credentialIn: "body",
    invoke: () => handleVertexToken(post("http://proxy/byok/vertex/token",
      { "content-type": "application/x-www-form-urlencoded" },
      "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=header.claims.signature"),
      makeEnv("byok"), makeCtx()),
    ok: () => json({ access_token: "ya29.x", token_type: "Bearer", expires_in: 3600 }),
  })],
  ["mcp (github, the user's server token)", () => ({
    host: "api.githubcopilot.com",
    invoke: () => handleMcp(post("http://proxy/mcp/github", { "x-bishop-upstream-key": "user-github-token" },
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })),
      makeEnv("managed", { MCP_GITHUB_BASE_URL: "https://api.githubcopilot.com" }), makeCtx()),
    ok: () => json({ jsonrpc: "2.0", id: 1, result: {} }),
  })],
  ["egress (fixed-host worker server, the worker's credential)", () => ({
    host: "api.perplexity.ai",
    invoke: () => handleEgress(post("http://proxy/egress/test-fixed/search?q=bishop",
      { "x-bishop-egress-authorization": "Bearer worker-credential" }, JSON.stringify({ q: "x" })),
      makeEnv("managed"), makeCtx()),
    ok: () => json({ ok: true }),
  })],
  ["provider files (OpenAI upload, a streamed body)", () => ({
    host: "api.openai.com",
    sameHostStatus: 302,
    invoke: () => handleProviderFiles(post("http://proxy/v1/openai/files",
      { "content-type": "multipart/form-data; boundary=--bishopBOUNDARY" }, "----bishopBOUNDARY\r\nRAW-MEDIA\r\n"),
      makeEnv("managed"), makeCtx()),
    ok: () => json({ id: "file-abc" }),
  })],
  ["gemini files (upload, a streamed body)", () => ({
    host: "generativelanguage.googleapis.com",
    sameHostStatus: 302,
    invoke: () => handleGeminiFiles(post("http://proxy/v1beta/files:upload", { "content-type": "application/pdf" },
      "RAW-MEDIA-BYTES"), makeEnv("managed"), makeCtx()),
    ok: () => json({ file: { uri: "https://x/files/abc", name: "files/abc" } }),
  })],
  ["azure (per-account resource, the user's api-key)", () => ({
    host: "myresource.openai.azure.com",
    invoke: () => handleAzure(post("http://proxy/byok/azure/openai/deployments/gpt-4/chat/completions?api-version=2024-02-01",
      { "x-bishop-upstream-key": "myresource:user-azure-key" }, CHAT_BODY), makeEnv("byok"), makeCtx()),
    ok: chatOk,
  })],
  ["bedrock (SigV4-signed with the user's keys)", () => ({
    host: "bedrock-runtime.us-east-1.amazonaws.com",
    invoke: () => handleBedrock(post("http://proxy/byok/bedrock/model/invoke",
      { "x-bishop-upstream-key": "AKIATEST12345678:user-secret-access-key" }, CHAT_BODY), makeEnv("byok"), makeCtx()),
    ok: () => json({ output: { message: { content: [] } } }),
  })],
  ["vertex (per-region, the user's access token)", () => ({
    host: "us-central1-aiplatform.googleapis.com",
    invoke: () => handleVertex(post(
      "http://proxy/byok/vertex/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-pro:generateContent",
      { "x-bishop-upstream-key": "us-central1:ya29.user-token" },
      JSON.stringify({ contents: [{ role: "user", parts: [{ text: "hi" }] }] })), makeEnv("byok"), makeCtx()),
    ok: () => json({ candidates: [] }),
  })],
];

describe("W38-S1047: a credential-carrying route follows a redirect only on the same host", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });
  for (const [label, route] of ROUTES) {
    describe(label, () => {
      redirectLegs(label, route);
    });
  }
});
