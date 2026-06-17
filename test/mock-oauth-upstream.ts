/**
 * Mock OAuth upstream for oauth-legs.test.ts.
 *
 * Records inbound Authorization, raw body, and X-DashScope-AuthType so probes
 * can assert the proxy forwarded the correct credential and did not leak client
 * identifiers.
 *
 *   POST /__reset          — clear lastAuth, lastBody, lastDashScopeAuthType
 *   GET  /__last_auth      — { auth: string | null }
 *   GET  /__last_body      — { body: string | null }
 *   GET  /__last_headers   — { authType, chatgptAccountId, originator, openaiBeta, accept, sessionId }
 *   POST <any path>        — branch on path:
 *     token paths (includes "oauth" | ends with "/token" | includes "access_token")
 *       → { access_token: "upstream-minted-xyz", token_type: "bearer", expires_in: 3600 }
 *     completion paths
 *       → text/event-stream SSE body when the request Accept is text/event-stream (codex),
 *         else the chatcmpl mock body
 */

let lastAuth: string | null = null;
let lastBody: string | null = null;
let lastDashScopeAuthType: string | null = null;
let lastChatgptAccountId: string | null = null;
let lastOriginator: string | null = null;
let lastOpenAIBeta: string | null = null;
let lastAccept: string | null = null;
let lastSessionId: string | null = null;

const CHATCMPL_BODY = {
  id: "chatcmpl-mock",
  object: "chat.completion",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: "mock" },
      finish_reason: "stop",
    },
  ],
};

// Responses-API SSE body (the codex backend shape) — returned when the inbound
// request asks for text/event-stream so a probe can assert the stream passes
// through the proxy uncorrupted.
const SSE_BODY =
  'data: {"type":"response.created"}\n\n' +
  'data: {"type":"response.output_text.delta","delta":"Hello "}\n\n' +
  'data: {"type":"response.output_text.delta","delta":"world"}\n\n' +
  'data: {"type":"response.completed","response":{"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world"}]}]}}\n\n' +
  "data: [DONE]\n\n";

const TOKEN_BODY = {
  access_token: "upstream-minted-xyz",
  token_type: "bearer",
  expires_in: 3600,
};

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      lastAuth = null;
      lastBody = null;
      lastDashScopeAuthType = null;
      lastChatgptAccountId = null;
      lastOriginator = null;
      lastOpenAIBeta = null;
      lastAccept = null;
      lastSessionId = null;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "GET" && url.pathname === "/__last_auth") {
      return new Response(JSON.stringify({ auth: lastAuth }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "GET" && url.pathname === "/__last_body") {
      return new Response(JSON.stringify({ body: lastBody }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "GET" && url.pathname === "/__last_headers") {
      return new Response(
        JSON.stringify({
          authType: lastDashScopeAuthType,
          chatgptAccountId: lastChatgptAccountId,
          originator: lastOriginator,
          openaiBeta: lastOpenAIBeta,
          accept: lastAccept,
          sessionId: lastSessionId,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    }

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      lastBody = await request.text();
      lastDashScopeAuthType = request.headers.get("x-dashscope-authtype");
      lastChatgptAccountId = request.headers.get("chatgpt-account-id");
      lastOriginator = request.headers.get("originator");
      lastOpenAIBeta = request.headers.get("openai-beta");
      lastAccept = request.headers.get("accept");
      lastSessionId = request.headers.get("session_id");

      const isTokenPath =
        url.pathname.includes("oauth") ||
        url.pathname.endsWith("/token") ||
        url.pathname.includes("access_token");

      if (isTokenPath) {
        return new Response(JSON.stringify(TOKEN_BODY), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      // Completion path. If the caller declared SSE (the codex fingerprint),
      // stream a text/event-stream body so the probe can assert the proxy
      // passes the stream through uncorrupted.
      if ((lastAccept ?? "").includes("text/event-stream")) {
        return new Response(SSE_BODY, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        });
      }
      return new Response(JSON.stringify(CHATCMPL_BODY), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  },
};
