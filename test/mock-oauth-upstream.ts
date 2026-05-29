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
 *   GET  /__last_headers   — { authType: string | null }
 *   POST <any path>        — branch on path:
 *     token paths (includes "oauth" | ends with "/token" | includes "access_token")
 *       → { access_token: "upstream-minted-xyz", token_type: "bearer", expires_in: 3600 }
 *     completion paths
 *       → chatcmpl mock body
 */

let lastAuth: string | null = null;
let lastBody: string | null = null;
let lastDashScopeAuthType: string | null = null;

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
      return new Response(JSON.stringify({ authType: lastDashScopeAuthType }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      lastBody = await request.text();
      lastDashScopeAuthType = request.headers.get("x-dashscope-authtype");

      const isTokenPath =
        url.pathname.includes("oauth") ||
        url.pathname.endsWith("/token") ||
        url.pathname.includes("access_token");

      const responseBody = isTokenPath ? TOKEN_BODY : CHATCMPL_BODY;
      return new Response(JSON.stringify(responseBody), {
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
