/**
 * Mock OpenAI-compatible upstream for non-openai-legs.test.ts and byok-legs.test.ts.
 *
 * Records the inbound Authorization header so probes can assert the proxy
 * forwarded the correct operator key and did not leak client credentials.
 *
 *   POST /v1/chat/completions  — grok + qwen + most byok upstream paths
 *   POST /chat/completions     — gemini upstream path
 *   POST <any other path>      — byok legs with non-standard paths (minimax, groq, etc.)
 *   GET  /__last_auth          — { auth: string | null }
 *   POST /__reset              — clear lastAuth
 */

let lastAuth: string | null = null;

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      lastAuth = null;
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

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      const body = {
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
      return new Response(JSON.stringify(body), {
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
