/**
 * Mock OpenAI-compatible upstream for non-openai-legs.test.ts and byok-legs.test.ts.
 *
 * Records the inbound Authorization header so probes can assert the proxy
 * forwarded the correct operator key and did not leak client credentials.
 *
 *   POST /v1/chat/completions  — grok + qwen + most byok upstream paths
 *   POST /chat/completions     — gemini (OpenAI-compat) upstream path
 *   POST …/models/{m}:generateContent — NATIVE Gemini path (returns a native body,
 *                                        records the x-goog-api-key it was sent)
 *   POST <any other path>      — byok legs with non-standard paths (minimax, groq, etc.)
 *   GET  /__last_auth          — { auth: string | null }
 *   GET  /__last_goog_key      — { key: string | null }  (native Gemini x-goog-api-key)
 *   POST /__reset              — clear lastAuth + lastGoogKey
 */

let lastAuth: string | null = null;
let lastGoogKey: string | null = null;

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      lastAuth = null;
      lastGoogKey = null;
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

    if (request.method === "GET" && url.pathname === "/__last_goog_key") {
      return new Response(JSON.stringify({ key: lastGoogKey }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      lastGoogKey = request.headers.get("x-goog-api-key");
      // NATIVE Gemini generateContent path → native response envelope.
      if (url.pathname.endsWith(":generateContent")) {
        const native = {
          candidates: [
            { content: { role: "model", parts: [{ text: "mock" }] }, finishReason: "STOP" },
          ],
        };
        return new Response(JSON.stringify(native), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
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
