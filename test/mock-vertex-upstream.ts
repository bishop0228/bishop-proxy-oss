/**
 * Mock Google Vertex AI upstream for vertex.test.ts (§1.17.19-VERTEX-PROXY-V).
 *
 * Records inbound authorization (Bearer), host, body, and search so probes
 * can assert header correctness, body pass-through, and query-param preservation.
 * The meaningful auth capture is the Authorization header (Bearer token).
 *
 *   POST /__reset          — clear all captured state
 *   GET  /__last_auth      — { auth: string | null }
 *   GET  /__last_host      — { host: string | null }
 *   GET  /__last_body      — { body: string | null }
 *   GET  /__last_search    — { search: string | null }
 *   POST <any path>        — mock Vertex chat completion JSON
 */

let lastAuth: string | null = null;
let lastHost: string | null = null;
let lastBody: string | null = null;
let lastSearch: string | null = null;

const VERTEX_MOCK_BODY = {
  id: "chatcmpl-mock",
  object: "chat.completion",
  created: 1700000000,
  model: "gemini-pro",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: "mock-vertex-response" },
      finish_reason: "stop",
    },
  ],
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
};

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      lastAuth = null;
      lastHost = null;
      lastBody = null;
      lastSearch = null;
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

    if (request.method === "GET" && url.pathname === "/__last_host") {
      return new Response(JSON.stringify({ host: lastHost }), {
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

    if (request.method === "GET" && url.pathname === "/__last_search") {
      return new Response(JSON.stringify({ search: lastSearch }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      lastHost = request.headers.get("host");
      lastBody = await request.text();
      lastSearch = url.search || null;
      return new Response(JSON.stringify(VERTEX_MOCK_BODY), {
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
