/**
 * Mock AWS Bedrock upstream for bedrock.test.ts (§1.17.17-BEDROCK-PROXY-V).
 *
 * Records inbound Authorization, x-amz-date, host, and raw body so probes
 * can assert SigV4 correctness and byte-exact body forwarding.
 *
 *   POST /__reset          — clear all captured state
 *   GET  /__last_auth      — { auth: string | null }
 *   GET  /__last_amzdate   — { amzDate: string | null }
 *   GET  /__last_host      — { host: string | null }
 *   GET  /__last_body      — { body: string | null }
 *   POST <any path>        — { modelStreamResponse: "mock-bedrock-response" }
 */

let lastAuth: string | null = null;
let lastAmzDate: string | null = null;
let lastHost: string | null = null;
let lastBody: string | null = null;

const BEDROCK_MOCK_BODY = {
  output: {
    message: {
      role: "assistant",
      content: [{ type: "text", text: "mock-bedrock-response" }],
    },
  },
  stopReason: "end_turn",
};

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      lastAuth = null;
      lastAmzDate = null;
      lastHost = null;
      lastBody = null;
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

    if (request.method === "GET" && url.pathname === "/__last_amzdate") {
      return new Response(JSON.stringify({ amzDate: lastAmzDate }), {
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

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      lastAmzDate = request.headers.get("x-amz-date");
      lastHost = request.headers.get("host");
      lastBody = await request.text();
      return new Response(JSON.stringify(BEDROCK_MOCK_BODY), {
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
