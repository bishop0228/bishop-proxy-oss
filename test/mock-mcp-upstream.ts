/**
 * Mock GitHub remote MCP upstream for mcp.test.ts (§1.18.15-MCP-PROXY-V).
 *
 * Records inbound authorization (the rebuilt upstream Bearer), the
 * x-bishop-upstream-key header (which MUST be stripped — never forwarded), the
 * body, and the path so probes can assert SSRF-safe host-derive, Pillar-1
 * identifier-strip, and JSON-RPC pass-through.
 *
 *   POST /__reset              — clear all captured state
 *   GET  /__last_auth          — { auth: string | null }
 *   GET  /__last_upstream_key  — { upstreamKey: string | null }  (expect null — stripped)
 *   GET  /__last_body          — { body: string | null }
 *   GET  /__last_path          — { path: string | null }
 *   POST <any path>            — JSON-RPC reply; SSE (text/event-stream) when ?sse=1
 */

let lastAuth: string | null = null;
let lastUpstreamKey: string | null = null;
let lastBody: string | null = null;
let lastPath: string | null = null;

const MCP_JSON_REPLY = {
  jsonrpc: "2.0",
  id: 1,
  result: { content: [{ type: "text", text: "mock-mcp-ok" }] },
};

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      lastAuth = null;
      lastUpstreamKey = null;
      lastBody = null;
      lastPath = null;
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

    if (request.method === "GET" && url.pathname === "/__last_upstream_key") {
      return new Response(JSON.stringify({ upstreamKey: lastUpstreamKey }), {
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

    if (request.method === "GET" && url.pathname === "/__last_path") {
      return new Response(JSON.stringify({ path: lastPath }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST") {
      lastAuth = request.headers.get("authorization");
      lastUpstreamKey = request.headers.get("x-bishop-upstream-key");
      lastBody = await request.text();
      lastPath = url.pathname;

      // SSE mode — return a Streamable-HTTP text/event-stream the proxy must
      // pass straight through (body ReadableStream forwarded verbatim).
      if (url.searchParams.has("sse")) {
        const sse =
          `event: message\n` +
          `data: ${JSON.stringify(MCP_JSON_REPLY)}\n\n`;
        return new Response(sse, {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        });
      }

      return new Response(JSON.stringify(MCP_JSON_REPLY), {
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
