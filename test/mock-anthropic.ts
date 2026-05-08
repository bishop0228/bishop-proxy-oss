/**
 * Mock upstream Anthropic worker for messages.test.ts.
 *
 * The proxy receives a single ANTHROPIC_BASE_URL at startup, so the test
 * harness sets the next mode via a control endpoint before each call:
 *
 *   POST /__set_mode  { mode: "stream-200" | "json-200" | "fail-500"
 *                            | "fail-400" | "flaky-500" }
 *   POST /__reset     — clears flaky attempt counter, mode → "stream-200"
 *   POST /v1/messages — returns according to the currently-set mode
 *
 * Modes:
 *   "stream-200"  200 + canned SSE
 *                 (message_start input=10/cache_read=2; message_delta
 *                  output=5; message_stop)
 *   "json-200"    200 + non-streaming JSON body with usage
 *   "fail-500"    500 — used to verify retry exhaustion / 5xx pass-through
 *   "fail-400"    400 — used to verify NO retry on 4xx
 *   "flaky-500"   500 on attempts 1 and 2, then 200 SSE on attempt 3
 *
 * State is module-local (process-local); vitest runs tests in this describe
 * serially, so global state is safe.
 */

let currentMode = "stream-200";
let flakyAttempts = 0;

function sseFrame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function sseStream(): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const frames = [
    sseFrame("message_start", {
      type: "message_start",
      message: {
        usage: {
          input_tokens: 10,
          output_tokens: 0,
          cache_read_input_tokens: 2,
          cache_creation_input_tokens: 1,
        },
      },
    }),
    sseFrame("content_block_delta", {
      type: "content_block_delta",
      delta: { type: "text_delta", text: "hello" },
    }),
    sseFrame("message_delta", {
      type: "message_delta",
      usage: { output_tokens: 5 },
    }),
    sseFrame("message_stop", { type: "message_stop" }),
  ];
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const f of frames) controller.enqueue(enc.encode(f));
      controller.close();
    },
  });
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__set_mode") {
      const body = (await request.json()) as { mode?: string };
      currentMode = body.mode ?? "stream-200";
      flakyAttempts = 0;
      return new Response(JSON.stringify({ ok: true, mode: currentMode }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/__reset") {
      currentMode = "stream-200";
      flakyAttempts = 0;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname !== "/v1/messages") {
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
    }

    if (currentMode === "fail-500") {
      return new Response("upstream error", { status: 500 });
    }
    if (currentMode === "fail-400") {
      return new Response(JSON.stringify({ error: "bad_request" }), { status: 400 });
    }
    if (currentMode === "flaky-500") {
      flakyAttempts += 1;
      if (flakyAttempts < 3) {
        return new Response("transient", { status: 500 });
      }
      return new Response(sseStream(), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    }
    if (currentMode === "json-200") {
      const body = {
        id: "msg_mock",
        type: "message",
        role: "assistant",
        content: [{ type: "text", text: "hi" }],
        usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 2 },
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(sseStream(), {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  },
};
