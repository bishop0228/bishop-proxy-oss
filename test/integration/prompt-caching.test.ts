/**
 * Prompt-caching unit tests.
 *
 * Covers:
 *   1. system cache_control injected on forward when no system field present
 *   2. existing system field is not overwritten
 *   3. cache_creation_input_tokens from SSE flows through to ProxyLogEvent
 *   4. cache_read_input_tokens (cached_tokens) from SSE flows through to ProxyLogEvent
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMessages } from "../../src/routes/messages";
import { isProxyLogEvent } from "../../src/lib/log";
import type { Env } from "../../src/index";
import type { ProxyLogEvent } from "../../src/lib/log";

// ---- stubs (mirrors log-discipline.test.ts makeEnv pattern) -------------

function makeStub(handler: (req: Request) => Promise<Response> | Response) {
  return {
    fetch: async (input: RequestInfo, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input as string, init);
      return handler(req);
    },
  };
}

function makeNamespace(
  handler: (req: Request) => Promise<Response> | Response,
): DurableObjectNamespace {
  return {
    idFromName: (_name: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    idFromString: (_s: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    newUniqueId: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    get: (_id: DurableObjectId) => makeStub(handler) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function makeEnv(): Env {
  const AUTH_STORE = makeNamespace(async (_req) =>
    new Response(
      JSON.stringify({
        valid: true,
        record: {
          token: "bsk_staging_xxxxxxxxxxxxxxxxxxxxxxxx",
          token_id: "33333333-3333-4333-8333-333333333333",
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: "2027-01-01T00:00:00Z",
          fingerprint_hash: "ff".repeat(32),
          status: "active",
          last_seen: null,
          refresh_count: 0,
          client_version: "test-0.1.0",
        },
        reason: null,
      }),
      { headers: { "content-type": "application/json" } },
    ),
  );

  const TIER_CACHE = makeNamespace(async (_req) =>
    new Response(JSON.stringify({ tier: "free" }), {
      headers: { "content-type": "application/json" },
    }),
  );

  const QUOTA_STORE = makeNamespace(async (req) => {
    const url = new URL(req.url);
    if (url.pathname === "/check") {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    if (url.pathname === "/increment") {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({
        monthly_cost_microcents: 0,
        monthly_tasks: 0,
        daily_floor_used: 0,
        period_month: "2026-05",
        period_day: "2026-05-07",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  });

  return {
    AUTH_STORE,
    TIER_CACHE,
    QUOTA_STORE,
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "operator_key_redacted",
    MOCK_AI: "1",
  } as Env;
}

function makeCtx(): { ctx: ExecutionContext; pending: Promise<unknown>[] } {
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (p: Promise<unknown>) => { pending.push(p); },
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
  return { ctx, pending };
}

function sseFrame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function makeSseStream(cacheCreation: number, cacheRead: number): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const frames = [
    sseFrame("message_start", {
      type: "message_start",
      message: {
        usage: {
          input_tokens: 10,
          output_tokens: 0,
          cache_read_input_tokens: cacheRead,
          cache_creation_input_tokens: cacheCreation,
        },
      },
    }),
    sseFrame("message_delta", { type: "message_delta", usage: { output_tokens: 5 } }),
    sseFrame("message_stop", { type: "message_stop" }),
  ];
  return new ReadableStream<Uint8Array>({
    start(c) {
      for (const f of frames) c.enqueue(enc.encode(f));
      c.close();
    },
  });
}

const VALID_BEARER = "Bearer bsk_staging_prompt_caching_test";

// ---- tests ---------------------------------------------------------------

describe("prompt caching", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let capturedBody: unknown;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    capturedBody = undefined;
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("system cache_control injected when no system field is present", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      // Capture the forwarded body.
      capturedBody = JSON.parse((init?.body as string) ?? "{}");
      return new Response(makeSseStream(1, 2), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    });

    try {
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: VALID_BEARER,
        },
        body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
      });
      await handleMessages(req, env, ctx);
      await Promise.allSettled(pending);

      const fwd = capturedBody as Record<string, unknown>;
      expect(Array.isArray(fwd.system)).toBe(true);
      const blocks = fwd.system as Array<Record<string, unknown>>;
      expect(blocks[0].type).toBe("text");
      expect(typeof blocks[0].text).toBe("string");
      expect((blocks[0].text as string).length).toBeGreaterThan(0);
      expect(blocks[0].cache_control).toEqual({ type: "ephemeral" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("existing system field is preserved and not overwritten", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      capturedBody = JSON.parse((init?.body as string) ?? "{}");
      return new Response(makeSseStream(0, 0), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    });

    try {
      const daemonSystem = "You are a summarization bot.";
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: VALID_BEARER,
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5",
          stream: true,
          system: daemonSystem,
        }),
      });
      await handleMessages(req, env, ctx);
      await Promise.allSettled(pending);

      const fwd = capturedBody as Record<string, unknown>;
      expect(fwd.system).toBe(daemonSystem);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("cache_creation_input_tokens from SSE reaches ProxyLogEvent", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      new Response(makeSseStream(7, 0), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    );

    try {
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: VALID_BEARER,
        },
        body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
      });
      const res = await handleMessages(req, env, ctx);
      await res.text();
      await Promise.allSettled(pending);

      // Find the response event emitted by the observer pipeline.
      const responseEvents = logSpy.mock.calls
        .map((c) => JSON.parse(c[0] as string) as ProxyLogEvent)
        .filter((e) => e.event_type === "response");
      expect(responseEvents.length).toBeGreaterThan(0);
      expect(responseEvents[0].cache_creation_input_tokens).toBe(7);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("cache_read_input_tokens from SSE reaches ProxyLogEvent", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      new Response(makeSseStream(0, 13), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    );

    try {
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: VALID_BEARER,
        },
        body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
      });
      const res = await handleMessages(req, env, ctx);
      await res.text();
      await Promise.allSettled(pending);

      const responseEvents = logSpy.mock.calls
        .map((c) => JSON.parse(c[0] as string) as ProxyLogEvent)
        .filter((e) => e.event_type === "response");
      expect(responseEvents.length).toBeGreaterThan(0);
      expect(responseEvents[0].cache_read_input_tokens).toBe(13);
      expect(responseEvents[0].cached_tokens).toBe(13);
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
