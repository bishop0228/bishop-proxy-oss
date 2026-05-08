/**
 * Log-discipline integration test.
 *
 * Audit artifact for the log-content-discipline claim made in the README: the
 * proxy never logs request body content, response body bytes, headers, or
 * fingerprints. The brief specifies a canary-string assertion: drive the
 * route with a body that contains a known marker, capture every console.log
 * call, and assert the marker never appears.
 *
 * Approach: in-process. We stub the DurableObjectNamespace bindings and
 * global.fetch so handleMessages can run directly inside vitest, where
 * vi.spyOn(console, "log") observes every emit. unstable_dev would put the
 * worker in a child workerd process whose stdout is unreachable — for an
 * audit artifact we want every emission, not just stdout snippets.
 *
 * Coverage:
 *   - missing/malformed bearer (auth-gate, no DO calls)
 *   - bad_json / unsupported_model (body-validation paths)
 *   - 200 success path including waitUntil() observer pipeline
 *   - upstream 4xx pass-through and 5xx retry-exhaustion
 *
 * For every path we assert:
 *   1. Every console.log argument is a valid JSON string.
 *   2. Every parsed event is a ProxyLogEvent (shape allowlist).
 *   3. The canary string never appears in any logged JSON.
 *   4. Header-derived values (Authorization, x-api-key) never appear either.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMessages } from "../../src/routes/messages";
import { isProxyLogEvent } from "../../src/lib/log";
import type { Env } from "../../src/index";

const CANARY = "BISHOP_TEST_CANARY_8a3f";
const SECRET_AUTH = "BISHOP_SECRET_AUTH_HEADER_e2c1";
const SECRET_API_KEY = "BISHOP_OPERATOR_KEY_4d7b";

// ---- minimal Env stubs --------------------------------------------------

function makeStub(handler: (req: Request) => Promise<Response> | Response) {
  return {
    fetch: async (input: RequestInfo, init?: RequestInit) => {
      const req = input instanceof Request
        ? input
        : new Request(input as string, init);
      return handler(req);
    },
  };
}

function makeNamespace(handler: (req: Request) => Promise<Response> | Response): DurableObjectNamespace {
  return {
    idFromName: (_name: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    idFromString: (_s: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    newUniqueId: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    get: (_id: DurableObjectId) => makeStub(handler) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

interface QuotaState {
  monthly_cost_cents: number;
  monthly_tasks: number;
  daily_floor_used: number;
  period_month: string;
  period_day: string;
}

function makeEnv(opts: {
  validToken?: boolean;
  tier?: string;
  quotaCheckOk?: boolean;
  quotaState?: QuotaState | null;
} = {}): Env {
  const validToken = opts.validToken ?? true;
  const tier = opts.tier ?? "free";
  const quotaCheckOk = opts.quotaCheckOk ?? true;
  const quotaState = opts.quotaState ?? {
    monthly_cost_cents: 0,
    monthly_tasks: 0,
    daily_floor_used: 0,
    period_month: "2026-04",
    period_day: "2026-04-28",
  };

  const AUTH_STORE = makeNamespace(async (req) => {
    const url = new URL(req.url);
    if (url.pathname === "/verify-token") {
      if (!validToken) {
        return new Response(JSON.stringify({ valid: false, record: null, reason: "not_found" }),
          { headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({
        valid: true,
        record: {
          token: "bsk_staging_xxxxxxxxxxxxxxxxxxxxxxxx",
          token_id: "11111111-1111-4111-8111-111111111111",
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: "2027-01-01T00:00:00Z",
          fingerprint_hash: "ff".repeat(32),
          status: "active",
          last_seen: null,
          refresh_count: 0,
          client_version: "test-0.1.0",
        },
        reason: null,
      }), { headers: { "content-type": "application/json" } });
    }
    return new Response("not_found", { status: 404 });
  });

  const TIER_CACHE = makeNamespace(async (_req) => {
    return new Response(JSON.stringify({ tier }), {
      headers: { "content-type": "application/json" },
    });
  });

  const QUOTA_STORE = makeNamespace(async (req) => {
    const url = new URL(req.url);
    if (url.pathname === "/check") {
      if (!quotaCheckOk) {
        return new Response(JSON.stringify({ ok: false, reason: "monthly_cost_exceeded" }),
          { status: 429, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ ok: true }),
        { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/increment") {
      return new Response(JSON.stringify({ ok: true }),
        { headers: { "content-type": "application/json" } });
    }
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(JSON.stringify(quotaState ?? {}),
        { status: quotaState ? 200 : 404, headers: { "content-type": "application/json" } });
    }
    return new Response("not_found", { status: 404 });
  });

  return {
    TIER_CACHE,
    AUTH_STORE,
    QUOTA_STORE,
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: SECRET_API_KEY,
    MOCK_AI: "1",
  } as Env;
}

// ---- ExecutionContext stub that awaits waitUntil -------------------------

function makeCtx(): { ctx: ExecutionContext; pending: Promise<unknown>[] } {
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (p: Promise<unknown>) => { pending.push(p); },
    passThroughOnException: () => { /* noop */ },
  } as unknown as ExecutionContext;
  return { ctx, pending };
}

// ---- canned upstream SSE -------------------------------------------------

function sseFrame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function cannedSseStream(): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const frames = [
    sseFrame("message_start", {
      type: "message_start",
      message: { usage: { input_tokens: 10, output_tokens: 0, cache_read_input_tokens: 2, cache_creation_input_tokens: 1 } },
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

// ---- assertion helpers ---------------------------------------------------

function assertNoLeak(spy: ReturnType<typeof vi.spyOn>): void {
  for (const call of spy.mock.calls) {
    const arg = call[0];
    expect(typeof arg).toBe("string");
    const text = arg as string;
    expect(text).not.toContain(CANARY);
    expect(text).not.toContain(SECRET_AUTH);
    expect(text).not.toContain(SECRET_API_KEY);
    expect(text).not.toContain("fingerprint");
    expect(text).not.toContain("anthropic-version");
    let parsed: unknown;
    expect(() => { parsed = JSON.parse(text); }).not.toThrow();
    expect(isProxyLogEvent(parsed)).toBe(true);
  }
}

// ---- tests ---------------------------------------------------------------

describe("log discipline (canary integration)", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("missing_bearer: canary in body never reaches log", async () => {
    const env = makeEnv();
    const { ctx } = makeCtx();
    const body = JSON.stringify({ model: "claude-haiku-4-5", stream: true, marker: CANARY });
    const req = new Request("http://proxy/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "10.1.2.3" },
      body,
    });
    const res = await handleMessages(req, env, ctx);
    expect(res.status).toBe(401);
    assertNoLeak(logSpy);
  });

  it("token_not_found: bearer + canary body never reach log", async () => {
    const env = makeEnv({ validToken: false });
    const { ctx } = makeCtx();
    const body = JSON.stringify({ model: "claude-haiku-4-5", stream: true, marker: CANARY });
    const req = new Request("http://proxy/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
      },
      body,
    });
    const res = await handleMessages(req, env, ctx);
    expect(res.status).toBe(401);
    assertNoLeak(logSpy);
  });

  it("bad_json: malformed body containing canary never reaches log", async () => {
    const env = makeEnv();
    const { ctx } = makeCtx();
    const req = new Request("http://proxy/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
      },
      body: `{ "marker": "${CANARY}", `,
    });
    const res = await handleMessages(req, env, ctx);
    expect(res.status).toBe(400);
    assertNoLeak(logSpy);
  });

  it("unsupported_model: model + canary body never reach log", async () => {
    const env = makeEnv();
    const { ctx } = makeCtx();
    const body = JSON.stringify({ model: "gpt-4", marker: CANARY });
    const req = new Request("http://proxy/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
      },
      body,
    });
    const res = await handleMessages(req, env, ctx);
    expect(res.status).toBe(400);
    assertNoLeak(logSpy);
  });

  it("200 success path: canary in body + upstream SSE never reach log", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response(cannedSseStream(), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    });

    try {
      const body = JSON.stringify({
        model: "claude-haiku-4-5",
        stream: true,
        messages: [{ role: "user", content: `please remember ${CANARY}` }],
      });
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
        },
        body,
      });
      const res = await handleMessages(req, env, ctx);
      expect(res.status).toBe(200);

      // Drain client body so we don't leave a dangling stream, and so the
      // observer branch (tee'd) flows through extractUsageFromSSE.
      const text = await res.text();
      expect(text).toContain("event: message_stop");

      // Wait for waitUntil() observer to finish (usage extraction + log emit).
      await Promise.allSettled(pending);

      assertNoLeak(logSpy);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("upstream 400 pass-through: no body bytes leak to log", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response(JSON.stringify({ error: "bad_request" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    });

    try {
      const body = JSON.stringify({
        model: "claude-haiku-4-5",
        stream: true,
        messages: [{ role: "user", content: CANARY }],
      });
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
        },
        body,
      });
      const res = await handleMessages(req, env, ctx);
      expect(res.status).toBe(400);
      await res.text();
      await Promise.allSettled(pending);
      assertNoLeak(logSpy);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("upstream 500 retry-exhaustion: no leak across retry attempts", async () => {
    const env = makeEnv();
    const { ctx, pending } = makeCtx();

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response("upstream error", { status: 500 });
    });

    try {
      const body = JSON.stringify({
        model: "claude-haiku-4-5",
        stream: true,
        messages: [{ role: "user", content: CANARY }],
      });
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
        },
        body,
      });
      const res = await handleMessages(req, env, ctx);
      expect(res.status).toBe(500);
      await res.text();
      await Promise.allSettled(pending);
      assertNoLeak(logSpy);
    } finally {
      fetchSpy.mockRestore();
    }
  }, 10000);

  it("emit-on-success contains structured fields ONLY (allowlist enforced)", async () => {
    // Independent assertion: every emitted event parses to exactly the
    // ProxyLogEvent allowlist key-set; spy.mock.calls cover the full set.
    const env = makeEnv();
    const { ctx, pending } = makeCtx();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      return new Response(cannedSseStream(), {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    });
    try {
      const req = new Request("http://proxy/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${SECRET_AUTH}thispadsto16chars`,
        },
        body: JSON.stringify({ model: "claude-haiku-4-5", stream: true }),
      });
      const res = await handleMessages(req, env, ctx);
      expect(res.status).toBe(200);
      await res.text();
      await Promise.allSettled(pending);

      // At least one event emitted (the response event from the observer).
      expect(logSpy.mock.calls.length).toBeGreaterThan(0);
      for (const call of logSpy.mock.calls) {
        const parsed = JSON.parse(call[0] as string);
        expect(isProxyLogEvent(parsed)).toBe(true);
      }
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
