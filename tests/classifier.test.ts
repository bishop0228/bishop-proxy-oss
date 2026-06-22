/**
 * Classifier unit tests.
 *
 * Branch coverage: allow / block / timeout / ai-error /
 *   resolveModel / classifyViaUrl / allow-path audit event shape.
 * MOCK_AI is NOT used here — these tests exercise the real classifier logic
 * with stubbed env.AI implementations.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect, vi, afterEach } from "vitest";
import { classify, resolveModel, classifyViaUrl, VETTED_CLASSIFIER_MODELS, type ClassifierResult } from "../src/lib/classifier";
import { isProxyLogEvent } from "../src/lib/log";
import { classificationGate } from "../src/routes/messages";
import type { Env } from "../src/index";

function makeEnv(aiRun: (model: string, input: unknown) => Promise<unknown>, extra?: Partial<Env>): Env {
  return {
    AI: { run: aiRun } as unknown as Ai,
    MOCK_AI: undefined,
    ...extra,
  } as unknown as Env;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("classify()", () => {
  it("allow: AI returns 'safe'", async () => {
    const env = makeEnv(async () => ({ response: "safe" }));
    const result = await classify({ messages: [{ role: "user", content: "hello" }] }, env);
    expect(result.decision).toBe("allow");
    expect(result.category).toBe(null);
    expect(result.classifier_error_reason).toBe(null);
  });

  it("block: AI returns 'unsafe\\nS4'", async () => {
    const env = makeEnv(async () => ({ response: "unsafe\nS4" }));
    const result = await classify({ messages: [{ role: "user", content: "bad content" }] }, env);
    expect(result.decision).toBe("block");
    expect(result.category).toBe("csam");
    expect(result.classifier_error_reason).toBe(null);
  });

  it("allow: non-CSAM unsafe category (S9 weapons) is allowed but still classified", async () => {
    const env = makeEnv(async () => ({ response: "unsafe\nS9" }));
    const result = await classify({ messages: [{ role: "user", content: "borderline" }] }, env);
    // CSAM-class only blocks; every other unsafe category proceeds (provider safety
    // is the backstop) but the category is still surfaced for transparency/logging.
    expect(result.decision).toBe("allow");
    expect(result.category).toBe("weapons");
    expect(result.classifier_error_reason).toBe(null);
  });

  it("allow: unmapped unsafe category (S1 → 'other') is allowed but still classified", async () => {
    const env = makeEnv(async () => ({ response: "unsafe\nS1" }));
    const result = await classify({ messages: [{ role: "user", content: "borderline" }] }, env);
    expect(result.decision).toBe("allow");
    expect(result.category).toBe("other");
    expect(result.classifier_error_reason).toBe(null);
  });

  it("timeout on BOTH attempts → fail-closed UNAVAILABLE (not block), retried", async () => {
    const run = vi.fn(async () => {
      await new Promise((r) => setTimeout(r, 3000));
      return { response: "safe" };
    });
    const env = makeEnv(run);
    const result = await classify({ messages: [] }, env);
    // ERROR ≠ VERDICT: a classifier availability failure is "unavailable" (→ 503),
    // never "block" (→ 451 content-policy). W38-S949.
    expect(result.decision).toBe("unavailable");
    expect(result.classifier_error_reason).toBe("timeout");
    expect(run).toHaveBeenCalledTimes(2); // bounded retry on transient error
  }, 12000);

  it("ai-error on BOTH attempts → fail-closed UNAVAILABLE (not block), retried", async () => {
    const run = vi.fn(async () => {
      throw new Error("AI binding unavailable");
    });
    const env = makeEnv(run);
    const result = await classify({ messages: [] }, env);
    expect(result.decision).toBe("unavailable");
    expect(result.classifier_error_reason).toBe("ai_binding_error");
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("transient blip: attempt 1 errors, retry returns 'safe' → ALLOW (the fix target)", async () => {
    let n = 0;
    const run = vi.fn(async () => {
      n += 1;
      if (n === 1) throw new Error("transient AI binding blip");
      return { response: "safe" };
    });
    const env = makeEnv(run);
    const result = await classify({ messages: [{ role: "user", content: "hi" }] }, env);
    expect(result.decision).toBe("allow");
    expect(result.classifier_error_reason).toBe(null);
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("transient blip then a CSAM verdict on retry → BLOCK (verdict survives retry)", async () => {
    let n = 0;
    const run = vi.fn(async () => {
      n += 1;
      if (n === 1) throw new Error("transient blip");
      return { response: "unsafe\nS4" };
    });
    const env = makeEnv(run);
    const result = await classify({ messages: [{ role: "user", content: "x" }] }, env);
    expect(result.decision).toBe("block");
    expect(result.category).toBe("csam");
    expect(result.classifier_error_reason).toBe(null);
  });

  it("config error: missing env.AI → UNAVAILABLE with NO retry (persistent)", async () => {
    const env = { AI: undefined, MOCK_AI: undefined } as unknown as Env;
    const result = await classify({ messages: [{ role: "user", content: "hi" }] }, env);
    expect(result.decision).toBe("unavailable");
    expect(result.classifier_error_reason).toBe("ai_binding_error");
  });
});

describe("resolveModel()", () => {
  it("default when CLASSIFIER_MODEL unset", () => {
    const env = makeEnv(async () => ({ response: "safe" }));
    expect(resolveModel(env)).toBe("@cf/meta/llama-guard-3-8b");
  });

  it("returns env value when CLASSIFIER_MODEL is on the vetted list", () => {
    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_MODEL: "@cf/meta/llama-guard-3-8b",
    });
    expect(resolveModel(env)).toBe("@cf/meta/llama-guard-3-8b");
  });

  it("returns null when CLASSIFIER_MODEL is not on the vetted list", () => {
    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_MODEL: "@cf/unknown/model-1b",
    });
    expect(resolveModel(env)).toBeNull();
  });

  it("classify() returns fail-closed UNAVAILABLE (no retry) when resolveModel returns null", async () => {
    const run = vi.fn(async () => ({ response: "safe" }));
    const env = makeEnv(run, { CLASSIFIER_MODEL: "@cf/unknown/model-1b" });
    const result = await classify({ messages: [{ role: "user", content: "hi" }] }, env);
    // Unvetted model is a CONFIG error (persistent) → unavailable, never block,
    // and the AI binding is never even invoked (no retry on a config error).
    expect(result.decision).toBe("unavailable");
    expect(result.classifier_error_reason).toBe("ai_binding_error");
    expect(run).not.toHaveBeenCalled();
  });

  it("VETTED_CLASSIFIER_MODELS contains the default model", () => {
    expect(VETTED_CLASSIFIER_MODELS.has("@cf/meta/llama-guard-3-8b")).toBe(true);
  });
});

describe("classifyViaUrl()", () => {
  it("routes through CLASSIFIER_URL and returns allow on safe response", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      json: async () => ({ response: "safe" }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const env = makeEnv(async () => ({ response: "block" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classifyViaUrl(
      [{ role: "user", content: "hello" }],
      env,
    );
    expect(result.decision).toBe("allow");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:9999/classify",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("timeout on BOTH attempts: self-host fetch exceeds 2000ms → UNAVAILABLE, retried", async () => {
    const mockFetch = vi.fn().mockImplementation(
      () => new Promise((r) => setTimeout(r, 3000)),
    );
    vi.stubGlobal("fetch", mockFetch);

    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classifyViaUrl([], env);
    expect(result.decision).toBe("unavailable");
    expect(result.classifier_error_reason).toBe("timeout");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  }, 12000);

  it("fetch error on BOTH attempts: network failure → UNAVAILABLE, retried", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("network_error"));
    vi.stubGlobal("fetch", mockFetch);

    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classifyViaUrl([], env);
    expect(result.decision).toBe("unavailable");
    expect(result.classifier_error_reason).toBe("ai_binding_error");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("transient blip: self-host fetch fails once, retry returns 'safe' → ALLOW", async () => {
    let n = 0;
    const mockFetch = vi.fn().mockImplementation(() => {
      n += 1;
      if (n === 1) return Promise.reject(new Error("network_error"));
      return Promise.resolve({ json: async () => ({ response: "safe" }) });
    });
    vi.stubGlobal("fetch", mockFetch);

    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classifyViaUrl([{ role: "user", content: "hi" }], env);
    expect(result.decision).toBe("allow");
    expect(result.classifier_error_reason).toBe(null);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("classify() uses CLASSIFIER_URL path when set (CLASSIFIER_URL takes precedence)", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      json: async () => ({ response: "safe" }),
    });
    vi.stubGlobal("fetch", mockFetch);

    // AI binding would block if called
    const env = makeEnv(async () => ({ response: "unsafe\nS4" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classify({ messages: [{ role: "user", content: "hi" }] }, env);
    expect(result.decision).toBe("allow");
    expect(mockFetch).toHaveBeenCalled();
  });
});

describe("allow-path audit event shape", () => {
  it("allow-path event passes isProxyLogEvent", () => {
    const event = {
      event_type: "classification" as const,
      timestamp: new Date().toISOString(),
      request_id: "req-test-123",
      token_id: "tok-abc",
      ip: "1.2.3.0",
      request_size_bytes: 42,
      response_status: 0,
      response_size_bytes: 0,
      token_count_in: null,
      token_count_out: null,
      cached_tokens: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      classification_decision: "allow" as const,
      classification_category: null,
      classifier_error_reason: null,
      duration_ms: 15,
      upstream_status: null,
      cap_type_hit: null,
    };
    expect(isProxyLogEvent(event)).toBe(true);
  });

  it("unavailable-path event passes isProxyLogEvent (decision unavailable + reason + 503)", () => {
    const event = {
      event_type: "classification" as const,
      timestamp: new Date().toISOString(),
      request_id: "req-test-503",
      token_id: "tok-abc",
      ip: "1.2.3.0",
      request_size_bytes: 42,
      response_status: 503,
      response_size_bytes: 0,
      token_count_in: null,
      token_count_out: null,
      cached_tokens: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      classification_decision: "unavailable" as const,
      classification_category: null,
      classifier_error_reason: "timeout" as const,
      duration_ms: 15,
      upstream_status: null,
      cap_type_hit: null,
    };
    expect(isProxyLogEvent(event)).toBe(true);
  });
});

describe("classificationGate() — the shared decision→Response mapping (W38-S949)", () => {
  // Capture the classification audit event the gate emits via logEvent → console.log.
  function gateWith(cls: ClassifierResult): { resp: Response | null; audit: Record<string, unknown> | null } {
    let audit: Record<string, unknown> | null = null;
    const spy = vi.spyOn(console, "log").mockImplementation((line: string) => {
      try { audit = JSON.parse(line); } catch { /* ignore non-JSON */ }
    });
    const resp = classificationGate(cls, "req-1", "tok-1", "1.2.3.0", 10, Date.now());
    spy.mockRestore();
    return { resp, audit };
  }

  it("allow → null (proceed), allow audit at status 0", () => {
    const { resp, audit } = gateWith({ decision: "allow", category: null, classifier_error_reason: null });
    expect(resp).toBeNull();
    expect(audit?.classification_decision).toBe("allow");
    expect(audit?.response_status).toBe(0);
  });

  it("block (CSAM verdict) → 451 content_policy_violation (UNCHANGED), block audit at 451", async () => {
    const { resp, audit } = gateWith({ decision: "block", category: "csam", classifier_error_reason: null });
    expect(resp).not.toBeNull();
    expect(resp!.status).toBe(451);
    const body = await resp!.json() as { error: { type: string } };
    expect(body.error.type).toBe("content_policy_violation");
    expect(audit?.classification_decision).toBe("block");
    expect(audit?.response_status).toBe(451);
    expect(audit?.classifier_error_reason).toBe(null);
  });

  it("unavailable (classifier ERROR) → retryable 503 classifier_unavailable, NOT 451", async () => {
    const { resp, audit } = gateWith({ decision: "unavailable", category: null, classifier_error_reason: "timeout" });
    expect(resp).not.toBeNull();
    expect(resp!.status).toBe(503);
    const body = await resp!.json() as { error: { type: string } };
    expect(body.error.type).toBe("classifier_unavailable");
    expect(body.error.type).not.toBe("content_policy_violation");
    // Audit distinguishes an availability ERROR from a content-policy VERDICT.
    expect(audit?.classification_decision).toBe("unavailable");
    expect(audit?.response_status).toBe(503);
    expect(audit?.classifier_error_reason).toBe("timeout");
  });
});

describe("every classify() route is wired through classificationGate (anti-N-route-skip)", () => {
  // The recurring failure mode is a structurally-different route that keeps the
  // old hand-rolled `if (cls.decision === "block") { … 451 … }` on the error path.
  // Enumerate EVERY route that calls classify() and assert it (a) routes through
  // the shared gate and (b) carries NO hand-rolled content-policy 451 block.
  const ROUTES = [
    "vertex", "azure", "chat-completions", "bedrock", "gemini",
    "oauth", "grok", "byok", "qwen", "messages",
  ];

  for (const name of ROUTES) {
    it(`${name}.ts: calls classify() and is wired through classificationGate (no hand-rolled 451)`, () => {
      const src = readFileSync(join(__dirname, "..", "src", "routes", `${name}.ts`), "utf8");
      expect(src.includes("await classify(")).toBe(true);
      expect(src.includes("classificationGate(")).toBe(true);
      // No route may still emit a content_policy_violation by hand — that path
      // now lives ONLY in classificationGate (defined in messages.ts).
      if (name !== "messages") {
        expect(src.includes("content_policy_violation")).toBe(false);
      }
      // And no route may branch on the old error-as-block shape.
      expect(src.includes('cls.decision === "block"')).toBe(false);
    });
  }

  it("the 451 content_policy_violation path lives ONLY in classificationGate", () => {
    const src = readFileSync(join(__dirname, "..", "src", "routes", "messages.ts"), "utf8");
    // Exactly one emission of the content-policy 451 response body (inside the gate).
    const occurrences = src.split('type: "content_policy_violation"').length - 1;
    expect(occurrences).toBe(1);
  });
});
