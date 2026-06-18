/**
 * Classifier unit tests.
 *
 * Branch coverage: allow / block / timeout / ai-error /
 *   resolveModel / classifyViaUrl / allow-path audit event shape.
 * MOCK_AI is NOT used here — these tests exercise the real classifier logic
 * with stubbed env.AI implementations.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { classify, resolveModel, classifyViaUrl, VETTED_CLASSIFIER_MODELS } from "../src/lib/classifier";
import { isProxyLogEvent } from "../src/lib/log";
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

  it("timeout: AI run exceeds 2000ms → fail-closed block", async () => {
    const env = makeEnv(async () => {
      await new Promise((r) => setTimeout(r, 3000));
      return { response: "safe" };
    });
    const result = await classify({ messages: [] }, env);
    expect(result.decision).toBe("block");
    expect(result.classifier_error_reason).toBe("timeout");
  }, 6000);

  it("ai-error: AI binding throws → fail-closed block", async () => {
    const env = makeEnv(async () => {
      throw new Error("AI binding unavailable");
    });
    const result = await classify({ messages: [] }, env);
    expect(result.decision).toBe("block");
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

  it("classify() returns fail-closed block when resolveModel returns null", async () => {
    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_MODEL: "@cf/unknown/model-1b",
    });
    const result = await classify({ messages: [{ role: "user", content: "hi" }] }, env);
    expect(result.decision).toBe("block");
    expect(result.classifier_error_reason).toBe("ai_binding_error");
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

  it("timeout: self-host fetch exceeds 2000ms → fail-closed block", async () => {
    const mockFetch = vi.fn().mockImplementation(
      () => new Promise((r) => setTimeout(r, 3000)),
    );
    vi.stubGlobal("fetch", mockFetch);

    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classifyViaUrl([], env);
    expect(result.decision).toBe("block");
    expect(result.classifier_error_reason).toBe("timeout");
  }, 6000);

  it("fetch error: network failure → fail-closed block", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("network_error"));
    vi.stubGlobal("fetch", mockFetch);

    const env = makeEnv(async () => ({ response: "safe" }), {
      CLASSIFIER_URL: "http://localhost:9999/classify",
    });
    const result = await classifyViaUrl([], env);
    expect(result.decision).toBe("block");
    expect(result.classifier_error_reason).toBe("ai_binding_error");
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
});
