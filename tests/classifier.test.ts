/**
 * Classifier unit tests.
 *
 * Branch coverage: allow / block / timeout / ai-error.
 * MOCK_AI is NOT used here — these tests exercise the real classifier logic
 * with stubbed env.AI implementations.
 */

import { describe, it, expect } from "vitest";
import { classify } from "../src/lib/classifier";
import type { Env } from "../src/index";

function makeEnv(aiRun: (model: string, input: unknown) => Promise<unknown>): Env {
  return {
    AI: { run: aiRun } as unknown as Ai,
    MOCK_AI: undefined,
  } as unknown as Env;
}

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
