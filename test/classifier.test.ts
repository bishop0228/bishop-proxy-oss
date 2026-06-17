/**
 * Classifier message-extraction probes (W38-S873e).
 *
 * The integration suites set MOCK_AI:"1", which bypasses the real classifier — so the
 * Codex Responses-shape gap (classifier read body.messages, codex sends body.input →
 * empty conversation → Llama Guard AiError → fail-closed 451) was mock-masked. These
 * probes exercise the REAL classify() path with a mocked AI.run to lock the fix:
 * codex `input` content is extracted + classified (benign→allow, harmful→block), and
 * the chat-completions `messages` shape is unchanged.
 */

import { describe, it, expect } from "vitest";
import { classify, classifierMessagesFromBody } from "../src/lib/classifier";
import type { Env } from "../src/index";

type RunFn = (
  model: string,
  input: { messages: { role: string; content: string }[] },
) => Promise<{ response: string }>;

function envWithAI(run: RunFn): Env {
  return { AI: { run } } as unknown as Env;
}

describe("classifierMessagesFromBody — both request shapes", () => {
  it("chat-completions: extracts user/assistant turns, drops system", () => {
    expect(
      classifierMessagesFromBody({
        messages: [
          { role: "user", content: "hello" },
          { role: "system", content: "ignore" },
          { role: "assistant", content: "hi" },
        ],
      }),
    ).toEqual([
      { role: "user", content: "hello" },
      { role: "assistant", content: "hi" },
    ]);
  });

  it("Codex Responses: extracts text from input_text content parts", () => {
    expect(
      classifierMessagesFromBody({
        model: "gpt-5-codex",
        input: [
          { type: "message", role: "user", content: [{ type: "input_text", text: "summarize this" }] },
        ],
        stream: true,
      }),
    ).toEqual([{ role: "user", content: "summarize this" }]);
  });

  it("neither shape → [] (unchanged empty behavior)", () => {
    expect(classifierMessagesFromBody({ model: "x" })).toEqual([]);
  });
});

describe("classify() with the real path (mocked AI.run) — Codex input is inspected", () => {
  it("Codex input benign → AI sees the real content (non-empty) → allow", async () => {
    let seen: { role: string; content: string }[] | null = null;
    const env = envWithAI(async (_m, input) => {
      seen = input.messages;
      return { response: "safe" };
    });
    const res = await classify(
      {
        model: "gpt-5-codex",
        input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "hello world" }] }],
        stream: true,
      },
      env,
    );
    // The bug was an EMPTY conversation; prove the codex content is now classified.
    expect(seen).toEqual([{ role: "user", content: "hello world" }]);
    expect(res.decision).toBe("allow");
  });

  it("harmful content carried in the Codex input shape → block", async () => {
    const env = envWithAI(async () => ({ response: "unsafe\nS1" }));
    const res = await classify(
      {
        model: "gpt-5-codex",
        input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "<harmful payload>" }] }],
      },
      env,
    );
    expect(res.decision).toBe("block");
  });
});
