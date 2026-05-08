/**
 * Llama Guard 3 8B content classifier.
 *
 * NAMED EXCEPTION: this module reads `body.messages` to pass to the AI model.
 * This is the sole permitted inspection of message content in the proxy.
 * The no-prompt-content-in-logs claim made in the README permits this because classification results
 * are stored as enumerated categories only — prompt text is never logged.
 * All other code in this codebase must not read message content.
 *
 * MOCK_AI substrate flag: when `env.MOCK_AI === "1"`, the real AI binding
 * is bypassed and the mock path returns "allow". This flag is never set in
 * production. Disclosed on three surfaces:
 *   1. This comment block (src/lib/classifier.ts).
 *   2. tests/README.md
 *   3. docs/dev/bishop-proxy-testing.md
 */

import type { Env } from "../index";
import type { ProxyLogEvent } from "./log";

export interface ClassifierResult {
  decision: NonNullable<ProxyLogEvent["classification_decision"]>;
  category: ProxyLogEvent["classification_category"];
  classifier_error_reason: ProxyLogEvent["classifier_error_reason"];
}

interface LlamaGuardResponse {
  response: string;
}

// S-code → category mapping for P1. P3 will refine the taxonomy.
function mapCategory(code: string): ProxyLogEvent["classification_category"] {
  switch (code) {
    case "S4": return "csam";       // Child Sexual Exploitation
    case "S9": return "weapons";    // Indiscriminate Weapons
    case "S11": return "self_harm"; // Self-Harm
    case "S7": return "pii";        // Privacy
    default:   return "other";
  }
}

function parseLlamaGuardResponse(response: string): Pick<ClassifierResult, "decision" | "category"> {
  const trimmed = response.trim();
  if (trimmed.startsWith("safe")) {
    return { decision: "allow", category: null };
  }
  // "unsafe\nS1,S4,..." — extract the first category code.
  const lines = trimmed.split("\n");
  const codes = (lines[1] ?? "").split(",");
  const firstCode = codes[0]?.trim() ?? "";
  return { decision: "block", category: mapCategory(firstCode) };
}

function mockClassify(): ClassifierResult {
  return { decision: "allow", category: null, classifier_error_reason: null };
}

const CLASSIFY_TIMEOUT_MS = 2000;

// Ai binding uses branded model overloads; cast the binding object to access run() with a plain signature.
type AiRunFn = (model: string, input: { messages: { role: string; content: string }[] }) => Promise<LlamaGuardResponse>;

export async function classify(
  body: Record<string, unknown>,
  env: Env,
): Promise<ClassifierResult> {
  if (env.MOCK_AI === "1") {
    return mockClassify();
  }

  // Fail-closed if AI binding is missing or misconfigured.
  if (!env.AI) {
    return { decision: "block", category: null, classifier_error_reason: "ai_binding_error" };
  }

  const messages = Array.isArray(body.messages)
    ? (body.messages as Array<{ role: string; content: unknown }>)
        .filter((m) => m.role === "user" || m.role === "assistant")
        .map((m) => ({
          role: m.role as "user" | "assistant",
          content: typeof m.content === "string" ? m.content : JSON.stringify(m.content),
        }))
    : [];

  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error("classifier_timeout")), CLASSIFY_TIMEOUT_MS),
  );

  try {
    const result = await Promise.race([
      (env.AI as unknown as { run: AiRunFn }).run(
        "@cf/meta/llama-guard-3-8b",
        { messages },
      ),
      timeoutPromise,
    ]);
    return { ...parseLlamaGuardResponse(result.response), classifier_error_reason: null };
  } catch (err: unknown) {
    const isTimeout = err instanceof Error && err.message === "classifier_timeout";
    return {
      decision: "block",
      category: null,
      classifier_error_reason: isTimeout ? "timeout" : "ai_binding_error",
    };
  }
}
