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
  const category = mapCategory(firstCode);
  // Operator-conduit floor: the proxy is a transit operator for the BYOK path,
  // so it BLOCKS only CSAM-class transit (Llama Guard S4 → "csam"). Every other
  // "unsafe" category is ALLOWED to proceed — the upstream provider's own safety
  // is the backstop — but is still classified and logged for transparency.
  return { decision: category === "csam" ? "block" : "allow", category };
}

function mockClassify(): ClassifierResult {
  return { decision: "allow", category: null, classifier_error_reason: null };
}

// Per-attempt timeout. Kept at the prior single-attempt ceiling: the bounded
// retry (below) fires ONLY on a transient error, so the happy path is unchanged
// and the worst case is two attempts + one short backoff (~4.25s wall) — well
// within the Workers wall-clock budget (the AI/fetch await is I/O, not CPU).
const CLASSIFY_TIMEOUT_MS = 2000;

// Backoff between the two attempts when the first fails transiently.
const CLASSIFY_RETRY_BACKOFF_MS = 250;

// One classify attempt. Distinguishes a clean verdict (ok) from a TRANSIENT
// error (timeout / ai_binding_error) so the retry wrapper can decide whether to
// re-try. Note: this is an ERROR vs VERDICT split — a parsed "block"/"allow" is
// a verdict (ok:true), never a transient error.
type AttemptOutcome =
  | { ok: true; result: Pick<ClassifierResult, "decision" | "category"> }
  | { ok: false; reason: NonNullable<ClassifierResult["classifier_error_reason"]> };

// Runs a single attempt, then — on a transient error only — retries once after a
// short backoff. A persistent verdict short-circuits (no retry). If both
// attempts error transiently, returns the fail-closed "unavailable" envelope
// (the request is NOT forwarded — §3.6 fail-closed is preserved). This is the
// W38-S949 split: an availability failure is "unavailable" (→ retryable 503),
// NOT "block" (→ 451 content-policy verdict).
async function classifyWithRetry(attempt: () => Promise<AttemptOutcome>): Promise<ClassifierResult> {
  let outcome = await attempt();
  if (!outcome.ok) {
    await new Promise((r) => setTimeout(r, CLASSIFY_RETRY_BACKOFF_MS));
    outcome = await attempt();
  }
  if (outcome.ok) {
    return { ...outcome.result, classifier_error_reason: null };
  }
  return { decision: "unavailable", category: null, classifier_error_reason: outcome.reason };
}

export const VETTED_CLASSIFIER_MODELS = new Set(["@cf/meta/llama-guard-3-8b"]);
const DEFAULT_CLASSIFIER_MODEL = "@cf/meta/llama-guard-3-8b";

// Returns the model string to use, or null when the caller-supplied model is not on the vetted list.
// null → classify() returns a fail-closed block envelope (unknown model is a safety risk).
export function resolveModel(env: Env): string | null {
  if (!env.CLASSIFIER_MODEL) return DEFAULT_CLASSIFIER_MODEL;
  return VETTED_CLASSIFIER_MODELS.has(env.CLASSIFIER_MODEL) ? env.CLASSIFIER_MODEL : null;
}

// Ai binding uses branded model overloads; cast the binding object to access run() with a plain signature.
type AiRunFn = (model: string, input: { messages: { role: string; content: string }[] }) => Promise<LlamaGuardResponse>;

// Extract the user/assistant turns the classifier must inspect, from EITHER request
// shape the proxy forwards: OpenAI chat-completions (`body.messages`) OR the OpenAI
// Responses API (`body.input` item list — what the ChatGPT/Codex subscription backend
// speaks; each item carries `content` parts like {type:"input_text", text}). Without
// the `input` branch a Responses request yields an EMPTY conversation → Llama Guard
// errors on empty input → fail-closed block (the live-observed Codex 451) AND the
// request's real content goes UN-classified. Reading both shapes closes that gap.
// The empty-result case is unchanged (still fail-closed downstream).
export function classifierMessagesFromBody(
  body: Record<string, unknown>,
): Array<{ role: "user" | "assistant"; content: string }> {
  if (Array.isArray(body.messages)) {
    return (body.messages as Array<{ role: string; content: unknown }>)
      .filter((m) => m.role === "user" || m.role === "assistant")
      .map((m) => ({
        role: m.role as "user" | "assistant",
        content: typeof m.content === "string" ? m.content : JSON.stringify(m.content),
      }));
  }
  if (Array.isArray(body.input)) {
    return (body.input as Array<Record<string, unknown>>)
      .filter((it) => it && typeof it === "object" && (it.role === "user" || it.role === "assistant"))
      .map((it) => {
        const c = it.content;
        let content: string;
        if (typeof c === "string") {
          content = c;
        } else if (Array.isArray(c)) {
          // Responses content parts: prefer the `text` field (input_text/output_text),
          // else stringify the part so nothing classifiable is silently dropped.
          content = c
            .map((p) =>
              p && typeof p === "object" && typeof (p as { text?: unknown }).text === "string"
                ? ((p as { text: string }).text)
                : JSON.stringify(p),
            )
            .join("\n");
        } else {
          content = JSON.stringify(c);
        }
        return { role: it.role as "user" | "assistant", content };
      });
  }
  return [];
}

// Routes the classify request through a self-hosted classifier endpoint (CLASSIFIER_URL).
// Mirrors the Cloudflare AI binding path: same per-attempt timeout, same bounded
// retry, same fail-closed "unavailable" envelope on persistent transient error.
export async function classifyViaUrl(
  messages: Array<{ role: string; content: string }>,
  env: Env,
): Promise<ClassifierResult> {
  const url = env.CLASSIFIER_URL!;
  const attempt = async (): Promise<AttemptOutcome> => {
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("classifier_timeout")), CLASSIFY_TIMEOUT_MS),
    );
    try {
      const fetchPromise = fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ messages }),
      }).then(async (res) => {
        const json = (await res.json()) as LlamaGuardResponse;
        return json;
      });
      const result = await Promise.race([fetchPromise, timeoutPromise]);
      return { ok: true, result: parseLlamaGuardResponse(result.response) };
    } catch (err: unknown) {
      const isTimeout = err instanceof Error && err.message === "classifier_timeout";
      return { ok: false, reason: isTimeout ? "timeout" : "ai_binding_error" };
    }
  };
  return classifyWithRetry(attempt);
}

export async function classify(
  body: Record<string, unknown>,
  env: Env,
): Promise<ClassifierResult> {
  if (env.MOCK_AI === "1") {
    return mockClassify();
  }

  const model = resolveModel(env);
  if (model === null) {
    // Unvetted CLASSIFIER_MODEL — a CONFIG error (persistent), not a transient
    // blip → fail-closed "unavailable" (503) with NO retry.
    return { decision: "unavailable", category: null, classifier_error_reason: "ai_binding_error" };
  }

  const messages = classifierMessagesFromBody(body);

  // CLASSIFIER_URL takes precedence over the Cloudflare AI binding (self-host path).
  if (env.CLASSIFIER_URL) {
    return classifyViaUrl(messages, env);
  }

  // Missing AI binding — a CONFIG error (persistent) → fail-closed "unavailable"
  // (503) with NO retry (a missing binding never recovers on a re-try).
  if (!env.AI) {
    return { decision: "unavailable", category: null, classifier_error_reason: "ai_binding_error" };
  }

  // Transient errors (timeout / ai_binding_error from .run()) get one bounded retry.
  const attempt = async (): Promise<AttemptOutcome> => {
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("classifier_timeout")), CLASSIFY_TIMEOUT_MS),
    );
    try {
      const result = await Promise.race([
        (env.AI as unknown as { run: AiRunFn }).run(
          model,
          { messages },
        ),
        timeoutPromise,
      ]);
      return { ok: true, result: parseLlamaGuardResponse(result.response) };
    } catch (err: unknown) {
      const isTimeout = err instanceof Error && err.message === "classifier_timeout";
      return { ok: false, reason: isTimeout ? "timeout" : "ai_binding_error" };
    }
  };
  return classifyWithRetry(attempt);
}
