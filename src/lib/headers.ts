/**
 * Request header rebuild for upstream Anthropic call.
 *
 * The brief's privacy posture: we MUST NOT forward client identifiers (Bearer
 * Bishop tokens, cookies, user-agent, X-Forwarded-For) to Anthropic. The proxy
 * substitutes the operator's own Anthropic API key so all upstream calls
 * appear to originate from one account, breaking client-IP linkage.
 *
 * Allowed forward headers: content-type and anthropic-version (request body
 * format markers). Everything else is dropped or replaced.
 */

const FORWARD_ALLOWLIST = new Set<string>([
  "content-type",
  "anthropic-version",
  "anthropic-beta",
]);

export function resolveUpstreamKey(
  accountMode: "managed" | "byok",
  incoming: Headers,
  operatorKey: string | null,
): { ok: true; key: string } | { ok: false; reason: "byok_key_missing" | "managed_key_unavailable" } {
  if (accountMode === "managed") {
    // Managed mode never reads the inbound upstream-key header. If no operator
    // key is bound for this provider, the route is structurally BYOK-only and
    // fails closed — it does NOT fall back to the inbound header.
    const op = (operatorKey ?? "").trim();
    if (!op) {
      return { ok: false, reason: "managed_key_unavailable" };
    }
    return { ok: true, key: op };
  }
  const inbound = (incoming.get("x-bishop-upstream-key") ?? "").trim();
  if (!inbound) {
    return { ok: false, reason: "byok_key_missing" };
  }
  return { ok: true, key: inbound };
}

export function rebuildHeaders(incoming: Headers, anthropicKey: string): Headers {
  const out = new Headers();
  for (const [key, value] of incoming.entries()) {
    if (FORWARD_ALLOWLIST.has(key.toLowerCase())) {
      out.set(key, value);
    }
  }
  // Operator credentials substitute for the client's Bearer.
  out.set("x-api-key", anthropicKey);
  // Default version if client didn't send one.
  if (!out.has("anthropic-version")) {
    out.set("anthropic-version", "2023-06-01");
  }
  if (!out.has("content-type")) {
    out.set("content-type", "application/json");
  }
  out.set("x-bishop-zdr", "1");
  return out;
}

/**
 * Request header rebuild for upstream OpenAI call.
 *
 * OpenAI authenticates with a Bearer token (not anthropic's x-api-key), and has
 * no per-request ZDR or anthropic-version markers. We forward ONLY content-type
 * and inject the resolved OpenAI key as Bearer. All client identifiers
 * (inbound authorization, cookie, x-bishop-upstream-key, user-agent,
 * x-forwarded-for) are dropped — Pillar 1 identifier-strip.
 */
const OPENAI_FORWARD_ALLOWLIST = new Set<string>(["content-type"]);

export function rebuildOpenAIHeaders(incoming: Headers, openaiKey: string): Headers {
  const out = new Headers();
  for (const [key, value] of incoming.entries()) {
    if (OPENAI_FORWARD_ALLOWLIST.has(key.toLowerCase())) out.set(key, value);
  }
  out.set("authorization", `Bearer ${openaiKey}`);
  if (!out.has("content-type")) out.set("content-type", "application/json");
  return out;
}

/**
 * Request header rebuild for /byok/ upstream calls.
 *
 * Strip-all like rebuildOpenAIHeaders: only content-type is forwarded from the
 * inbound request. All 14 BYOK legs use Bearer auth.
 *
 * All client identifiers (inbound authorization, x-bishop-upstream-key,
 * user-agent, x-forwarded-for) are dropped — Pillar 1 identifier-strip.
 */
export function rebuildByokHeaders(incoming: Headers, key: string): Headers {
  const out = new Headers();
  for (const [k, v] of incoming.entries()) {
    if (k.toLowerCase() === "content-type") out.set(k, v);
  }
  out.set("authorization", `Bearer ${key}`);
  if (!out.has("content-type")) out.set("content-type", "application/json");
  return out;
}

/**
 * Request header rebuild for the NATIVE Google Gemini upstream call
 * (`…/v1beta/models/{model}:generateContent`).
 *
 * Unlike the OpenAI-compatible Gemini leg (Bearer via rebuildOpenAIHeaders), the
 * native generateContent endpoint authenticates with the `x-goog-api-key` header.
 * Only content-type is forwarded from the inbound request; every client
 * identifier (inbound authorization, x-bishop-upstream-key, user-agent,
 * x-forwarded-for, cookie) is dropped — Pillar 1 identifier-strip.
 */
export function rebuildGeminiNativeHeaders(incoming: Headers, key: string): Headers {
  const out = new Headers();
  for (const [k, v] of incoming.entries()) {
    if (k.toLowerCase() === "content-type") out.set(k, v);
  }
  out.set("x-goog-api-key", key);
  if (!out.has("content-type")) out.set("content-type", "application/json");
  return out;
}
