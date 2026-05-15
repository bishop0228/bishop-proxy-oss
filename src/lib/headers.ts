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
