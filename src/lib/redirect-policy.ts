/**
 * W38-S1047 — a credential-carrying upstream call follows a redirect only on the SAME host.
 *
 * A route that sends a credential (an Authorization header, an API key, a vault-held token) or a
 * token-exchange body must not let the upstream move it somewhere else. Cloudflare's fetch, in its
 * default `redirect: "follow"` mode, forwards ALL headers to the redirect destination, "even if the
 * destination is a different hostname or domain. This includes sensitive headers like Cookie,
 * Authorization" (developers.cloudflare.com/workers/runtime-apis/request/), and the outbound
 * allowlist interceptor only ever sees the FIRST URL. So a connected service that answered with a
 * redirect to another host would receive the user's token for that service along with it.
 *
 * The rule here is the daemon's W38-S1044 rule (`url_validator._same_destination`), built on the
 * model-registry route's manual-redirect pattern:
 *   - follow a redirect only to the same host and port, or from http on its default port to https
 *     on its default port (an upgrade);
 *   - refuse anything else by name, WITHOUT contacting the other host;
 *   - refuse a redirect with no Location, a malformed Location, and a chain longer than
 *     MAX_SAME_HOST_HOPS;
 *   - on a followed hop apply fetch's own method rules: 303 (and 301/302 for a POST) become a GET
 *     without the body; 307/308 keep the method and body, and a streamed body that was already
 *     spent on the first request cannot be re-sent, so that hop is refused too.
 *
 * Every hop goes back through `globalThis.fetch`, so the allowlist interceptor now checks each hop
 * as well as the first.
 */

/** The named error a refused redirect carries back to the caller. */
export const REDIRECT_REFUSED = "upstream_redirect_refused";

/** The header that marks a refusal, so the retry loop does not retry it. */
export const REDIRECT_REFUSED_HEADER = "x-bishop-redirect-refused";

/** Same bound as the daemon's W38-S1044 rule. */
export const MAX_SAME_HOST_HOPS = 3;

/** The statuses fetch itself treats as redirects; any other 3xx (300, 304, ...) is an answer. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Headers that describe a request body, dropped when a hop turns the request into a GET. */
const BODY_HEADERS = ["content-type", "content-length", "content-encoding", "content-language", "content-location"];

function defaultPort(protocol: string): string {
  if (protocol === "https:") return "443";
  if (protocol === "http:") return "80";
  return "";
}

/**
 * True when `next` is the same destination as `current`: the same host and port, or http on its
 * default port upgraded to https on its default port. https → http is NOT the same destination
 * (the ports differ), so a downgrade is refused.
 */
export function sameDestination(current: URL, next: URL): boolean {
  if (current.hostname.toLowerCase() !== next.hostname.toLowerCase()) return false;
  const curPort = current.port || defaultPort(current.protocol);
  const nextPort = next.port || defaultPort(next.protocol);
  if (current.protocol === next.protocol) return curPort === nextPort;
  return current.protocol === "http:" && next.protocol === "https:" && curPort === "80" && nextPort === "443";
}

/** A refusal: status 502, the named error and the reason in the body, marked so it is not retried. */
export function redirectRefused(reason: string, detail: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ error: REDIRECT_REFUSED, reason, ...detail }), {
    status: 502,
    headers: { "content-type": "application/json", [REDIRECT_REFUSED_HEADER]: reason },
  });
}

/** True when a response is a refusal made by this module. */
export function isRedirectRefusal(resp: Response): boolean {
  return resp.headers.has(REDIRECT_REFUSED_HEADER);
}

/**
 * One upstream call that follows redirects only on the same host (see the module comment). The
 * caller's `redirect` mode is replaced by "manual"; a caller that wants another policy (the model
 * registry's allowlisted CDN hops) passes its own mode to `fetchWithRetry` and never reaches here.
 */
export async function fetchFollowingSameHost(url: string, init: RequestInit): Promise<Response> {
  let current = new URL(url);
  let method = (init.method ?? "GET").toUpperCase();
  let body: BodyInit | null | undefined = init.body;
  let headers = new Headers(init.headers);

  let resp = await fetch(current.toString(), { ...init, method, body, headers, redirect: "manual" });
  for (let hops = 0; REDIRECT_STATUSES.has(resp.status); hops++) {
    if (hops >= MAX_SAME_HOST_HOPS) return redirectRefused("too_many_redirects");
    const location = resp.headers.get("location");
    if (!location) return redirectRefused("no_location");
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      return redirectRefused("bad_location");
    }
    if (!sameDestination(current, next)) {
      return redirectRefused("cross_host", { location_host: next.host });
    }
    const toGet =
      (resp.status === 303 && method !== "HEAD") ||
      ((resp.status === 301 || resp.status === 302) && method === "POST");
    if (toGet) {
      method = "GET";
      body = null;
      headers = new Headers(headers);
      for (const h of BODY_HEADERS) headers.delete(h);
    } else if (body instanceof ReadableStream) {
      // 307/308 re-send the body, and a streamed body was spent on the first request.
      return redirectRefused("body_not_replayable");
    }
    current = next;
    resp = await fetch(current.toString(), { ...init, method, body, headers, redirect: "manual" });
  }
  return resp;
}
