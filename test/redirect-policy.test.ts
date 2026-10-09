/**
 * W38-S1047 — a credential-carrying upstream call follows a redirect only on the same host.
 *
 * The rule (src/lib/redirect-policy.ts) and its seat in fetchWithRetry, pinned both ways: what must
 * be refused (another host, a downgrade, no Location, too many hops, a spent stream body) and what
 * must still work (the same host, an http→https upgrade, a relative Location, fetch's own method
 * rules, a 3xx that is not a redirect). Each refusal must leave the other host uncontacted.
 * The per-route legs live beside each route's own tests, through test/helpers/redirect-legs.ts.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  sameDestination,
  fetchFollowingSameHost,
  isRedirectRefusal,
  REDIRECT_REFUSED,
  MAX_SAME_HOST_HOPS,
} from "../src/lib/redirect-policy";
import { fetchWithRetry } from "../src/routes/messages";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

type Call = { url: string; init: RequestInit };

/** Stub global fetch with a scripted list of responses; record every call. */
function script(...responses: Array<() => Response>): Call[] {
  const calls: Call[] = [];
  let i = 0;
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: input instanceof Request ? input.url : String(input), init: init ?? {} });
    const make = responses[Math.min(i, responses.length - 1)];
    i++;
    return make();
  }));
  return calls;
}

const redirect = (status: number, location?: string) => () =>
  new Response(null, { status, headers: location === undefined ? {} : { location } });
const ok = (text = "ok") => () => new Response(text, { status: 200 });

const START = "https://api.example.com/v1/thing";
const AUTH = { authorization: "Bearer secret-token", "content-type": "application/json" };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sameDestination", () => {
  const u = (s: string) => new URL(s);
  it("is true for the same host and port", () => {
    expect(sameDestination(u("https://a.example/x"), u("https://a.example/y"))).toBe(true);
    expect(sameDestination(u("https://a.example/x"), u("https://A.EXAMPLE:443/y"))).toBe(true);
  });
  it("is false for another host, a subdomain, or another port", () => {
    expect(sameDestination(u("https://a.example/"), u("https://b.example/"))).toBe(false);
    expect(sameDestination(u("https://a.example/"), u("https://x.a.example/"))).toBe(false);
    expect(sameDestination(u("https://a.example/"), u("https://a.example:8443/"))).toBe(false);
  });
  it("allows an http→https upgrade on the default ports and refuses the downgrade", () => {
    expect(sameDestination(u("http://a.example/"), u("https://a.example/"))).toBe(true);
    expect(sameDestination(u("https://a.example/"), u("http://a.example/"))).toBe(false);
    expect(sameDestination(u("http://a.example:8080/"), u("https://a.example/"))).toBe(false);
  });
});

describe("fetchFollowingSameHost", () => {
  it("refuses a redirect to another host, by name, and never contacts it", async () => {
    const calls = script(redirect(302, "https://evil.example/steal"), ok());
    const resp = await fetchFollowingSameHost(START, { method: "POST", headers: AUTH, body: "{}" });
    expect(resp.status).toBe(502);
    expect(isRedirectRefusal(resp)).toBe(true);
    const body = (await resp.json()) as Record<string, string>;
    expect(body.error).toBe(REDIRECT_REFUSED);
    expect(body.reason).toBe("cross_host");
    expect(body.location_host).toBe("evil.example");
    expect(calls).toHaveLength(1);
    expect(calls.some((c) => new URL(c.url).hostname === "evil.example")).toBe(false);
  });

  it("refuses an https→http downgrade on the same host", async () => {
    const calls = script(redirect(307, "http://api.example.com/v1/thing"), ok());
    const resp = await fetchFollowingSameHost(START, { method: "POST", headers: AUTH, body: "{}" });
    expect(((await resp.json()) as Record<string, string>).reason).toBe("cross_host");
    expect(calls).toHaveLength(1);
  });

  it("refuses a redirect with no Location, and one with a malformed Location", async () => {
    let calls = script(redirect(302), ok());
    let resp = await fetchFollowingSameHost(START, { headers: AUTH });
    expect(((await resp.json()) as Record<string, string>).reason).toBe("no_location");
    expect(calls).toHaveLength(1);

    calls = script(redirect(302, "http://[::1"), ok());
    resp = await fetchFollowingSameHost(START, { headers: AUTH });
    expect(((await resp.json()) as Record<string, string>).reason).toBe("bad_location");
    expect(calls).toHaveLength(1);
  });

  it("follows a same-host 307 with the method, the body and the credential kept", async () => {
    const calls = script(redirect(307, "https://api.example.com/v2/thing"), ok("followed"));
    const resp = await fetchFollowingSameHost(START, { method: "POST", headers: AUTH, body: '{"a":1}' });
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("followed");
    expect(calls.map((c) => c.url)).toEqual([START, "https://api.example.com/v2/thing"]);
    expect(calls[1].init.method).toBe("POST");
    expect(calls[1].init.body).toBe('{"a":1}');
    expect(new Headers(calls[1].init.headers).get("authorization")).toBe("Bearer secret-token");
  });

  it("follows a relative Location against the current URL", async () => {
    const calls = script(redirect(308, "/v3/thing?x=1"), ok());
    const resp = await fetchFollowingSameHost(START, { method: "GET", headers: AUTH });
    expect(resp.status).toBe(200);
    expect(calls[1].url).toBe("https://api.example.com/v3/thing?x=1");
  });

  it("applies fetch's method rules: 302 turns a POST into a GET without the body; 303 too", async () => {
    for (const status of [301, 302, 303]) {
      const calls = script(redirect(status, "https://api.example.com/next"), ok());
      await fetchFollowingSameHost(START, { method: "POST", headers: AUTH, body: '{"a":1}' });
      expect(calls[1].init.method).toBe("GET");
      expect(calls[1].init.body).toBeNull();
      const h = new Headers(calls[1].init.headers);
      expect(h.get("content-type")).toBeNull();
      expect(h.get("authorization")).toBe("Bearer secret-token");
    }
  });

  it("refuses a 307 that would have to re-send a spent stream body", async () => {
    const calls = script(redirect(307, "https://api.example.com/upload2"), ok());
    const stream = new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1, 2, 3])); c.close(); } });
    const resp = await fetchFollowingSameHost(START, { method: "POST", headers: AUTH, body: stream });
    expect(((await resp.json()) as Record<string, string>).reason).toBe("body_not_replayable");
    expect(calls).toHaveLength(1);
  });

  it(`stops after ${MAX_SAME_HOST_HOPS} same-host hops`, async () => {
    const calls = script(redirect(302, "https://api.example.com/loop"));
    const resp = await fetchFollowingSameHost(START, { headers: AUTH });
    expect(((await resp.json()) as Record<string, string>).reason).toBe("too_many_redirects");
    expect(calls).toHaveLength(1 + MAX_SAME_HOST_HOPS);
  });

  it("returns a 3xx that is not a redirect (304) as the answer", async () => {
    const calls = script(() => new Response(null, { status: 304 }));
    const resp = await fetchFollowingSameHost(START, { headers: AUTH });
    expect(resp.status).toBe(304);
    expect(calls).toHaveLength(1);
  });

  it("asks fetch for manual redirects on every hop, so the runtime never follows one itself", async () => {
    const calls = script(redirect(307, "https://api.example.com/b"), ok());
    await fetchFollowingSameHost(START, { method: "POST", headers: AUTH, body: "{}", redirect: "follow" });
    expect(calls.every((c) => c.init.redirect === "manual")).toBe(true);
  });
});

describe("fetchWithRetry carries the policy", () => {
  it("applies it when the caller names no redirect mode, and does not retry a refusal", async () => {
    const calls = script(redirect(302, "https://evil.example/"), ok());
    const resp = await fetchWithRetry(START, { method: "POST", headers: AUTH, body: "{}" });
    expect(resp.status).toBe(502);
    expect(isRedirectRefusal(resp)).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("leaves a caller that passes its own redirect mode alone (the model routes' allowlisted hops)", async () => {
    const calls = script(redirect(302, "https://cdn.example/blob"));
    const resp = await fetchWithRetry(START, { method: "GET", redirect: "manual" });
    expect(resp.status).toBe(302);
    expect(resp.headers.get("location")).toBe("https://cdn.example/blob");
    expect(calls).toHaveLength(1);
  });

  it("still retries an ordinary 5xx", async () => {
    vi.useFakeTimers();
    try {
      const calls = script(() => new Response("down", { status: 503 }), ok("up"));
      const p = fetchWithRetry(START, { method: "GET", headers: AUTH });
      await vi.runAllTimersAsync();
      const resp = await p;
      expect(resp.status).toBe(200);
      expect(calls).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("no route opts out of the policy", () => {
  // Read with comments stripped: a rule about code must not be satisfied (or tripped) by prose.
  const strip = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const routesDir = resolve(dirname(fileURLToPath((import.meta as any).url)), "..", "src", "routes");
  const read = (f: string) => strip(readFileSync(resolve(routesDir, f), "utf8"));
  const files = readdirSync(routesDir).filter((f) => f.endsWith(".ts"));
  /** The anonymous model routes run their own allowlisted manual-redirect loop; nothing else may. */
  const OWN_REDIRECT_LOOP = new Set(["model-registry.ts", "model-hf.ts", "model-list.ts"]);

  it("only the three anonymous model routes set a redirect mode", () => {
    const offenders = files.filter((f) => !OWN_REDIRECT_LOOP.has(f) && /\bredirect\s*:/.test(read(f)));
    expect(offenders).toEqual([]);
  });

  it("no route calls the global fetch directly: upstream calls go through fetchWithRetry", () => {
    // messages.ts defines fetchWithRetry; browser-egress uses the sanctioned raw seam, which sends no credential.
    const offenders = files.filter((f) =>
      f !== "messages.ts" && f !== "browser-egress.ts" && /(^|[^.\w])fetch\s*\(/m.test(read(f)));
    expect(offenders).toEqual([]);
  });
});
