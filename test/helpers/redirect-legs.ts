/**
 * W38-S1047 — the three redirect legs every credential-carrying route must pass.
 *
 * Each leg stubs the global fetch, drives the route's real handler once, and reads what the
 * handler sent upstream:
 *   1. a redirect to ANOTHER host is refused by name, and that host is never contacted;
 *   2. a redirect on the SAME host is followed, carrying the same credential to the same host;
 *   3. a redirect with NO Location is refused by name.
 * The rule itself is pinned in test/redirect-policy.test.ts; these legs prove each route reaches it.
 */
import { it, expect, vi } from "vitest";
import { REDIRECT_REFUSED } from "../../src/lib/redirect-policy";

export interface RouteUnderTest {
  /** The host the route sends its upstream call to. */
  host: string;
  /** Drive the route's handler once with a request it accepts. */
  invoke: () => Promise<Response>;
  /** A success response the route accepts from its upstream. */
  ok: () => Response;
  /** The status that moves the request on the same host (307 by default; 302 for a streamed body). */
  sameHostStatus?: number;
  /** Where the route's secret travels: a header (default), or the body (a token exchange). */
  credentialIn?: "headers" | "body";
}

type Call = { url: string; headers: Headers; body: string | null };

/** Headers that carry a credential to an upstream; compared between the two same-host hops. */
const CREDENTIAL_HEADERS = ["authorization", "x-api-key", "api-key", "x-goog-api-key", "cf-aig-authorization"];

function stubUpstream(first: () => Response, then: () => Response): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    const headers = input instanceof Request ? input.headers : new Headers(init?.headers);
    const raw = init?.body;
    calls.push({ url, headers, body: typeof raw === "string" ? raw : null });
    return calls.length === 1 ? first() : then();
  }));
  return calls;
}

async function expectNamedRefusal(resp: Response): Promise<void> {
  expect(resp.status).toBe(502);
  expect(await resp.text()).toContain(REDIRECT_REFUSED);
}

export function redirectLegs(label: string, route: () => RouteUnderTest): void {
  it(`${label}: a redirect to another host is refused by name and never contacted`, async () => {
    const r = route();
    const calls = stubUpstream(
      () => new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } }),
      () => new Response("must not be reached", { status: 200 }),
    );
    await expectNamedRefusal(await r.invoke());
    expect(calls.map((c) => new URL(c.url).hostname)).toEqual([r.host]);
  });

  it(`${label}: a redirect on the same host is followed with the same credential`, async () => {
    const r = route();
    const status = r.sameHostStatus ?? 307;
    const calls = stubUpstream(
      () => new Response(null, { status, headers: { location: `https://${r.host}/moved` } }),
      r.ok,
    );
    const resp = await r.invoke();
    expect(resp.status).toBe(200);
    expect(calls.map((c) => new URL(c.url).hostname)).toEqual([r.host, r.host]);
    if ((r.credentialIn ?? "headers") === "body") {
      // A token exchange: the secret is the body, which a same-host 307 re-sends unchanged.
      expect(calls[0].body).toBeTruthy();
      expect(calls[1].body).toBe(calls[0].body);
    } else {
      for (const h of CREDENTIAL_HEADERS) {
        expect(calls[1].headers.get(h)).toBe(calls[0].headers.get(h));
      }
      expect(CREDENTIAL_HEADERS.some((h) => calls[0].headers.get(h))).toBe(true);
    }
  });

  it(`${label}: a redirect with no Location is refused by name`, async () => {
    const r = route();
    const calls = stubUpstream(
      () => new Response(null, { status: 302 }),
      () => new Response("must not be reached", { status: 200 }),
    );
    await expectNamedRefusal(await r.invoke());
    expect(calls).toHaveLength(1);
  });
}
