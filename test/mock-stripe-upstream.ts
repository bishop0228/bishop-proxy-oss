/**
 * Mock Stripe API upstream for billing.test.ts and tier.test.ts (W38-S1326 (a), W38-S1335 (a)).
 *
 * Records what the proxy sends, and answers as Stripe's API does for the calls the billing routes and the webhook make.
 *
 *   POST /__reset                       — clear captured state; no subscription
 *   POST /__subscription                — body {"customer": "cus_..." | null}: what the search answers
 *   POST /__subscription_state          — body: a subscription object (its "id" required): what Stripe holds for it now
 *   POST /__subscription_read_fails     — body {"fail": true | false}: reads of a subscription answer 500 while true
 *   POST /__subscription_read_redirect  — body {"to": "<url>" | null}: reads answer 302 to that address while set
 *   GET  /__last                        — {checkout, search, portal, reads, read_auth, hits}: the last of each call, as
 *                                         received; reads lists each subscription id read, in order, read_auth the
 *                                         last read's Authorization header
 *   POST /v1/checkout/sessions          — {"id": "cs_test_mock", "url": "https://checkout.stripe.com/c/pay/cs_test_mock"}
 *   GET  /v1/subscriptions/search       — {"object": "search_result", "data": [...]}
 *   GET  /v1/subscriptions/<id>         — the object set for <id>, 404 when none was set, 500 while reads fail
 *   POST /v1/billing_portal/sessions    — {"id": "bps_test_mock", "url": "https://billing.stripe.com/p/session/test_mock"}
 */

type Seen = { auth: string | null; body: string | null; query: string | null } | null;

let checkout: Seen = null;
let search: Seen = null;
let portal: Seen = null;
let hits = 0;
let customer: string | null = null;
const subscriptions = new Map<string, unknown>();
let readFails = false;
let reads: string[] = [];
let readAuth: string | null = null;
let readRedirect: string | null = null;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/__reset") {
      checkout = search = portal = null;
      hits = 0;
      customer = null;
      subscriptions.clear();
      readFails = false;
      reads = [];
      readAuth = null;
      readRedirect = null;
      return json(200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/__subscription") {
      customer = ((await request.json()) as { customer: string | null }).customer;
      return json(200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/__subscription_state") {
      const object = (await request.json()) as { id?: unknown };
      if (typeof object.id !== "string") return json(400, { error: "no id" });
      subscriptions.set(object.id, object);
      return json(200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/__subscription_read_redirect") {
      const to = ((await request.json()) as { to?: unknown }).to;
      readRedirect = typeof to === "string" ? to : null;
      return json(200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/__subscription_read_fails") {
      readFails = Boolean(((await request.json()) as { fail?: unknown }).fail);
      return json(200, { ok: true });
    }
    if (request.method === "GET" && url.pathname === "/__last") {
      return json(200, { checkout, search, portal, reads, read_auth: readAuth, hits });
    }

    hits += 1;
    const seen = async (): Promise<Seen> => ({
      auth: request.headers.get("authorization"),
      body: request.method === "GET" ? null : await request.text(),
      query: url.searchParams.get("query"),
    });

    if (request.method === "POST" && url.pathname === "/v1/checkout/sessions") {
      checkout = await seen();
      return json(200, { id: "cs_test_mock", url: "https://checkout.stripe.com/c/pay/cs_test_mock" });
    }
    if (request.method === "GET" && url.pathname === "/v1/subscriptions/search") {
      search = await seen();
      return json(200, {
        object: "search_result",
        data: customer ? [{ id: "sub_test_mock", object: "subscription", customer }] : [],
      });
    }
    const one = url.pathname.match(/^\/v1\/subscriptions\/([^/]+)$/);
    if (request.method === "GET" && one) {
      const id = decodeURIComponent(one[1]);
      reads.push(id);
      readAuth = request.headers.get("authorization");
      if (readFails) return json(500, { error: { message: "mock: the read fails" } });
      if (readRedirect) return new Response(null, { status: 302, headers: { location: readRedirect } });
      if (request.headers.get("authorization") === null) return json(401, { error: { message: "no key" } });
      const object = subscriptions.get(id);
      if (!object) return json(404, { error: { message: `No such subscription: '${id}'` } });
      return json(200, object);
    }
    if (request.method === "POST" && url.pathname === "/v1/billing_portal/sessions") {
      portal = await seen();
      return json(200, { id: "bps_test_mock", url: "https://billing.stripe.com/p/session/test_mock" });
    }
    return json(404, { error: { message: "unknown path in the mock" } });
  },
};
