/**
 * Mock Stripe API upstream for billing.test.ts (W38-S1326 (a)).
 *
 * Records what the proxy sends, and answers as Stripe's API does for the three calls the billing routes make.
 *
 *   POST /__reset                       — clear captured state; no subscription
 *   POST /__subscription                — body {"customer": "cus_..." | null}: what the search answers
 *   GET  /__last                        — {checkout, search, portal, hits}: the last of each call, as received
 *   POST /v1/checkout/sessions          — {"id": "cs_test_mock", "url": "https://checkout.stripe.com/c/pay/cs_test_mock"}
 *   GET  /v1/subscriptions/search       — {"object": "search_result", "data": [...]}
 *   POST /v1/billing_portal/sessions    — {"id": "bps_test_mock", "url": "https://billing.stripe.com/p/session/test_mock"}
 */

type Seen = { auth: string | null; body: string | null; query: string | null } | null;

let checkout: Seen = null;
let search: Seen = null;
let portal: Seen = null;
let hits = 0;
let customer: string | null = null;

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
      return json(200, { ok: true });
    }
    if (request.method === "POST" && url.pathname === "/__subscription") {
      customer = ((await request.json()) as { customer: string | null }).customer;
      return json(200, { ok: true });
    }
    if (request.method === "GET" && url.pathname === "/__last") {
      return json(200, { checkout, search, portal, hits });
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
    if (request.method === "POST" && url.pathname === "/v1/billing_portal/sessions") {
      portal = await seen();
      return json(200, { id: "bps_test_mock", url: "https://billing.stripe.com/p/session/test_mock" });
    }
    return json(404, { error: { message: "unknown path in the mock" } });
  },
};
