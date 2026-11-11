/**
 * POST /v1/billing/checkout and POST /v1/billing/portal (W38-S1326 (a), the founder's decisions of 2026-11-10).
 *
 * The proxy starts a Solo purchase, and opens the subscription's management page, for the device its bearer token
 * authenticates. Stripe is called here with a RESTRICTED key held as a Worker secret (STRIPE_RESTRICTED_KEY:
 * Checkout Sessions write, Customer Portal write, Subscriptions read), never from the daemon, so Bishop's Stripe key
 * is on no user's machine.
 *
 * Binding sub-decision (a): the purchase carries an id the proxy derives from the caller's own token,
 * billing id = HMAC-SHA256(USER_INDEX_HMAC_KEY, "billing:" + token_id), never an id the caller sends. The checkout
 * binds it to the token in AuthStoreDO (/bind-user), so the Stripe webhook maps a subscription's billing id to its
 * token; the portal finds the caller's Stripe customer by it. A caller can only buy, and manage, for itself, and the
 * user id never leaves the device: Stripe receives the billing id alone.
 *
 * Both routes answer 503 billing_not_configured, with no call to Stripe, until the deploy sets the secret and vars
 * (wrangler.toml names them). Each call carries the restricted key, so it follows a redirect only on the same host
 * (W38-S1047, fetchFollowingSameHost); a refused redirect is answered as the rule names it. The answer is {"url": ...} on a Stripe host the daemon accepts (checkout.stripe.com,
 * billing.stripe.com); the portal answers 404 no_subscription when the caller has no subscription.
 */

import type { Env } from "../index";
import { verifyBearer } from "../lib/auth";
import { fetchFollowingSameHost, isRedirectRefusal } from "../lib/redirect-policy";
import { computeUserHash } from "../lib/user-hash";

/** Stripe's API; the test suite points STRIPE_API_BASE_URL at a mock upstream (a test seam, never set in production). */
const STRIPE_API = "https://api.stripe.com";

/** The hosts each answer's url must be on. */
const CHECKOUT_HOST = "checkout.stripe.com";
const PORTAL_HOST = "billing.stripe.com";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** The billing id for a token: HMAC-SHA256(USER_INDEX_HMAC_KEY, "billing:" + token_id), 64 hex characters. */
export async function computeBillingId(tokenId: string, key: string): Promise<string> {
  return computeUserHash(`billing:${tokenId}`, key);
}

/** A billing id's form, as the webhook reads it from a subscription's metadata. */
export function isBillingId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function stripeBase(env: Env): string {
  return (env.STRIPE_API_BASE_URL || STRIPE_API).replace(/\/+$/, "");
}

function form(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

/** The url in a Stripe session answer, when it is https on *host*; else null. */
function sessionUrl(body: unknown, host: string): string | null {
  const url = (body as { url?: unknown } | null)?.url;
  if (typeof url !== "string") return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" && u.hostname === host ? url : null;
  } catch {
    return null;
  }
}

async function stripeJson(resp: Response): Promise<unknown> {
  try {
    return await resp.json();
  } catch {
    return null;
  }
}

/** The caller's token id and billing id, or the Response to return. */
async function caller(
  request: Request,
  env: Env,
  needs: ReadonlyArray<keyof Env>,
): Promise<{ ok: true; tokenId: string; billingId: string } | { ok: false; response: Response }> {
  const auth = await verifyBearer(request, env);
  if (!auth.ok) return auth;
  const missing = ["STRIPE_RESTRICTED_KEY", "USER_INDEX_HMAC_KEY", ...needs].filter(
    (k) => !env[k as keyof Env],
  );
  if (missing.length) {
    return { ok: false, response: json(503, { error: "billing_not_configured" }) };
  }
  const billingId = await computeBillingId(auth.record.token_id, env.USER_INDEX_HMAC_KEY);
  return { ok: true, tokenId: auth.record.token_id, billingId };
}

export async function handleBillingCheckout(request: Request, env: Env): Promise<Response> {
  const c = await caller(request, env, ["STRIPE_SOLO_PRICE_ID", "BILLING_SUCCESS_URL", "BILLING_CANCEL_URL"]);
  if (!c.ok) return c.response;

  // Bind the billing id to the caller's token before Stripe can send an event naming it. The id is derived from the
  // token, so the binding is the same each time and no other token can be bound to it.
  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const bindResp = await stub.fetch("https://internal/bind-user", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user_hash: c.billingId, token_id: c.tokenId }),
  });
  if (!bindResp.ok) return json(502, { error: "bind_failed" });

  const resp = await fetchFollowingSameHost(`${stripeBase(env)}/v1/checkout/sessions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.STRIPE_RESTRICTED_KEY}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form({
      mode: "subscription",
      "line_items[0][price]": env.STRIPE_SOLO_PRICE_ID as string,
      "line_items[0][quantity]": "1",
      client_reference_id: c.billingId,
      "subscription_data[metadata][billing_id]": c.billingId,
      success_url: env.BILLING_SUCCESS_URL as string,
      cancel_url: env.BILLING_CANCEL_URL as string,
    }),
  });
  if (isRedirectRefusal(resp)) return resp;
  if (!resp.ok) return json(502, { error: "stripe_error", status: resp.status });
  const url = sessionUrl(await stripeJson(resp), CHECKOUT_HOST);
  if (!url) return json(502, { error: "stripe_bad_response" });
  return json(200, { url });
}

export async function handleBillingPortal(request: Request, env: Env): Promise<Response> {
  const c = await caller(request, env, ["BILLING_RETURN_URL"]);
  if (!c.ok) return c.response;
  const auth = { authorization: `Bearer ${env.STRIPE_RESTRICTED_KEY}` };

  const query = `metadata['billing_id']:'${c.billingId}'`;
  const search = await fetchFollowingSameHost(
    `${stripeBase(env)}/v1/subscriptions/search?query=${encodeURIComponent(query)}`,
    { method: "GET", headers: auth },
  );
  if (isRedirectRefusal(search)) return search;
  if (!search.ok) return json(502, { error: "stripe_error", status: search.status });
  const found = (await stripeJson(search)) as { data?: Array<{ customer?: unknown }> } | null;
  const first = found?.data?.[0];
  if (!first) return json(404, { error: "no_subscription" });
  const customer =
    typeof first.customer === "string"
      ? first.customer
      : (first.customer as { id?: unknown } | null)?.id;
  if (typeof customer !== "string" || !customer) return json(502, { error: "stripe_bad_response" });

  const resp = await fetchFollowingSameHost(`${stripeBase(env)}/v1/billing_portal/sessions`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/x-www-form-urlencoded" },
    body: form({ customer, return_url: env.BILLING_RETURN_URL as string }),
  });
  if (isRedirectRefusal(resp)) return resp;
  if (!resp.ok) return json(502, { error: "stripe_error", status: resp.status });
  const url = sessionUrl(await stripeJson(resp), PORTAL_HOST);
  if (!url) return json(502, { error: "stripe_bad_response" });
  return json(200, { url });
}
