import type { Env } from "../index";
import { computeUserHash } from "../lib/user-hash";
import { isBillingId, stripeBase } from "./billing";
import { fetchFollowingSameHost } from "../lib/redirect-policy";

interface StripeEvent {
  id: string;
  type: string;
  data: {
    object: {
      id: string;
      status?: string;
      cancel_at?: number | null;
      // Pre-2025 API versions had current_period_end on the Subscription object.
      // Newer versions (2025-09-30.clover and later, including the
      // 2026-03-25.dahlia version configured on the webhook destination)
      // moved this to Subscription Items. Kept here as fallback for older
      // events; primary read path is sub.items.data[0].current_period_end.
      current_period_end?: number;
      items?: {
        data?: Array<{
          current_period_end?: number;
        }>;
      };
      // billing_id: set by /v1/billing/checkout (W38-S1326 (a)), derived from the buyer's token. user_id: the
      // legacy key, kept for any subscription created before it.
      metadata?: { user_id?: string; billing_id?: string };
      // The subscription's customer (an id, or the object when expanded): recorded per billing id for the portal.
      customer?: string | { id?: string } | null;
      // When the subscription was created, in seconds since the epoch: orders the customer record.
      created?: number;
    };
  };
}

async function verifyStripeSignature(
  rawBody: string,
  signatureHeader: string,
  secret: string
): Promise<boolean> {
  const parts = signatureHeader.split(",").map((p) => p.split("="));
  const tEntry = parts.find((p) => p[0] === "t");
  const v1Entry = parts.find((p) => p[0] === "v1");
  if (!tEntry || !v1Entry) return false;
  const timestamp = tEntry[1];
  const expectedSig = v1Entry[1];

  const signedPayload = `${timestamp}.${rawBody}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const sigHex = Array.from(new Uint8Array(sigBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (sigHex.length !== expectedSig.length) return false;
  let mismatch = 0;
  for (let i = 0; i < sigHex.length; i++) {
    mismatch |= sigHex.charCodeAt(i) ^ expectedSig.charCodeAt(i);
  }
  return mismatch === 0;
}

export async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  const signature = request.headers.get("Stripe-Signature");
  if (!signature) {
    return new Response("missing signature", { status: 400 });
  }
  const rawBody = await request.text();
  const ok = await verifyStripeSignature(rawBody, signature, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) {
    return new Response("invalid signature", { status: 400 });
  }

  const event = JSON.parse(rawBody) as StripeEvent;

  if (
    event.type !== "customer.subscription.created" &&
    event.type !== "customer.subscription.updated" &&
    event.type !== "customer.subscription.deleted"
  ) {
    // Acknowledge but ignore other event types (including checkout.session.completed,
    // which the proxy intentionally does not act on — subscription events carry the
    // authoritative tier transition).
    // Accepted: customer.subscription.created, .updated, .deleted
    return new Response(JSON.stringify({ status: "ignored", type: event.type }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  const sub = event.data.object;
  const billingId = sub.metadata?.billing_id;
  const userId = sub.metadata?.user_id;
  if (billingId !== undefined || !userId) {
    if (billingId === undefined) {
      // Subscription with neither key — created outside Bishop's flow (or a pre-fix subscription created before
      // the metadata propagation patch landed).
      return new Response(JSON.stringify({ status: "no_user_id" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return applyByBillingId(env, event, billingId);
  }
  // (the legacy user_id path; billing ids and subscriptions with neither key returned above)

  // W38-S1335 (a): the subscription as Stripe holds it now, not the event's snapshot; a read that fails answers 500, so
  // Stripe sends the event again.
  const current = await readSubscription(env, sub.id);
  if (!current) {
    return new Response(JSON.stringify({ error: "subscription_read_failed" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }
  const applyBody = subscriptionBody(current, event.id);

  // Shard 1 (legacy/user-keyed): preserved for backward compatibility with
  // /v1/tier reads and for users who haven't yet bound a token.
  const userApplied = await applyToShard(env, userId, applyBody);
  if (userApplied === null) {
    return new Response(JSON.stringify({ error: "tier_write_failed" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }

  // Shard 2 (token-keyed). Look up token_id via AuthStoreDO
  // /lookup-user using HMAC(user_id). 404 means "user has not bound a token
  // yet" — silently skip; the user-keyed shard write above is sufficient
  // (/v1/tier/bind, which bound them, is removed: W38-S1326 (a)). The token-keyed shard is what
  // /v1/quota and /v1/messages tier reads consume.
  let tokenShardWritten = false;
  try {
    const userHash = await computeUserHash(userId, env.USER_INDEX_HMAC_KEY);
    const authStub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
    const lookupResp = await authStub.fetch(
      `https://internal/lookup-user?h=${encodeURIComponent(userHash)}`,
      { method: "GET" },
    );
    if (lookupResp.ok) {
      const { token_id: tokenId } = (await lookupResp.json()) as { token_id: string };
      tokenShardWritten = (await applyToShard(env, tokenId, applyBody)) !== null;
    }
  } catch (err) {
    // Token-keyed shard write is best-effort — failing it must not fail the
    // webhook (Stripe retries on non-2xx, which would re-apply the user-keyed
    // shard but provides no path to recover the token-keyed write).
    void err;
  }

  return new Response(
    JSON.stringify({
      status: "applied",
      tier: userApplied.tier,
      subscription_record: userApplied.outcome,
      user_id_prefix: userId.slice(0, 8),
      token_shard_written: tokenShardWritten,
    }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}

/**
 * W38-S1335 (a), the founder's decision of 2026-11-11: the subscription as Stripe holds it now. The webhook applies
 * this, never the event's snapshot: Stripe "doesn't guarantee the delivery of events in the order that they're
 * generated" and retries a failed delivery "for up to three days", and "You can also use the API to retrieve any
 * missing objects" (docs.stripe.com/webhooks, "Event ordering"). A late or repeated event then applies today's state.
 */
interface StripeSubscription {
  id: string;
  status: string;
  created?: number;
  current_period_end?: number;
  items?: { data?: Array<{ current_period_end?: number }> };
  customer?: string | { id?: string } | null;
}

/** Read subscription *id* from Stripe with the restricted key (Subscriptions read), or null when it cannot be had:
 *  no key, an id not in Stripe's form, a refused redirect, an answer that is not 2xx, or one that does not name it. */
async function readSubscription(env: Env, id: unknown): Promise<StripeSubscription | null> {
  if (!env.STRIPE_RESTRICTED_KEY || typeof id !== "string" || !/^[A-Za-z0-9_-]{1,255}$/.test(id)) return null;
  try {
    const resp = await fetchFollowingSameHost(`${stripeBase(env)}/v1/subscriptions/${encodeURIComponent(id)}`, {
      method: "GET",
      headers: { authorization: `Bearer ${env.STRIPE_RESTRICTED_KEY}` },
    });
    if (!resp.ok) return null;
    const body = (await resp.json()) as Partial<StripeSubscription> | null;
    if (!body || body.id !== id || typeof body.status !== "string") return null;
    return body as StripeSubscription;
  } catch {
    return null;
  }
}

/** The body TierCacheDO /apply-subscription takes for *sub*, read for the event *eventId*. */
function subscriptionBody(sub: StripeSubscription, eventId: string): string {
  // current_period_end moved from Subscription to Subscription Items in Stripe API 2025-09-30.clover and later. Read
  // from items first; fall back to the legacy field for older API versions.
  const periodEnd = sub.items?.data?.[0]?.current_period_end ?? sub.current_period_end;
  return JSON.stringify({
    subscription: {
      id: sub.id,
      status: sub.status,
      current_period_end: typeof periodEnd === "number" ? periodEnd : null,
      created: typeof sub.created === "number" ? sub.created : null,
    },
    stripe_event_id: eventId,
  });
}

/** Apply *body* to the tier shard named *name*: the tier the shard now derives and what became of the record, or null
 *  when the write failed. */
async function applyToShard(
  env: Env,
  name: string,
  body: string,
): Promise<{ tier: "free" | "solo"; outcome: string } | null> {
  const stub = env.TIER_CACHE.get(env.TIER_CACHE.idFromName(name));
  const resp = await stub.fetch(
    new Request("https://internal/apply-subscription", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    }),
  );
  if (!resp.ok) return null;
  const out = (await resp.json()) as { status?: string; record?: { tier?: "free" | "solo" } };
  if (out.record?.tier !== "free" && out.record?.tier !== "solo") return null;
  return { tier: out.record.tier, outcome: out.status ?? "applied" };
}

/**
 * W38-S1326 (a): a subscription /v1/billing/checkout created names its buyer's billing id, which the checkout bound
 * to the buyer's token. Map it through AuthStoreDO /lookup-user and write the token-keyed shard, the one /v1/quota
 * and /v1/messages read, from the subscription as Stripe holds it now (W38-S1335 (a)). An id no checkout bound is
 * acknowledged and ignored; a lookup, a read from Stripe or a write that fails answers 500, so Stripe sends the event
 * again.
 */
async function applyByBillingId(env: Env, event: StripeEvent, billingId: string): Promise<Response> {
  const reply = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  if (!isBillingId(billingId)) return reply(200, { status: "invalid_billing_id" });
  let applied: { tier: "free" | "solo"; outcome: string } | null;
  let current: StripeSubscription | null;
  try {
    const authStub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
    const lookupResp = await authStub.fetch(
      `https://internal/lookup-user?h=${encodeURIComponent(billingId)}`,
      { method: "GET" },
    );
    if (lookupResp.status === 404) return reply(200, { status: "unknown_billing_id" });
    if (!lookupResp.ok) return reply(500, { error: "lookup_failed" });
    const { token_id: tokenId } = (await lookupResp.json()) as { token_id: string };
    current = await readSubscription(env, event.data.object.id);
    if (!current) return reply(500, { error: "subscription_read_failed" });
    applied = await applyToShard(env, tokenId, subscriptionBody(current, event.id));
    if (!applied) return reply(500, { error: "tier_write_failed" });
  } catch {
    return reply(500, { error: "billing_apply_failed" });
  }
  // Record the subscription's customer for the portal, which reads it before Stripe's search. Best effort: a missed
  // record leaves the portal on the search, which finds the subscription once Stripe has indexed it.
  // Ordered by the subscription's own creation time, never the event's: Stripe "doesn't guarantee the delivery of
  // events in the order that they're generated", and "Don't use `created` to determine event order"
  // (docs.stripe.com/webhooks, "Event ordering"). AuthStoreDO keeps the newest subscription's customer.
  let customerRecorded = false;
  const customer = typeof current.customer === "string" ? current.customer : current.customer?.id;
  if (typeof customer === "string" && customer && typeof current.created === "number") {
    try {
      const authStub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
      const bound = await authStub.fetch("https://internal/bind-customer", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ billing_id: billingId, customer, subscription_created: current.created }),
      });
      customerRecorded = bound.ok;
    } catch {
      customerRecorded = false;
    }
  }
  return reply(200, {
    status: "applied",
    tier: applied.tier,
    subscription_record: applied.outcome,
    billing_id_prefix: billingId.slice(0, 8),
    token_shard_written: true,
    customer_recorded: customerRecorded,
  });
}
