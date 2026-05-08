import type { Env } from "../index";
import { computeUserHash } from "../lib/user-hash";

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
      metadata?: { user_id?: string };
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
  const userId = sub.metadata?.user_id;
  if (!userId) {
    // Subscription without a user_id — created outside Bishop's flow (or a pre-fix
    // subscription created before the metadata propagation patch landed).
    return new Response(JSON.stringify({ status: "no_user_id" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  const isActive =
    (event.type === "customer.subscription.updated" || event.type === "customer.subscription.created") &&
    sub.status === "active";
  const tier: "free" | "solo" = isActive ? "solo" : "free";
  // current_period_end moved from Subscription to Subscription Items in
  // Stripe API 2025-09-30.clover and later. Read from items first; fall
  // back to the legacy field for older API versions.
  const currentPeriodEnd =
    sub.items?.data?.[0]?.current_period_end ?? sub.current_period_end;
  const validUntil =
    isActive && currentPeriodEnd
      ? new Date(currentPeriodEnd * 1000).toISOString()
      : new Date().toISOString();

  const setBody = JSON.stringify({
    tier,
    valid_until: validUntil,
    stripe_event_id: event.id,
  });

  // Shard 1 (legacy/user-keyed): preserved for backward compatibility with
  // /v1/tier reads and for users who haven't yet bound a token.
  const userStub = env.TIER_CACHE.get(env.TIER_CACHE.idFromName(userId));
  await userStub.fetch(
    new Request("https://internal/set", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: setBody,
    })
  );

  // Shard 2 (token-keyed). Look up token_id via AuthStoreDO
  // /lookup-user using HMAC(user_id). 404 means "user has not bound a token
  // yet" — silently skip; the user-keyed shard write above is sufficient
  // until the daemon calls /v1/tier/bind. The token-keyed shard is what
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
      const tokenStub = env.TIER_CACHE.get(env.TIER_CACHE.idFromName(tokenId));
      await tokenStub.fetch(
        new Request("https://internal/set", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: setBody,
        })
      );
      tokenShardWritten = true;
    }
  } catch (err) {
    // Token-keyed shard write is best-effort — failing it must not fail the
    // webhook (Stripe retries on non-2xx, which would re-apply the user-keyed
    // shard via the idempotency guard but provides no path to recover the
    // token-keyed write). Logged for observability.
    console.log(JSON.stringify({
      event_type: "error",
      timestamp: new Date().toISOString(),
      stripe_event_id: event.id,
      note: "tier_cache_token_shard_failed",
      error: err instanceof Error ? err.message : String(err),
    }));
  }

  return new Response(
    JSON.stringify({
      status: "applied",
      tier,
      user_id_prefix: userId.slice(0, 8),
      token_shard_written: tokenShardWritten,
    }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}
