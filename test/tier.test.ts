import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";

const STRIPE_TEST_SECRET = "test_secret";

async function signStripeBody(rawBody: string, timestamp: number): Promise<string> {
  const signedPayload = `${timestamp}.${rawBody}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(STRIPE_TEST_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const sigHex = Array.from(new Uint8Array(sigBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `t=${timestamp},v1=${sigHex}`;
}

async function postSubscriptionEvent(
  worker: Unstable_DevWorker,
  opts: { eventId: string; userId: string; periodEnd: number },
) {
  const body = JSON.stringify({
    id: opts.eventId,
    type: "customer.subscription.updated",
    data: {
      object: {
        id: "sub_test",
        status: "active",
        items: { data: [{ current_period_end: opts.periodEnd }] },
        metadata: { user_id: opts.userId },
      },
    },
  });
  const sig = await signStripeBody(body, Math.floor(Date.now() / 1000));
  return worker.fetch("/stripe/webhook", {
    method: "POST",
    headers: { "content-type": "application/json", "Stripe-Signature": sig },
    body,
  });
}

describe("/v1/tier", () => {
  let worker: Unstable_DevWorker;

  beforeAll(async () => {
    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: { STRIPE_WEBHOOK_SECRET: STRIPE_TEST_SECRET, ANTHROPIC_API_KEY: "test_key" },
      persist: false,
    });
  });

  afterAll(async () => {
    await worker.stop();
  });

  it("returns 401 when Authorization missing", async () => {
    const res = await worker.fetch("/v1/tier");
    expect(res.status).toBe(401);
  });

  it("returns 400 when user_id too short", async () => {
    const res = await worker.fetch("/v1/tier", {
      headers: { Authorization: "Bearer x" },
    });
    expect(res.status).toBe(400);
  });

  it("returns Free tier default for unknown user_id", async () => {
    const res = await worker.fetch("/v1/tier", {
      headers: { Authorization: "Bearer test-user-id-unknown-1234" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { tier: string; verified_at: string; valid_until: string };
    expect(body.tier).toBe("free");
    expect(body.verified_at).toBeTruthy();
    expect(body.valid_until).toBeTruthy();
  });

  it("/health returns ok", async () => {
    const res = await worker.fetch("/health");
    expect(res.status).toBe(200);
  });

  // Non-null short-circuit branch of TierCacheDO /set.
  // Two webhook deliveries with the same Stripe event id must not bump
  // verified_at on the second call (idempotent replay). A subsequent webhook
  // with a different event id must update verified_at.
  // The companion null-path scenario (set-null/set-null both write — no
  // short-circuit when stripe_event_id is null) is exercised when Step 3.4
  // enrollment-seeding lands; no public route currently calls /set with null.
  it("idempotent replay: same Stripe event id does not bump verified_at", async () => {
    const userId = "tier-idempotency-user-0001";
    const eventId = "evt_idem_001";
    const periodEnd = Math.floor(Date.now() / 1000) + 30 * 86400;

    const r1 = await postSubscriptionEvent(worker, { eventId, userId, periodEnd });
    expect(r1.status).toBe(200);

    const t1 = await worker.fetch("/v1/tier", {
      headers: { Authorization: `Bearer ${userId}` },
    });
    expect(t1.status).toBe(200);
    const b1 = (await t1.json()) as { tier: string; verified_at: string };
    expect(b1.tier).toBe("solo");
    const verifiedAt1 = b1.verified_at;

    // Wait long enough for a fresh ISO timestamp if the second call did NOT
    // short-circuit. Sub-second resolution is fine here — Date.now() advances
    // monotonically between the two writes.
    await new Promise((r) => setTimeout(r, 25));

    const r2 = await postSubscriptionEvent(worker, { eventId, userId, periodEnd });
    expect(r2.status).toBe(200);

    const t2 = await worker.fetch("/v1/tier", {
      headers: { Authorization: `Bearer ${userId}` },
    });
    const b2 = (await t2.json()) as { verified_at: string };
    expect(b2.verified_at).toBe(verifiedAt1);

    await new Promise((r) => setTimeout(r, 25));

    const r3 = await postSubscriptionEvent(worker, {
      eventId: "evt_idem_002",
      userId,
      periodEnd: periodEnd + 86400,
    });
    expect(r3.status).toBe(200);

    const t3 = await worker.fetch("/v1/tier", {
      headers: { Authorization: `Bearer ${userId}` },
    });
    const b3 = (await t3.json()) as { verified_at: string };
    expect(b3.verified_at).not.toBe(verifiedAt1);
  });
});
