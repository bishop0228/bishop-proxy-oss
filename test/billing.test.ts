/**
 * W38-S1326 (a) — the proxy's billing routes and the webhook's billing id (the founder's decisions of 2026-11-10).
 *
 * /v1/billing/checkout and /v1/billing/portal create Stripe sessions for the device the bearer token authenticates,
 * through a mock Stripe API (STRIPE_API_BASE_URL). The checkout carries a billing id the proxy derives from the
 * caller's token, never a user id; the webhook maps that id to the token's tier shard; the legacy user_id path still
 * applies; /v1/tier/bind is gone.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { unstable_dev, Unstable_DevWorker } from "wrangler";
import { argon2id } from "@noble/hashes/argon2.js";
import { clearAuthRateLimits } from "./helpers/clear-auth-rate-limits";
import { handleBillingCheckout, handleBillingPortal } from "../src/routes/billing";
import type { Env } from "../src/index";

const STRIPE_TEST_SECRET = "test_secret";
const RESTRICTED_KEY = "rk_test_billing_key";
const PRICE = "price_solo_test";
const SUCCESS = "https://mybishop.ai/billing/success";
const CANCEL = "https://mybishop.ai/billing/cancel";
const RETURN = "https://mybishop.ai/billing/return";

const PROXY_VARS_BASE = {
  STRIPE_WEBHOOK_SECRET: STRIPE_TEST_SECRET,
  ANTHROPIC_API_KEY: "test_key",
  TARGET_ZERO_BITS: "8",
  TARGET_MEMORY_KIB: "8",
  CHALLENGE_TTL: "60",
  MOCK_AI: "1",
};

// ── PoW + enroll helpers (as azure.test.ts) ──────────────────────────────────

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function countLeadingZeroBits(bytes: Uint8Array): number {
  let count = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      count += 8;
    } else {
      count += Math.clz32(byte) - 24;
      break;
    }
  }
  return count;
}

function solvePow(fingerprintHash: string, nonce: string, targetBits: number, memKib: number): string {
  const fpBytes = fromHex(fingerprintHash);
  const nonceBytes = fromHex(nonce);
  const salt = new Uint8Array(24);
  salt.set(nonceBytes, 0);
  for (let i = 0; i < 0xffffffff; i++) {
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, BigInt(i), false);
    salt.set(counterBytes, 16);
    const hash = argon2id(fpBytes, salt, { t: 1, m: memKib, p: 1, dkLen: 32 });
    if (countLeadingZeroBits(hash) >= targetBits) return toHex(counterBytes);
  }
  throw new Error("No solution found");
}

async function enroll(worker: Unstable_DevWorker, fp: string): Promise<string> {
  const challengeRes = await worker.fetch("/v1/challenge");
  if (challengeRes.status !== 200) throw new Error(`challenge failed: ${challengeRes.status}`);
  const { nonce } = (await challengeRes.json()) as { nonce: string };
  const enrollRes = await worker.fetch("/v1/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce,
      counter: solvePow(fp, nonce, 8, 8),
      fingerprint_hash: fp,
      client_version: "test-billing-0.1.0",
    }),
  });
  expect([200, 201]).toContain(enrollRes.status);
  return ((await enrollRes.json()) as { token: string }).token;
}

async function signStripeBody(rawBody: string, timestamp: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(STRIPE_TEST_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${rawBody}`));
  return `t=${timestamp},v1=${toHex(new Uint8Array(sig))}`;
}

async function postSubscriptionEvent(
  worker: Unstable_DevWorker,
  eventId: string,
  metadata: Record<string, string>,
  opts: { customer?: string; type?: string; status?: string; subscription?: string; subscriptionCreated?: number } = {},
) {
  const body = JSON.stringify({
    id: eventId,
    type: opts.type ?? "customer.subscription.updated",
    data: {
      object: {
        id: opts.subscription ?? "sub_test_mock",
        created: opts.subscriptionCreated ?? Math.floor(Date.now() / 1000),
        status: opts.status ?? "active",
        items: { data: [{ current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400 }] },
        metadata,
        ...(opts.customer ? { customer: opts.customer } : {}),
      },
    },
  });
  return worker.fetch("/stripe/webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "Stripe-Signature": await signStripeBody(body, Math.floor(Date.now() / 1000)),
    },
    body,
  });
}

// ── Workers ──────────────────────────────────────────────────────────────────

describe("W38-S1326 (a) billing routes", () => {
  let mock: Unstable_DevWorker;
  let worker: Unstable_DevWorker;
  let mockUrl: string;
  let tokenA: string;
  let tokenB: string;
  let tokenC: string;
  let tokenD: string;

  type Last = {
    checkout: { auth: string | null; body: string | null } | null;
    search: { auth: string | null; query: string | null } | null;
    portal: { auth: string | null; body: string | null } | null;
    hits: number;
  };
  const last = async (): Promise<Last> => (await (await mock.fetch(`${mockUrl}/__last`)).json()) as Last;
  const post = (path: string, token?: string) =>
    worker.fetch(path, {
      method: "POST",
      headers: token ? { authorization: `Bearer ${token}`, "content-type": "application/json" } : {},
      body: "{}",
    });
  const checkoutId = async (token: string): Promise<string> => {
    const res = await post("/v1/billing/checkout", token);
    expect(res.status).toBe(200);
    const sent = new URLSearchParams((await last()).checkout?.body ?? "");
    return sent.get("client_reference_id") ?? "";
  };

  beforeAll(async () => {
    mock = await unstable_dev("test/mock-stripe-upstream.ts", {
      config: "test/wrangler.mock.toml",
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
      persist: false,
    });
    mockUrl = `http://${mock.address}:${mock.port}`;
    worker = await unstable_dev("src/index.ts", {
      experimental: { disableExperimentalWarning: true },
      env: "staging",
      vars: {
        ...PROXY_VARS_BASE,
        ADMIN_TOKEN: "test_admin",
        USER_INDEX_HMAC_KEY: "test_hmac_key",
        STRIPE_API_BASE_URL: mockUrl,
        BISHOP_TEST_OUTBOUND_HOSTS: mock.address,
        STRIPE_RESTRICTED_KEY: RESTRICTED_KEY,
        STRIPE_SOLO_PRICE_ID: PRICE,
        BILLING_SUCCESS_URL: SUCCESS,
        BILLING_CANCEL_URL: CANCEL,
        BILLING_RETURN_URL: RETURN,
      },
      persist: false,
    });
    await clearAuthRateLimits(worker);
    tokenA = await enroll(worker, "13".repeat(32));
    tokenB = await enroll(worker, "57".repeat(32));
    tokenC = await enroll(worker, "9b".repeat(32));
    tokenD = await enroll(worker, "d4".repeat(32));
  }, 60000);

  afterAll(async () => {
    await worker.stop();
    await mock.stop();
  });

  beforeEach(async () => {
    await mock.fetch(`${mockUrl}/__reset`, { method: "POST" });
  });

  it("refuses both routes without a bearer, or with a token never enrolled, and calls Stripe for neither", async () => {
    for (const path of ["/v1/billing/checkout", "/v1/billing/portal"]) {
      expect((await post(path)).status).toBe(401);
      expect((await post(path, "not-a-real-token-0123456789abcdef")).status).toBe(401);
    }
    expect((await last()).hits).toBe(0);
  });

  it("sends Stripe the billing id, the Solo price and the vars' pages, with the restricted key, and no user id", async () => {
    const res = await post("/v1/billing/checkout", tokenA);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: "https://checkout.stripe.com/c/pay/cs_test_mock" });
    const seen = (await last()).checkout;
    expect(seen?.auth).toBe(`Bearer ${RESTRICTED_KEY}`);
    const sent = new URLSearchParams(seen?.body ?? "");
    const id = sent.get("client_reference_id") ?? "";
    expect(id).toMatch(/^[0-9a-f]{64}$/);
    expect(sent.get("subscription_data[metadata][billing_id]")).toBe(id);
    expect(sent.get("mode")).toBe("subscription");
    expect(sent.get("line_items[0][price]")).toBe(PRICE);
    expect(sent.get("line_items[0][quantity]")).toBe("1");
    expect(sent.get("success_url")).toBe(SUCCESS);
    expect(sent.get("cancel_url")).toBe(CANCEL);
    for (const key of sent.keys()) expect(key).not.toMatch(/user/);
    expect(seen?.body ?? "").not.toContain(tokenA);
  });

  it("derives the same billing id for a token each time, and a different one for another token", async () => {
    const a1 = await checkoutId(tokenA);
    const a2 = await checkoutId(tokenA);
    const b1 = await checkoutId(tokenB);
    expect(a1).toBe(a2);
    expect(b1).not.toBe(a1);
  });

  it("opens the portal for the customer whose subscription carries the caller's billing id", async () => {
    const id = await checkoutId(tokenA);
    await mock.fetch(`${mockUrl}/__subscription`, { method: "POST", body: JSON.stringify({ customer: "cus_test_a" }) });
    const res = await post("/v1/billing/portal", tokenA);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: "https://billing.stripe.com/p/session/test_mock" });
    const seen = await last();
    expect(seen.search?.query).toBe(`metadata['billing_id']:'${id}'`);
    expect(seen.search?.auth).toBe(`Bearer ${RESTRICTED_KEY}`);
    const sent = new URLSearchParams(seen.portal?.body ?? "");
    expect(sent.get("customer")).toBe("cus_test_a");
    expect(sent.get("return_url")).toBe(RETURN);
  });

  it("answers 404 no_subscription when the caller has no subscription, and opens no portal", async () => {
    const res = await post("/v1/billing/portal", tokenB);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "no_subscription" });
    const seen = await last();
    expect(seen.search).not.toBeNull();
    expect(seen.portal).toBeNull();
  });

  it("opens the portal for a subscription made seconds ago, from the customer its event recorded, before Stripe's search sees it", async () => {
    // Stripe: "Don't use search for read-after-write flows ... data is searchable in under 1 minute" (docs.stripe.com/search).
    const id = await checkoutId(tokenC);
    const event = await postSubscriptionEvent(worker, "evt_billing_c_created", { billing_id: id }, {
      customer: "cus_JustMade42",
      type: "customer.subscription.created",
    });
    expect(await event.json()).toMatchObject({ status: "applied", customer_recorded: true });
    // The mock's search still answers no subscription, as Stripe's does until it has indexed the new one.
    const res = await post("/v1/billing/portal", tokenC);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: "https://billing.stripe.com/p/session/test_mock" });
    const seen = await last();
    expect(seen.search).toBeNull();
    expect(new URLSearchParams(seen.portal?.body ?? "").get("customer")).toBe("cus_JustMade42");
  });

  it("records a customer id of up to 255 letters, digits, '_' and '-', the form Stripe documents, and refuses any other", async () => {
    // Stripe: "Make sure that your integration can handle Stripe-generated object IDs, which can contain up to 255
    // characters" (docs.stripe.com/api-versions); customer IDs "can only contain alphanumeric and `_-` characters"
    // (docs.stripe.com/changelog/2018-05-21).
    const id = await checkoutId(tokenC);
    const longest = "cus_" + "a1_-".repeat(62) + "Zz9";
    expect(longest.length).toBe(255);
    const kept = await postSubscriptionEvent(worker, "evt_billing_c_255", { billing_id: id }, { customer: longest });
    expect(await kept.json()).toMatchObject({ status: "applied", customer_recorded: true });
    for (const [eventId, refused] of [
      ["evt_billing_c_256", longest + "x"],
      ["evt_billing_c_slash", "cus_a/b"],
      ["evt_billing_c_space", "cus_a b"],
    ]) {
      const res = await postSubscriptionEvent(worker, eventId, { billing_id: id }, { customer: refused });
      expect(await res.json()).toMatchObject({ status: "applied", customer_recorded: false });
    }
    // The portal opens for the id recorded last, never for a refused one.
    expect((await post("/v1/billing/portal", tokenC)).status).toBe(200);
    expect(new URLSearchParams((await last()).portal?.body ?? "").get("customer")).toBe(longest);
  });

  it("keeps the customer of the newer subscription when an older subscription's event is delivered after it, and the portal opens for it", async () => {
    // Stripe "doesn't guarantee the delivery of events in the order that they're generated" and retries a failed
    // delivery "for up to three days" (docs.stripe.com/webhooks): subscription A's cancellation can arrive after the
    // owner has bought B, which a new checkout gives a new customer.
    const id = await checkoutId(tokenD);
    const newer = await postSubscriptionEvent(worker, "evt_billing_d_b_created", { billing_id: id }, {
      customer: "cus_NewerB",
      type: "customer.subscription.created",
      subscription: "sub_newer_b",
      subscriptionCreated: 1893459600,
    });
    expect(await newer.json()).toMatchObject({ status: "applied", customer_recorded: true });
    const older = await postSubscriptionEvent(worker, "evt_billing_d_a_deleted", { billing_id: id }, {
      customer: "cus_OlderA",
      type: "customer.subscription.deleted",
      status: "canceled",
      subscription: "sub_older_a",
      subscriptionCreated: 1893456000,
    });
    expect(await older.json()).toMatchObject({ status: "applied", customer_recorded: false });
    expect((await post("/v1/billing/portal", tokenD)).status).toBe(200);
    expect(new URLSearchParams((await last()).portal?.body ?? "").get("customer")).toBe("cus_NewerB");
  });

  it("lets an event of a subscription created in the same second replace the record", async () => {
    const id = await checkoutId(tokenD);
    for (const [eventId, customer, subscription] of [
      ["evt_billing_d_tie_first", "cus_TieFirst", "sub_tie_first"],
      ["evt_billing_d_tie_second", "cus_TieSecond", "sub_tie_second"],
    ]) {
      const res = await postSubscriptionEvent(worker, eventId, { billing_id: id }, {
        customer,
        subscription,
        subscriptionCreated: 1893459600,
      });
      expect(await res.json()).toMatchObject({ status: "applied", customer_recorded: true });
    }
    expect((await post("/v1/billing/portal", tokenD)).status).toBe(200);
    expect(new URLSearchParams((await last()).portal?.body ?? "").get("customer")).toBe("cus_TieSecond");
  });

  it("maps a subscription's billing id to its token's tier shard, and only that token's", async () => {
    const id = await checkoutId(tokenA);
    const res = await postSubscriptionEvent(worker, "evt_billing_a_1", { billing_id: id });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "applied", tier: "solo", token_shard_written: true });
    const quota = async (token: string) =>
      ((await (await worker.fetch("/v1/quota", { headers: { authorization: `Bearer ${token}` } })).json()) as {
        tier: string;
      }).tier;
    expect(await quota(tokenA)).toBe("solo");
    expect(await quota(tokenB)).toBe("free");
  });

  it("acknowledges a billing id no checkout bound, and changes no tier", async () => {
    const res = await postSubscriptionEvent(worker, "evt_billing_unknown_1", { billing_id: "ab".repeat(32) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "unknown_billing_id" });
  });

  it("still applies a legacy subscription that names a user_id", async () => {
    const userId = "legacy-user-0000-1111-2222";
    const res = await postSubscriptionEvent(worker, "evt_legacy_user_1", { user_id: userId });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "applied", tier: "solo", user_id_prefix: userId.slice(0, 8) });
    const tier = await worker.fetch("/v1/tier", { headers: { authorization: `Bearer ${userId}` } });
    expect(((await tier.json()) as { tier: string }).tier).toBe("solo");
  });

  it("no longer serves /v1/tier/bind", async () => {
    const res = await worker.fetch("/v1/tier/bind", {
      method: "POST",
      headers: { authorization: `Bearer ${tokenA}`, "content-type": "application/json" },
      body: JSON.stringify({ user_id: "anyone-at-all-0000" }),
    });
    expect(res.status).toBe(404);
  });
});

describe("W38-S1326 (a) billing routes before the deploy sets them up", () => {
  function envWith(vars: Partial<Env>): Env {
    const authStore = {
      fetch: async () =>
        new Response(JSON.stringify({ valid: true, record: { token_id: "tok_unit" }, reason: null }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    };
    return {
      AUTH_STORE: { idFromName: () => ({}), get: () => authStore },
      USER_INDEX_HMAC_KEY: "test_hmac_key",
      ...vars,
    } as unknown as Env;
  }
  const req = () =>
    new Request("https://proxy.test/v1/billing/checkout", {
      method: "POST",
      headers: { authorization: "Bearer a-token-long-enough-0123456789" },
    });

  it("answers 503 billing_not_configured, calling nothing, until the key and the vars are set", async () => {
    const calls: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response("{}", { status: 500 });
    }) as typeof fetch;
    try {
      for (const vars of [{}, { STRIPE_RESTRICTED_KEY: "rk_x" }, { STRIPE_RESTRICTED_KEY: "rk_x", STRIPE_SOLO_PRICE_ID: "p" }]) {
        const res = await handleBillingCheckout(req(), envWith(vars));
        expect(res.status).toBe(503);
        expect(await res.json()).toEqual({ error: "billing_not_configured" });
      }
      const portal = await handleBillingPortal(req(), envWith({ STRIPE_RESTRICTED_KEY: "rk_x" }));
      expect(portal.status).toBe(503);
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(calls).toEqual([]);
  });

  it("refuses a redirect off Stripe's host on the portal's session call, after the search, contacting nothing else", async () => {
    const hosts: string[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      hosts.push(url.hostname);
      if (url.pathname === "/v1/subscriptions/search") {
        return new Response(JSON.stringify({ data: [{ customer: "cus_unit" }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } });
    }) as typeof fetch;
    try {
      const res = await handleBillingPortal(req(), envWith({ STRIPE_RESTRICTED_KEY: "rk_x", BILLING_RETURN_URL: RETURN }));
      expect(res.status).toBe(502);
      expect(await res.text()).toContain("upstream_redirect_refused");
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(hosts).toEqual(["api.stripe.com", "api.stripe.com"]);
  });
});
