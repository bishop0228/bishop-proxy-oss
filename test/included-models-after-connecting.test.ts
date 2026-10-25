/**
 * W38-S1168 (founder decision 2026-10-25, (a)): a paying device keeps its included models after it connects a provider
 * of its own, and its own key is used only where the request names one. A free device that connected keeps today's
 * meaning: its own key only.
 *
 * A device's record says byok for good once it connects anything (auth-store's one-way relabel). Before this decision
 * every /v1/messages request from such a device needed its own Anthropic key (x-bishop-upstream-key) and was refused
 * byok_key_missing without one, so a Solo owner who connected, say, a local server lost the models the plan includes.
 * /v1/messages now reads the request through servedMode: the quota check, the key and the increment all follow it.
 *
 * Drives the real handler over fake stores and a stubbed upstream, and reads what it sent: the key the upstream saw,
 * and the account_mode the quota check and the increment were given.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleMessages } from "../src/routes/messages";
import { isManaged, servedMode } from "../src/lib/managed-scope";
import type { Env } from "../src/index";

const DEVICE = "bsk_staging_" + "s".repeat(24);
const OPERATOR = "op-anthropic-key";
const OWN = "user-anthropic-key";

type Mode = "managed" | "byok";
type Tier = "free" | "solo" | "studio";
interface QuotaCall { path: string; body: Record<string, unknown> }

function namespace(handler: (req: Request) => Promise<Response> | Response): DurableObjectNamespace {
  const stub = {
    fetch: async (input: RequestInfo, init?: RequestInit) =>
      handler(input instanceof Request ? input : new Request(input as string, init)),
  };
  return {
    idFromName: () => ({ toString: () => "id" }),
    idFromString: () => ({ toString: () => "id" }),
    newUniqueId: () => ({ toString: () => "id" }),
    get: () => stub,
  } as unknown as DurableObjectNamespace;
}

const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });

function makeEnv(accountMode: Mode, tier: Tier, quota: QuotaCall[]): Env {
  const record = {
    token: DEVICE,
    token_id: "55555555-5555-4555-8555-555555555555",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-s1168",
    account_mode: accountMode,
  };
  return {
    AUTH_STORE: namespace(() => json({ valid: true, record, reason: null })),
    TIER_CACHE: namespace(() => json({ tier })),
    QUOTA_STORE: namespace(async (req) => {
      const path = new URL(req.url).pathname;
      if (req.method === "GET") {
        return json({
          period_month: "2026-10", period_day: "2026-10-25", monthly_cost_microcents: 0,
          monthly_tasks: 0, daily_tasks: 0, monthly_uploads: 0, monthly_upload_bytes: 0,
        });
      }
      quota.push({ path, body: (await req.json()) as Record<string, unknown> });
      return json({ ok: true });
    }),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
    ANTHROPIC_API_KEY: OPERATOR,
  } as unknown as Env;
}

/** A context that keeps the work the handler hands to waitUntil, so a test can wait for the increment. */
function makeCtx(): { ctx: ExecutionContext; settled: () => Promise<unknown> } {
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (p: Promise<unknown>) => { pending.push(p); },
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
  return { ctx, settled: () => Promise.all(pending) };
}

function messagesReq(ownKey?: string): Request {
  const headers: Record<string, string> = {
    authorization: `Bearer ${DEVICE}`,
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
  };
  if (ownKey !== undefined) headers["x-bishop-upstream-key"] = ownKey;
  return new Request("http://proxy/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify({ model: "claude-haiku-4-5", max_tokens: 16, messages: [{ role: "user", content: "hi" }] }),
  });
}

/** Drive /v1/messages once; return the status, the key the upstream saw, and the quota calls in order. */
async function drive(accountMode: Mode, tier: Tier, ownKey?: string) {
  const sent: Headers[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    sent.push(input instanceof Request ? input.headers : new Headers(init?.headers));
    return json({
      id: "msg_1", type: "message", role: "assistant", content: [], model: "claude-haiku-4-5",
      usage: { input_tokens: 1, output_tokens: 1 },
    });
  }));
  const quota: QuotaCall[] = [];
  const { ctx, settled } = makeCtx();
  const resp = await handleMessages(messagesReq(ownKey), makeEnv(accountMode, tier, quota), ctx);
  await settled();
  const body = resp.status === 200 ? null : ((await resp.json()) as { error: string });
  return {
    status: resp.status,
    error: body?.error ?? null,
    upstreamKeys: sent.map((h) => h.get("x-api-key")),
    modeAt: (path: string) => quota.find((c) => c.path === path)?.body.account_mode,
    quota,
  };
}

describe("W38-S1168: servedMode and isManaged", () => {
  const withKey = new Headers({ "x-bishop-upstream-key": OWN });
  const blankKey = new Headers({ "x-bishop-upstream-key": "   " });
  const none = new Headers();

  it("a managed device is served managed on every tier, whatever the request carries", () => {
    for (const tier of ["free", "solo", "studio"] as const) {
      for (const h of [withKey, blankKey, none]) {
        expect(servedMode("managed", tier, h)).toBe("managed");
        expect(servedMode(null, tier, h)).toBe("managed");
        expect(servedMode(undefined, tier, h)).toBe("managed");
      }
    }
  });

  it("a free device that connected is served byok, with or without a key of its own", () => {
    for (const h of [withKey, blankKey, none]) expect(servedMode("byok", "free", h)).toBe("byok");
  });

  it("a paying device that connected is served byok only where the request names a key", () => {
    for (const tier of ["solo", "studio"] as const) {
      expect(servedMode("byok", tier, withKey)).toBe("byok");
      expect(servedMode("byok", tier, blankKey)).toBe("managed");
      expect(servedMode("byok", tier, none)).toBe("managed");
    }
  });

  it("isManaged reads a record without a mode as managed", () => {
    expect(isManaged("managed")).toBe(true);
    expect(isManaged(null)).toBe(true);
    expect(isManaged(undefined)).toBe(true);
    expect(isManaged("byok")).toBe(false);
  });
});

describe("W38-S1168: /v1/messages for a device that connected a provider of its own", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("★ a paying device with no key of its own is served its included models: the operator key, metered as managed", async () => {
    for (const tier of ["solo", "studio"] as const) {
      const r = await drive("byok", tier);
      expect(r.status).toBe(200);
      expect(r.upstreamKeys).toEqual([OPERATOR]);
      expect(r.modeAt("/check")).toBe("managed");
      expect(r.modeAt("/increment")).toBe("managed");
    }
  });

  it("★ the same device naming its own key uses that key and is metered as byok", async () => {
    const r = await drive("byok", "solo", OWN);
    expect(r.status).toBe(200);
    expect(r.upstreamKeys).toEqual([OWN]);
    expect(r.modeAt("/check")).toBe("byok");
    expect(r.modeAt("/increment")).toBe("byok");
  });

  it("★ a free device that connected keeps today's meaning: no key of its own is refused, nothing sent", async () => {
    const r = await drive("byok", "free");
    expect(r.status).toBe(400);
    expect(r.error).toBe("byok_key_missing");
    expect(r.upstreamKeys).toEqual([]);
    expect(r.quota.map((c) => c.path)).not.toContain("/increment");
  });

  it("CONTROL: a managed device is unchanged: the operator key, metered as managed, an inbound key ignored", async () => {
    for (const ownKey of [undefined, OWN]) {
      const r = await drive("managed", "free", ownKey);
      expect(r.status).toBe(200);
      expect(r.upstreamKeys).toEqual([OPERATOR]);
      expect(r.modeAt("/check")).toBe("managed");
      expect(r.modeAt("/increment")).toBe("managed");
    }
  });
});
