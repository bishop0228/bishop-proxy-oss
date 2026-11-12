export interface TierRecord {
  tier: "free" | "solo";
  verified_at: string;       // ISO8601
  valid_until: string;       // ISO8601
  last_stripe_event_id: string | null;
}

/**
 * W38-S1335 (a), the founder's decision of 2026-11-11: one record per Stripe subscription, kept under
 * sub:<subscription id>, holding the subscription's state as Stripe answered it when an event about it arrived (the
 * webhook reads it, never the event's snapshot). The tier is derived from these records when it is read: solo while any
 * recorded subscription is active within its period. A subscription Stripe has ended (canceled, incomplete_expired) is
 * held final: no later write changes it, so two deliveries handled at once cannot put back a state Stripe has ended.
 */
export interface SubscriptionRecord {
  id: string;
  status: string;
  current_period_end: number | null;  // seconds since the epoch, as Stripe gives it
  created: number | null;
  updated_at: string;                 // ISO8601: when Bishop last read the subscription from Stripe
  last_stripe_event_id: string | null;
}

const FINAL_STATUSES = new Set(["canceled", "incomplete_expired"]);
const SUBSCRIPTION_ID = /^[A-Za-z0-9_-]{1,255}$/;  // Stripe's ids: up to 255 letters, digits, '_' and '-'
const STATUS = /^[a-z_]{1,40}$/;

/** The tier the recorded subscriptions give at *now* (milliseconds): solo while any is active within its period. */
export function deriveTier(subs: SubscriptionRecord[], now: number): TierRecord {
  const latest = subs.reduce<SubscriptionRecord | null>((a, s) => (!a || s.updated_at > a.updated_at ? s : a), null);
  const active = subs.filter(
    (s) => s.status === "active" && s.current_period_end !== null && s.current_period_end * 1000 > now,
  );
  const until = active.length ? Math.max(...active.map((s) => s.current_period_end as number)) * 1000 : now;
  return {
    tier: active.length ? "solo" : "free",
    verified_at: latest ? latest.updated_at : new Date(now).toISOString(),
    valid_until: new Date(until).toISOString(),
    last_stripe_event_id: latest ? latest.last_stripe_event_id : null,
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export class TierCacheDO {
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  private async subscriptions(): Promise<SubscriptionRecord[]> {
    const listed = await this.state.storage.list<SubscriptionRecord>({ prefix: "sub:" });
    return [...listed.values()];
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      // A shard with subscription records answers from them, at the time of the read, so a period that ends with no
      // further event ends Solo too. One without (an enrollment seed, or a shard last written before W38-S1335) answers
      // its stored record, as before.
      const subs = await this.subscriptions();
      if (subs.length) return json(200, deriveTier(subs, Date.now()));
      const record = await this.state.storage.get<TierRecord>("record");
      if (!record) return json(404, { error: "no_record" });
      return json(200, record);
    }

    if (request.method === "POST" && url.pathname === "/apply-subscription") {
      const body = (await request.json()) as {
        subscription?: { id?: unknown; status?: unknown; current_period_end?: unknown; created?: unknown };
        stripe_event_id?: unknown;
      };
      const sub = body.subscription ?? {};
      const eventId = typeof body.stripe_event_id === "string" ? body.stripe_event_id : null;
      const periodEnd = sub.current_period_end;
      const created = sub.created;
      if (
        typeof sub.id !== "string" || !SUBSCRIPTION_ID.test(sub.id) ||
        typeof sub.status !== "string" || !STATUS.test(sub.status) ||
        !(periodEnd === null || (typeof periodEnd === "number" && Number.isSafeInteger(periodEnd))) ||
        !(created === null || (typeof created === "number" && Number.isSafeInteger(created)))
      ) {
        return json(400, { error: "invalid_fields" });
      }
      const key = `sub:${sub.id}`;
      let outcome = "applied";
      await this.state.storage.transaction(async (txn) => {
        const existing = await txn.get<SubscriptionRecord>(key);
        if (existing && FINAL_STATUSES.has(existing.status)) {
          outcome = "final_kept";
          return;
        }
        if (existing && eventId !== null && existing.last_stripe_event_id === eventId) {
          outcome = "already_applied";
          return;
        }
        const record: SubscriptionRecord = {
          id: sub.id as string,
          status: sub.status as string,
          current_period_end: periodEnd as number | null,
          created: created as number | null,
          updated_at: new Date().toISOString(),
          last_stripe_event_id: eventId,
        };
        await txn.put(key, record);
      });
      return json(200, { status: outcome, record: deriveTier(await this.subscriptions(), Date.now()) });
    }

    if (request.method === "POST" && url.pathname === "/set") {
      const body = (await request.json()) as {
        tier: "free" | "solo";
        valid_until: string;
        stripe_event_id: string | null;
      };
      const existing = await this.state.storage.get<TierRecord>("record");
      // null stripe_event_id means "not from a Stripe event" (e.g., enrollment
      // seed). Two consecutive null writes proceed normally; only non-null
      // matching event ids short-circuit as idempotent replays.
      if (
        existing
        && body.stripe_event_id !== null
        && existing.last_stripe_event_id === body.stripe_event_id
      ) {
        return json(200, { status: "already_applied" });
      }
      const newRecord: TierRecord = {
        tier: body.tier,
        verified_at: new Date().toISOString(),
        valid_until: body.valid_until,
        last_stripe_event_id: body.stripe_event_id,
      };
      await this.state.storage.put("record", newRecord);
      return json(200, { status: "applied", record: newRecord });
    }

    return json(404, { error: "not_found" });
  }
}
