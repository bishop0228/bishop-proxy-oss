export interface TierRecord {
  tier: "free" | "solo";
  verified_at: string;       // ISO8601
  valid_until: string;       // ISO8601
  last_stripe_event_id: string | null;
}

export class TierCacheDO {
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      const record = await this.state.storage.get<TierRecord>("record");
      if (!record) {
        return new Response(JSON.stringify({ error: "no_record" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify(record), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
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
        return new Response(JSON.stringify({ status: "already_applied" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      const newRecord: TierRecord = {
        tier: body.tier,
        verified_at: new Date().toISOString(),
        valid_until: body.valid_until,
        last_stripe_event_id: body.stripe_event_id,
      };
      await this.state.storage.put("record", newRecord);
      return new Response(JSON.stringify({ status: "applied", record: newRecord }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }
}
