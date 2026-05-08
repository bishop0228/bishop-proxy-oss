import type { Env } from "../index";
import type { TierRecord } from "../durable-objects/tier-cache";

export async function handleTierGet(request: Request, env: Env): Promise<Response> {
  const auth = request.headers.get("Authorization") ?? "";
  const match = auth.match(/^Bearer\s+(.+)$/);
  if (!match) {
    return new Response(JSON.stringify({ error: "missing_authorization" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }
  const userId = match[1].trim();
  // user_id from daemon's user_identity.get_user_id() — UUID-shape, ~36 chars.
  if (userId.length < 8 || userId.length > 256) {
    return new Response(JSON.stringify({ error: "invalid_user_id" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  // DO id derived from the user_id (acting as bearer in this code path).
  const id = env.TIER_CACHE.idFromName(userId);
  const stub = env.TIER_CACHE.get(id);
  const doResponse = await stub.fetch(new Request("https://internal/", { method: "GET" }));

  if (doResponse.status === 404) {
    // Default Free tier for users whose Stripe subscription hasn't fired a webhook.
    const now = new Date();
    const validUntil = new Date(now.getTime() + 24 * 3600 * 1000);
    return new Response(
      JSON.stringify({
        tier: "free",
        verified_at: now.toISOString(),
        valid_until: validUntil.toISOString(),
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  }

  const record = (await doResponse.json()) as TierRecord;
  return new Response(
    JSON.stringify({
      tier: record.tier,
      verified_at: record.verified_at,
      valid_until: record.valid_until,
    }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}
