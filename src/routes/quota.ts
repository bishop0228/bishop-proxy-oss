/**
 * GET /v1/quota.
 *
 * Authenticated read-only view of the caller's tier + remaining quota,
 * derived from TierCacheDO (token-keyed shard, idFromName(token_id)) and
 * QuotaStoreDO (also token-keyed). 30-second response cache.
 * keyed on token_id, served via the Workers Cache API.
 *
 * Shape:
 *   { tier, valid_until,
 *     monthly_cost_cents_used, monthly_cost_cents_remaining,
 *     monthly_tasks_used, monthly_tasks_remaining,
 *     daily_tasks_used, daily_tasks_remaining }
 *
 * "remaining = null" means the cap is null (unmetered for this dimension at
 * this tier — e.g., studio across the board, solo on daily_floor).
 *
 * Tier-cache 404 (token-keyed shard never seeded) falls back to "free" — the
 * AuthStoreDO best-effort seed in _issueToken makes this rare, but we treat
 * "no record" as the documented default per brief.
 */

import type { Env } from "../index";
import { verifyBearer } from "../lib/auth";
import type { TierRecord } from "../durable-objects/tier-cache";
import type { QuotaState } from "../durable-objects/quota-store";
import { TIER_CAPS, MICROCENTS_PER_CENT, type Tier } from "../lib/pricing";

const QUOTA_CACHE_TTL_SECONDS = 30;

function remaining(used: number, cap: number | null): number | null {
  if (cap === null) return null;
  return Math.max(0, cap - used);
}

export async function handleQuotaGet(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const auth = await verifyBearer(request, env);
  if (!auth.ok) return auth.response;

  const tokenId = auth.record.token_id;
  const cacheKey = new Request(`https://internal.cache/v1/quota/${tokenId}`, {
    method: "GET",
  });
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;

  const tierStub = env.TIER_CACHE.get(env.TIER_CACHE.idFromName(tokenId));
  const tierResp = await tierStub.fetch("https://internal/");
  let tier: Tier = "free";
  let validUntil: string | null = null;
  if (tierResp.ok) {
    const tierRec = (await tierResp.json()) as TierRecord;
    tier = tierRec.tier;
    validUntil = tierRec.valid_until;
  }

  const quotaStub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
  const quotaResp = await quotaStub.fetch("https://internal/");
  const quota = (await quotaResp.json()) as QuotaState;

  const cap = TIER_CAPS[tier];
  // W38-S938: the meter accumulates in micro-cents; the /v1/quota response keeps
  // its cents shape. Derive cents by ceiling the micro-cent total at DISPLAY only
  // (never a per-request floor). The cap table stays authored in cents.
  const monthlyCostCentsUsed = Math.ceil(quota.monthly_cost_microcents / MICROCENTS_PER_CENT);
  const payload = {
    tier,
    valid_until: validUntil,
    monthly_cost_cents_used: monthlyCostCentsUsed,
    monthly_cost_cents_remaining: remaining(monthlyCostCentsUsed, cap.monthly_cost_cents),
    monthly_tasks_used: quota.monthly_tasks,
    monthly_tasks_remaining: remaining(quota.monthly_tasks, cap.monthly_tasks),
    daily_tasks_used: quota.daily_tasks,
    daily_tasks_remaining: remaining(quota.daily_tasks, cap.daily_floor),
  };

  const response = new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": `private, max-age=${QUOTA_CACHE_TTL_SECONDS}`,
    },
  });

  ctx.waitUntil(caches.default.put(cacheKey, response.clone()));
  return response;
}
