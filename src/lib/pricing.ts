/**
 * Pricing + tier caps.
 *
 * Cost is computed per-request in cents, rounded UP to the next whole cent
 * (Math.ceil). The per-1M-token rates below are sourced from Anthropic public
 * pricing as of brief codification:
 *   haiku  — $0.25 input / $1.25 output / $0.025 cached  per 1M tokens
 *   sonnet — $3.00 input / $15.00 output / $0.30 cached  per 1M tokens
 *   opus   — $15.00 input / $75.00 output / $1.50 cached per 1M tokens
 *            (PLACEHOLDER — matches Anthropic public rates late 2025;
 *             pricing finalization gated on ≥30-day staging measurement)
 *
 * Internal storage is cents-per-1M to keep one rounding boundary at the end.
 *
 * Task weighting (G11): haiku=1, sonnet=3, opus=5. Used by QuotaStoreDO when
 * incrementing the monthly_tasks counter — a single sonnet request consumes
 * 3 task units; opus consumes 5.
 *
 * Tier caps (G12 / D2):
 *   free   — 100¢ monthly cost, 200 monthly tasks, 30 daily floor
 *   solo   — 480¢ monthly cost (PROVISIONAL — see brief), 2000 monthly tasks, no daily floor
 *   studio — all null (unmetered at P2.1; D2 defers studio row entirely until P2.2)
 *
 * NOTE on solo cap: 480¢ is severely undersized for Opus (~46 deep tasks at
 * ~10.5¢/task). Finalization gated on staging cost-measurement. Do not treat
 * as load-bearing outside this file.
 */

export type ModelFamily = "haiku" | "sonnet" | "opus";

export interface PricingRow {
  input_cents_per_1m: number;
  output_cents_per_1m: number;
  cached_cents_per_1m: number;
}

export const PRICING: Record<ModelFamily, PricingRow> = {
  haiku: {
    input_cents_per_1m: 25,
    output_cents_per_1m: 125,
    cached_cents_per_1m: 2.5,
  },
  sonnet: {
    input_cents_per_1m: 300,
    output_cents_per_1m: 1500,
    cached_cents_per_1m: 30,
  },
  opus: {
    input_cents_per_1m: 1500,
    output_cents_per_1m: 7500,
    cached_cents_per_1m: 150,
  },
};

export const TASK_WEIGHTS: Record<ModelFamily, number> = {
  haiku: 1,
  sonnet: 3,
  opus: 5,
};

export interface TierCap {
  monthly_cost_cents: number | null;
  monthly_tasks: number | null;
  daily_floor: number | null;
}

export type Tier = "free" | "solo" | "studio";

/**
 * Fine money unit. The monthly_cost meter accumulates in micro-cents
 * (cents × 10,000, integer) so that a typical sub-cent request is metered at
 * its TRUE cost instead of being floored to a whole cent per request.
 *
 * W38-S938: the old per-request `Math.ceil`-to-whole-cent minimum
 * (computeCostCents) inflated the free-tier monthly_cost meter ~20× — a ~0.04¢
 * task billed ≥1¢, so the free $1.00 (100¢) cost cap fired at ~100 requests,
 * well before the intended 200-task cap (a device hit monthly_cost_exceeded at
 * ~$0.05 of real spend). Metering in micro-cents drops that floor: the cap now
 * reflects real projected spend and the 200-task cap correctly bites first for
 * tiny tasks, while a genuinely expensive task still accrues real cost toward $1.
 * Tier caps stay AUTHORED in cents (below); they are converted to micro-cents
 * (× this constant) at compare time, and /v1/quota ceils back to cents at DISPLAY.
 */
export const MICROCENTS_PER_CENT = 10_000;

export const TIER_CAPS: Record<Tier, TierCap> = {
  free:   { monthly_cost_cents: 100, monthly_tasks: 200,  daily_floor: 30 },
  solo:   { monthly_cost_cents: 480, monthly_tasks: 2000, daily_floor: null },
  studio: { monthly_cost_cents: null, monthly_tasks: null, daily_floor: null },
};

export interface Usage {
  input_tokens: number;
  output_tokens: number;
  cached_tokens: number;
  cache_creation_input_tokens: number;
}

/**
 * Map a full model id (e.g., "claude-haiku-4-5-20251001",
 * "claude-sonnet-4-6") to a pricing row. Unrecognized ids return null —
 * callers must handle this (the messages route falls back to haiku rates
 * with an error log per the brief's safety default).
 */
export function modelFamily(modelId: string): ModelFamily | null {
  const m = modelId.toLowerCase();
  if (m.includes("haiku")) return "haiku";
  if (m.includes("sonnet")) return "sonnet";
  if (m.includes("opus")) return "opus";
  return null;
}

/**
 * Compute cost in whole cents, rounded UP. Multiplication is in
 * cents-per-1M-tokens space, then divided by 1_000_000 and ceiled.
 *
 * Rounds the *total* up once, not per-component — that matches the brief's
 * "Math.ceil to next cent" rule and avoids over-charging by stacking rounds.
 */
export function computeCostCents(family: ModelFamily, usage: Usage): number {
  const row = PRICING[family];
  const centsTimes1M =
    row.input_cents_per_1m * usage.input_tokens +
    row.output_cents_per_1m * usage.output_tokens +
    row.cached_cents_per_1m * usage.cached_tokens;
  return Math.ceil(centsTimes1M / 1_000_000);
}

/**
 * Compute the EXACT per-request cost in micro-cents (cents × 10,000, integer),
 * WITHOUT the per-request ceil-to-whole-cent minimum that computeCostCents
 * applies. This is the value the monthly_cost meter accumulates (W38-S938).
 *
 * The token-rate product is in cents-per-1M space (cents × 1,000,000); dividing
 * by 100 converts to micro-cents (× 10,000 / 1,000,000 = / 100). We `Math.ceil`
 * only to the nearest whole micro-cent — a sub-0.0001¢ rounding that preserves
 * integer-money discipline (no floats) without re-introducing a 1¢-per-request
 * floor. So a ~0.04¢ task accrues ~400 micro-cents, not 10,000.
 */
export function computeCostMicroCents(family: ModelFamily, usage: Usage): number {
  const row = PRICING[family];
  const centsTimes1M =
    row.input_cents_per_1m * usage.input_tokens +
    row.output_cents_per_1m * usage.output_tokens +
    row.cached_cents_per_1m * usage.cached_tokens;
  return Math.ceil(centsTimes1M / 100);
}

export function taskWeight(family: ModelFamily): number {
  return TASK_WEIGHTS[family];
}
