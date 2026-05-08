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
  const microCents =
    row.input_cents_per_1m * usage.input_tokens +
    row.output_cents_per_1m * usage.output_tokens +
    row.cached_cents_per_1m * usage.cached_tokens;
  return Math.ceil(microCents / 1_000_000);
}

export function taskWeight(family: ModelFamily): number {
  return TASK_WEIGHTS[family];
}
