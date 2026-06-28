/**
 * Pricing + tier caps.
 *
 * Cost is computed per-request in cents, rounded UP to the next whole cent
 * (Math.ceil). The per-1M-token rates below are the LIVE Anthropic model rates
 * (Haiku 4.5 / Sonnet 4.6 / Opus 4.8), verified against the 2026-06-28
 * measured-cost probe run on the founder's key:
 *   haiku  — $1.00 input / $5.00 output / $0.10 cached  per 1M tokens
 *   sonnet — $3.00 input / $15.00 output / $0.30 cached per 1M tokens
 *   opus   — $5.00 input / $25.00 output / $0.50 cached per 1M tokens
 *
 * Internal storage is cents-per-1M to keep one rounding boundary at the end.
 *
 * Task counting (cost-derived, founder-ratified 2026-06-28): there is NO fixed
 * per-model weight. One task unit = the cost of an average Haiku task
 * (TASK_UNIT_MICROCENTS, below). Every metered call counts as
 * tasksForCostMicroCents(its REAL cost) = round(cost ÷ unit), minimum 1 — so an
 * average Haiku call ≈ 1, Sonnet ≈ 4, Opus ≈ 8, but a short answer counts less
 * and a giant-file call counts more. The authoritative count is the exact
 * cost-derived value at /increment; nominalTaskWeight() is only the pre-call
 * /check estimate (real cost isn't known until the response returns).
 *
 * Tier caps (G12 / D2):
 *   free   — 60¢ monthly cost, 200 monthly tasks, 30/day ceiling (anti-grief)
 *   solo   — 600¢ ($6) monthly cost, 2000 monthly tasks, no daily ceiling
 *   studio — all null (unmetered at P2.1; D2 defers studio row entirely until P2.2)
 *
 * Both metered tiers run the cost-derived task count AND the $ cost cap together;
 * whichever is reached first ends the month. For normal tasks the task count
 * leads (the unit normalizes per-task cost); the $ cap only fires first on an
 * abnormally expensive call. BYOK devices pay their own provider and bypass all.
 *
 * NOTE on caps: free $0.60/mo, solo $6/mo (founder-set 2026-06-28). Solo is
 * $12/mo, so the $6 cap guarantees ≥50% margin. Authoritative tier caps —
 * mirror docs/PRICING.md.
 */

export type ModelFamily = "haiku" | "sonnet" | "opus";

export interface PricingRow {
  input_cents_per_1m: number;
  output_cents_per_1m: number;
  cached_cents_per_1m: number;
}

export const PRICING: Record<ModelFamily, PricingRow> = {
  haiku: {
    input_cents_per_1m: 100,
    output_cents_per_1m: 500,
    cached_cents_per_1m: 10,
  },
  sonnet: {
    input_cents_per_1m: 300,
    output_cents_per_1m: 1500,
    cached_cents_per_1m: 30,
  },
  opus: {
    input_cents_per_1m: 500,
    output_cents_per_1m: 2500,
    cached_cents_per_1m: 50,
  },
};

/**
 * Cost-derived task counting (founder-ratified 2026-06-28). One task unit = the
 * measured cost of an average Haiku task. Every metered call counts as
 * round(its REAL cost ÷ unit), minimum 1 — the ONLY input is the call's actual
 * dollar cost; there is no fixed per-model weight. 2800 micro-cents = $0.0028 =
 * one average Haiku task (1002 in + 359 out at the live $1/$5 rates), from the
 * 2026-06-28 BYOK-key probe.
 */
export const TASK_UNIT_MICROCENTS = 2800;

/**
 * Average measured cost (micro-cents) of one task per family — Haiku $0.0028,
 * Sonnet $0.0098, Opus $0.0236 (same 2026-06-28 probe). Used ONLY for the
 * pre-call /check estimate via nominalTaskWeight(); the authoritative count is
 * the exact cost-derived tasksForCostMicroCents(real cost) at /increment.
 */
const AVG_TASK_MICROCENTS: Record<ModelFamily, number> = {
  haiku: 2800,
  sonnet: 9800,
  opus: 23600,
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
  free:   { monthly_cost_cents: 60,  monthly_tasks: 200,  daily_floor: 30 },
  solo:   { monthly_cost_cents: 600, monthly_tasks: 2000, daily_floor: null },
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

/**
 * Authoritative task count for a call's EXACT cost: round(cost ÷ unit), min 1.
 * Used at /increment, where the real per-request cost is known. This is the
 * only thing that decrements a user's 200 / 2,000 allowance.
 */
export function tasksForCostMicroCents(microcents: number): number {
  return Math.max(1, Math.round(microcents / TASK_UNIT_MICROCENTS));
}

/**
 * Pre-call /check estimate: the task count an average call of this family is
 * expected to consume (tasksForCostMicroCents of the family's average cost,
 * ≈ Haiku 1 / Sonnet 4 / Opus 8). NOT a billing weight — the real count is
 * computed from the actual cost at /increment once the response returns.
 */
export function nominalTaskWeight(family: ModelFamily): number {
  return tasksForCostMicroCents(AVG_TASK_MICROCENTS[family]);
}
