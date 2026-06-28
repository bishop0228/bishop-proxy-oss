/**
 * pricing.ts unit tests.
 *
 * Covers:
 *   1) haiku/sonnet/opus per-1M rates — the LIVE model rates (Haiku 4.5 $1/$5,
 *      Sonnet 4.6 $3/$15, Opus 4.8 $5/$25), corrected 2026-06-28 from the old
 *      Haiku-3 / Opus-3 placeholders that under/over-counted the cost meter.
 *   2) computeCostCents / computeCostMicroCents math at the new rates.
 *   3) cached-token discount path (cache-read = 0.1× input).
 *   4) modelFamily mapping for full claude-* ids and unknown fallback.
 *   5) TIER_CAPS shape — free 60¢, solo 600¢ ($6), studio unmetered.
 *   6) Cost-derived task counting (founder-ratified 2026-06-28): no fixed
 *      per-model weight — tasksForCostMicroCents(cost) = round(cost ÷ unit), min 1;
 *      nominalTaskWeight is the per-family pre-call /check estimate (≈ 1/4/8).
 */

import { describe, it, expect } from "vitest";
import {
  PRICING,
  TIER_CAPS,
  TASK_UNIT_MICROCENTS,
  MICROCENTS_PER_CENT,
  computeCostCents,
  computeCostMicroCents,
  modelFamily,
  tasksForCostMicroCents,
  nominalTaskWeight,
} from "../src/lib/pricing";

describe("PRICING table", () => {
  it("haiku rates: 100/500/10 cents per 1M tokens (live Haiku 4.5 $1/$5)", () => {
    expect(PRICING.haiku).toEqual({
      input_cents_per_1m: 100,
      output_cents_per_1m: 500,
      cached_cents_per_1m: 10,
    });
  });

  it("sonnet rates: 300/1500/30 cents per 1M tokens (Sonnet 4.6 $3/$15)", () => {
    expect(PRICING.sonnet).toEqual({
      input_cents_per_1m: 300,
      output_cents_per_1m: 1500,
      cached_cents_per_1m: 30,
    });
  });

  it("opus rates: 500/2500/50 cents per 1M tokens (live Opus 4.8 $5/$25)", () => {
    expect(PRICING.opus).toEqual({
      input_cents_per_1m: 500,
      output_cents_per_1m: 2500,
      cached_cents_per_1m: 50,
    });
  });
});

describe("computeCostCents", () => {
  it("haiku — 1M input tokens = 100¢ exactly (no rounding bump)", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 1_000_000,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(100);
  });

  it("sonnet — 1M input + 1M output = 300+1500 = 1800¢", () => {
    const c = computeCostCents("sonnet", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(1800);
  });

  it("haiku — cached tokens priced at 10¢/1M (1M cached = 10¢)", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 1_000_000,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(10);
  });

  it("zero usage rounds to 0¢", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(0);
  });

  it("sub-cent residue rounds UP to 1¢ — small haiku request (1 input token)", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 1,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(1);
  });

  it("rounds *total* up once, not per-component (haiku 100k input + 100k output)", () => {
    // 100 * 100_000 / 1e6 = 10¢
    // 500 * 100_000 / 1e6 = 50¢
    // total raw = 60¢ exactly — no rounding bump expected
    const c = computeCostCents("haiku", {
      input_tokens: 100_000,
      output_tokens: 100_000,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(60);
  });

  it("opus — 1M input + 1M output = 500+2500 = 3000¢", () => {
    const c = computeCostCents("opus", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(3000);
  });

  it("opus — cached tokens at 50¢/1M (1M cached = 50¢)", () => {
    const c = computeCostCents("opus", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 1_000_000,
      cache_creation_input_tokens: 0,
    });
    expect(c).toBe(50);
  });
});

// W38-S938: the monthly cost meter accumulates in micro-cents (cents × 10,000)
// using the EXACT per-request cost — NO per-request ceil-to-1¢ minimum. This is
// what fixes the ~20× free-tier over-count that fired the cost cap at pennies.
describe("computeCostMicroCents (W38-S938 — exact, no 1¢-per-request floor)", () => {
  it("MICROCENTS_PER_CENT is 10,000", () => {
    expect(MICROCENTS_PER_CENT).toBe(10_000);
  });

  it("haiku — 1M input tokens = 100¢ = 1,000,000 micro-cents", () => {
    const m = computeCostMicroCents("haiku", {
      input_tokens: 1_000_000,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(m).toBe(100 * MICROCENTS_PER_CENT);
  });

  it("a ~0.16¢ task accrues 1600 micro-cents (NOT the 10,000 the 1¢ floor billed)", () => {
    // haiku 1600 input tokens: 100 cents/1M × 1600 = 160,000 (cents×1M) → 1600 µ¢.
    const m = computeCostMicroCents("haiku", {
      input_tokens: 1600,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(m).toBe(1600);
    // the legacy whole-cent path would floor the SAME task to 1¢ = 10,000 µ¢.
    expect(computeCostCents("haiku", {
      input_tokens: 1600, output_tokens: 0, cached_tokens: 0, cache_creation_input_tokens: 0,
    }) * MICROCENTS_PER_CENT).toBe(10_000);
  });

  it("a single-token request is NOT floored to 1¢ — it is ~4 micro-cents", () => {
    const m = computeCostMicroCents("haiku", {
      input_tokens: 1,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    // 100 × 1 = 100 (cents×1M) → ceil(100/100) = 1 µ¢. Far below the old 10,000 floor.
    expect(m).toBe(1);
  });

  it("zero usage = 0 micro-cents", () => {
    const m = computeCostMicroCents("haiku", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(m).toBe(0);
  });

  it("opus — 1M input + 1M output = 3000¢ = 30,000,000 micro-cents", () => {
    const m = computeCostMicroCents("opus", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
      cached_tokens: 0,
      cache_creation_input_tokens: 0,
    });
    expect(m).toBe(3000 * MICROCENTS_PER_CENT);
  });

  it("returns an integer (no float money)", () => {
    const m = computeCostMicroCents("sonnet", {
      input_tokens: 7,
      output_tokens: 13,
      cached_tokens: 3,
      cache_creation_input_tokens: 0,
    });
    expect(Number.isInteger(m)).toBe(true);
  });
});

describe("modelFamily", () => {
  it("maps full claude-* model ids to families", () => {
    expect(modelFamily("claude-haiku-4-5-20251001")).toBe("haiku");
    expect(modelFamily("claude-sonnet-4-6")).toBe("sonnet");
    expect(modelFamily("claude-opus-4-6")).toBe("opus");
    expect(modelFamily("claude-opus-4-7")).toBe("opus");
    expect(modelFamily("gpt-4o")).toBe(null);
  });

  it("is case-insensitive", () => {
    expect(modelFamily("Claude-HAIKU-4-5")).toBe("haiku");
  });
});

describe("TIER_CAPS", () => {
  it("free is metered: 60¢, 200 tasks, 30/day ceiling", () => {
    expect(TIER_CAPS.free).toEqual({
      monthly_cost_cents: 60,
      monthly_tasks: 200,
      daily_floor: 30,
    });
  });

  it("solo is metered: 600¢ ($6), 2000 tasks, no daily ceiling", () => {
    expect(TIER_CAPS.solo).toEqual({
      monthly_cost_cents: 600,
      monthly_tasks: 2000,
      daily_floor: null,
    });
  });

  it("studio is unmetered at P2.1 — all caps null per D2", () => {
    expect(TIER_CAPS.studio).toEqual({
      monthly_cost_cents: null,
      monthly_tasks: null,
      daily_floor: null,
    });
  });
});

describe("cost-derived task counting (founder-ratified 2026-06-28)", () => {
  it("one task unit = an average Haiku task = 2800 micro-cents ($0.0028)", () => {
    expect(TASK_UNIT_MICROCENTS).toBe(2800);
  });

  it("tasksForCostMicroCents = round(cost ÷ unit), minimum 1", () => {
    // an average Haiku task ≈ 1 unit
    expect(tasksForCostMicroCents(2800)).toBe(1);
    // average Sonnet ($0.0098 = 9800 µ¢) → 3.5 → rounds to 4
    expect(tasksForCostMicroCents(9800)).toBe(4);
    // average Opus ($0.0236 = 23600 µ¢) → 8.43 → rounds to 8
    expect(tasksForCostMicroCents(23600)).toBe(8);
  });

  it("floors at 1 — a sub-Haiku (or zero) cost still counts as one task", () => {
    expect(tasksForCostMicroCents(0)).toBe(1);
    expect(tasksForCostMicroCents(100)).toBe(1); // 0.036 → max(1, 0)
    expect(tasksForCostMicroCents(1400)).toBe(1); // 0.5 → round 1
  });

  it("a giant-file call counts MORE — cost is the only input", () => {
    // a $0.05 task (50,000 µ¢) → round(17.86) = 18 tasks
    expect(tasksForCostMicroCents(50_000)).toBe(18);
  });

  it("nominalTaskWeight is the per-family pre-call /check estimate (≈ 1/4/8)", () => {
    expect(nominalTaskWeight("haiku")).toBe(1);
    expect(nominalTaskWeight("sonnet")).toBe(4);
    expect(nominalTaskWeight("opus")).toBe(8);
  });
});
