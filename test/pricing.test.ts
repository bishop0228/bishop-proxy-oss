/**
 * pricing.ts unit tests, including Opus pricing extension.
 *
 * Covers:
 *   1) haiku cost — input-only baseline, Math.ceil rounding to next cent
 *   2) sonnet cost — input + output mix
 *   3) opus cost — 1M input + 1M output = 1500+7500 = 9000¢
 *   4) cached-token discount path
 *   5) zero-token request rounds to 0¢ (degenerate; ceil(0)=0)
 *   6) sub-cent residue rounds UP to 1¢ (the "small request" guarantee)
 *   7) modelFamily mapping for full claude-* ids and unknown fallback
 *   8) TIER_CAPS shape — free metered, solo metered (provisional), studio unmetered
 *      and TASK_WEIGHTS — haiku=1, sonnet=3, opus=5
 */

import { describe, it, expect } from "vitest";
import {
  PRICING,
  TIER_CAPS,
  TASK_WEIGHTS,
  computeCostCents,
  modelFamily,
  taskWeight,
} from "../src/lib/pricing";

describe("PRICING table", () => {
  it("haiku rates: 25/125/2.5 cents per 1M tokens", () => {
    expect(PRICING.haiku).toEqual({
      input_cents_per_1m: 25,
      output_cents_per_1m: 125,
      cached_cents_per_1m: 2.5,
    });
  });

  it("sonnet rates: 300/1500/30 cents per 1M tokens", () => {
    expect(PRICING.sonnet).toEqual({
      input_cents_per_1m: 300,
      output_cents_per_1m: 1500,
      cached_cents_per_1m: 30,
    });
  });

  it("opus rates: 1500/7500/150 cents per 1M tokens (placeholder, finalization gated on staging measurement)", () => {
    expect(PRICING.opus).toEqual({
      input_cents_per_1m: 1500,
      output_cents_per_1m: 7500,
      cached_cents_per_1m: 150,
    });
  });
});

describe("computeCostCents", () => {
  it("haiku — 1M input tokens = 25¢ exactly (no rounding bump)", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 1_000_000,
      output_tokens: 0,
      cached_tokens: 0,
    });
    expect(c).toBe(25);
  });

  it("sonnet — 1M input + 1M output = 300+1500 = 1800¢", () => {
    const c = computeCostCents("sonnet", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
      cached_tokens: 0,
    });
    expect(c).toBe(1800);
  });

  it("haiku — cached tokens priced at 2.5¢/1M (1M cached = 3¢ after ceil from 2.5)", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 1_000_000,
    });
    expect(c).toBe(3);
  });

  it("zero usage rounds to 0¢", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 0,
    });
    expect(c).toBe(0);
  });

  it("sub-cent residue rounds UP to 1¢ — small haiku request (1 input token)", () => {
    const c = computeCostCents("haiku", {
      input_tokens: 1,
      output_tokens: 0,
      cached_tokens: 0,
    });
    expect(c).toBe(1);
  });

  it("rounds *total* up once, not per-component (haiku 100k input + 100k output)", () => {
    // 25 * 100_000 / 1e6 = 2.5¢
    // 125 * 100_000 / 1e6 = 12.5¢
    // total raw = 15¢ exactly — no rounding bump expected
    const c = computeCostCents("haiku", {
      input_tokens: 100_000,
      output_tokens: 100_000,
      cached_tokens: 0,
    });
    expect(c).toBe(15);
  });

  it("opus — 1M input + 1M output = 1500+7500 = 9000¢", () => {
    const c = computeCostCents("opus", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
      cached_tokens: 0,
    });
    expect(c).toBe(9000);
  });

  it("opus — cached tokens at 150¢/1M (1M cached = 150¢)", () => {
    const c = computeCostCents("opus", {
      input_tokens: 0,
      output_tokens: 0,
      cached_tokens: 1_000_000,
    });
    expect(c).toBe(150);
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

describe("TIER_CAPS + TASK_WEIGHTS", () => {
  it("free is metered: 100¢, 200 tasks, 30 daily floor", () => {
    expect(TIER_CAPS.free).toEqual({
      monthly_cost_cents: 100,
      monthly_tasks: 200,
      daily_floor: 30,
    });
  });

  it("solo is metered (PROVISIONAL 480¢): 480¢, 2000 tasks, no daily floor", () => {
    expect(TIER_CAPS.solo).toEqual({
      monthly_cost_cents: 480,
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

  it("task weights: haiku=1, sonnet=3, opus=5", () => {
    expect(TASK_WEIGHTS).toEqual({ haiku: 1, sonnet: 3, opus: 5 });
    expect(taskWeight("haiku")).toBe(1);
    expect(taskWeight("sonnet")).toBe(3);
    expect(taskWeight("opus")).toBe(5);
  });
});
