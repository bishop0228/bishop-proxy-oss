/**
 * QuotaStoreDO pure-helper tests.
 *
 * Test-infra note: this repo does not depend on
 * `@cloudflare/vitest-pool-workers`, so DO `fetch()` cannot be invoked from
 * outside the worker. Following the pattern in `test/auth-store.test.ts`,
 * the DO-routed surface (`/check` 429, `/increment` cumulative state, alarm
 * scheduling) is deferred to `test/messages.test.ts` at Step 8, where
 * `/v1/messages` exercises it end-to-end.
 *
 * The pure helpers below — currentPeriod, rollPeriod, evaluateCheck,
 * applyIncrement, migrateState — carry the cap-comparison, period-rollover and
 * micro-cent migration logic and are unit-testable here without DO infra.
 *
 * W38-S938: the monthly cost meter accumulates in MICRO-CENTS (cents × 10,000)
 * so a sub-cent request is metered at its true cost rather than floored to ≥1¢.
 * Cap table stays authored in cents (100¢ = 1,000,000 micro-cents for free).
 */

import { describe, it, expect } from "vitest";
import {
  currentPeriod,
  rollPeriod,
  emptyState,
  evaluateCheck,
  applyIncrement,
  migrateState,
  isLegacyShape,
  type QuotaState,
} from "../src/durable-objects/quota-store";

const C = 10_000; // micro-cents per cent (mirror of MICROCENTS_PER_CENT)

function stateAt(opts: Partial<QuotaState> = {}): QuotaState {
  return {
    period_month: "2026-04",
    period_day: "2026-04-28",
    monthly_cost_microcents: 0,
    monthly_tasks: 0,
    daily_tasks: 0,
    ...opts,
  };
}

describe("currentPeriod", () => {
  it("formats UTC YYYY-MM and YYYY-MM-DD with zero-padding", () => {
    const d = new Date(Date.UTC(2026, 0, 9, 23, 59, 59)); // Jan 9, 2026
    expect(currentPeriod(d)).toEqual({ month: "2026-01", day: "2026-01-09" });
  });
});

describe("rollPeriod", () => {
  it("no-op when both periods match", () => {
    const s = stateAt();
    const now = new Date(Date.UTC(2026, 3, 28));
    expect(rollPeriod(s, now)).toBe(s);
  });

  it("zeros monthly counters when month rolls", () => {
    const s = stateAt({
      period_month: "2026-03",
      period_day: "2026-03-31",
      monthly_cost_microcents: 99 * C,
      monthly_tasks: 150,
      daily_tasks: 10,
    });
    const now = new Date(Date.UTC(2026, 3, 1));
    const next = rollPeriod(s, now);
    expect(next.monthly_cost_microcents).toBe(0);
    expect(next.monthly_tasks).toBe(0);
    expect(next.daily_tasks).toBe(0); // day also rolled
    expect(next.period_month).toBe("2026-04");
  });

  it("zeros only daily counter when day rolls but month doesn't", () => {
    const s = stateAt({
      period_month: "2026-04",
      period_day: "2026-04-27",
      monthly_cost_microcents: 50 * C,
      monthly_tasks: 25,
      daily_tasks: 30,
    });
    const now = new Date(Date.UTC(2026, 3, 28));
    const next = rollPeriod(s, now);
    expect(next.monthly_cost_microcents).toBe(50 * C);
    expect(next.monthly_tasks).toBe(25);
    expect(next.daily_tasks).toBe(0);
    expect(next.period_day).toBe("2026-04-28");
  });
});

describe("evaluateCheck — free tier (cap 100¢ = 1,000,000 micro-cents)", () => {
  it("allows when all caps would still be respected", () => {
    const s = stateAt({ monthly_cost_microcents: 50 * C, monthly_tasks: 100, daily_tasks: 5 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: true });
  });

  it("rejects when monthly_cost would be exceeded", () => {
    const s = stateAt({ monthly_cost_microcents: 95 * C, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });

  it("rejects when monthly_tasks would be exceeded (weight=3 from sonnet)", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 199, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 3, cost_cents_estimate: 0 });
    expect(r).toEqual({ ok: false, reason: "monthly_tasks_exceeded" });
  });

  it("rejects when daily_floor would be exceeded", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 0, daily_tasks: 30 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 0 });
    expect(r).toEqual({ ok: false, reason: "daily_floor_exceeded" });
  });

  it("cost-cap takes precedence over task-cap when both would fail", () => {
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 200, daily_tasks: 30 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 1 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });

  // W38-S938: the metering-accuracy fix — sub-cent state below the cents-cap is
  // NOT rejected. 99.9¢ of real spend (well under 100¢) passes even though the
  // legacy per-request 1¢ floor would have inflated it past the cap long ago.
  it("sub-cent accuracy: 99.9¢ of real micro-cent spend is still under the cap", () => {
    const s = stateAt({ monthly_cost_microcents: 999_000, monthly_tasks: 10, daily_tasks: 1 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 0 });
    expect(r).toEqual({ ok: true });
  });
});

// W38-S923: a CONNECTED (byok) device pays its own provider, so the free-tier
// daily_floor must NOT gate it — only managed/FREE devices are metered.
describe("evaluateCheck — account_mode byok bypasses the daily_floor", () => {
  it("byok device at/over the daily_floor is NOT rejected", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 0, daily_tasks: 30 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 0, account_mode: "byok",
    });
    expect(r).toEqual({ ok: true });
  });

  it("managed device at the daily_floor is STILL rejected (the wall stays)", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 0, daily_tasks: 30 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 0, account_mode: "managed",
    });
    expect(r).toEqual({ ok: false, reason: "daily_floor_exceeded" });
  });

  it("omitted account_mode defaults to the metered (managed) path", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 0, daily_tasks: 30 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 0 });
    expect(r).toEqual({ ok: false, reason: "daily_floor_exceeded" });
  });

  it("byok does NOT bypass the monthly_tasks cap (only the cost meters lift)", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 200, daily_tasks: 0 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 0, account_mode: "byok",
    });
    expect(r).toEqual({ ok: false, reason: "monthly_tasks_exceeded" });
  });
});

// W38-S937: a CONNECTED (byok) device pays its own provider, so the free-tier
// monthly_cost cap must NOT gate it either (sibling of the S923 daily_floor fix).
describe("evaluateCheck — account_mode byok bypasses the monthly_cost cap", () => {
  it("byok device over the monthly_cost cap is NOT rejected", () => {
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 10, account_mode: "byok",
    });
    expect(r).toEqual({ ok: true });
  });

  it("managed device over the monthly_cost cap is STILL rejected (the wall stays)", () => {
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 10, account_mode: "managed",
    });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });

  it("omitted account_mode defaults to the metered (managed) monthly_cost path", () => {
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });
});

describe("evaluateCheck — solo tier (cap 480¢ = 4,800,000 micro-cents)", () => {
  it("allows below 480¢ / 2000-task caps", () => {
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 500, daily_tasks: 999 });
    const r = evaluateCheck(s, { tier: "solo", weight: 3, cost_cents_estimate: 50 });
    expect(r).toEqual({ ok: true });
  });

  it("solo has no daily_floor — daily counter does not gate", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 0, daily_tasks: 9999 });
    const r = evaluateCheck(s, { tier: "solo", weight: 1, cost_cents_estimate: 1 });
    expect(r.ok).toBe(true);
  });

  it("rejects at solo monthly_cost cap (480¢)", () => {
    const s = stateAt({ monthly_cost_microcents: 480 * C, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "solo", weight: 1, cost_cents_estimate: 1 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });
});

describe("evaluateCheck — studio tier (D2 unmetered)", () => {
  it("always passes regardless of counters", () => {
    const s = stateAt({
      monthly_cost_microcents: 999_999_999,
      monthly_tasks: 999_999,
      daily_tasks: 999_999,
    });
    const r = evaluateCheck(s, {
      tier: "studio",
      weight: 9999,
      cost_cents_estimate: 9999,
    });
    expect(r).toEqual({ ok: true });
  });
});

describe("applyIncrement", () => {
  it("adds cost (micro-cents) and weight to all three counters", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    const next = applyIncrement(s, { weight: 3, cost_microcents: 25 });
    expect(next).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 35,
      monthly_tasks: 8,
      daily_tasks: 5,
    });
  });

  it("is a pure function — input not mutated", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    applyIncrement(s, { weight: 3, cost_microcents: 25 });
    expect(s.monthly_cost_microcents).toBe(10);
    expect(s.monthly_tasks).toBe(5);
    expect(s.daily_tasks).toBe(2);
  });

  // W38-S937: a byok device's inference cost must not touch the free-tier cost
  // meter; the task counters (abuse bound) still advance.
  it("byok increment does NOT advance monthly_cost_microcents (task counters still move)", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    const next = applyIncrement(s, { weight: 3, cost_microcents: 25, account_mode: "byok" });
    expect(next).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 10,
      monthly_tasks: 8,
      daily_tasks: 5,
    });
  });

  it("managed increment still advances monthly_cost_microcents (unchanged)", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    const next = applyIncrement(s, { weight: 3, cost_microcents: 25, account_mode: "managed" });
    expect(next.monthly_cost_microcents).toBe(35);
  });
});

// W38-S938: the core scenario the fix protects — 100 tiny (~0.04¢ = 400 µ¢)
// tasks stay WELL under the $1 (100¢ = 1,000,000 µ¢) cost cap. The 200-task cap
// governs first, as intended. Under the old per-request 1¢ floor, the same 100
// tasks billed 100¢ and the cost cap fired at task ~100.
describe("W38-S938 — 100 tiny tasks stay under the $1 cost cap", () => {
  it("accumulates ~40,000 micro-cents (≈4¢), not the 1,000,000 µ¢ cap", () => {
    let s = stateAt();
    for (let i = 0; i < 100; i++) {
      s = applyIncrement(s, { weight: 1, cost_microcents: 400 });
    }
    expect(s.monthly_cost_microcents).toBe(40_000); // 4¢ of real spend
    expect(s.monthly_tasks).toBe(100);
    // The COST cap is nowhere near firing — isolate it from the daily_floor
    // (which gates per-day volume) by checking with a fresh daily counter, as if
    // the 100 tiny tasks were spread across the month. Under the OLD per-request
    // 1¢ floor this same state would read 100¢ and the cost cap would have fired.
    expect(
      evaluateCheck({ ...s, daily_tasks: 0 }, { tier: "free", weight: 1, cost_cents_estimate: 0 }),
    ).toEqual({ ok: true });
  });

  it("the 200-task cap (not the cost cap) governs tiny-task volume", () => {
    let s = stateAt();
    for (let i = 0; i < 200; i++) {
      s = applyIncrement(s, { weight: 1, cost_microcents: 400 });
    }
    // 200 tasks × 400 µ¢ = 80,000 µ¢ = 8¢ — nowhere near the 100¢ cost cap.
    expect(s.monthly_cost_microcents).toBe(80_000);
    // the 201st task trips the TASK cap, not the cost cap.
    expect(evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 0 })).toEqual({
      ok: false,
      reason: "monthly_tasks_exceeded",
    });
  });

  it("a genuinely expensive task still accrues real cost toward the cap", () => {
    // one opus deep task ≈ 9000¢ raw rates / typical usage; here meter near cap.
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 1, daily_tasks: 1 });
    expect(evaluateCheck(s, { tier: "free", weight: 5, cost_cents_estimate: 1 })).toEqual({
      ok: false,
      reason: "monthly_cost_exceeded",
    });
  });
});

describe("emptyState", () => {
  it("zeroes all counters and stamps current period", () => {
    const now = new Date(Date.UTC(2026, 3, 28));
    const s = emptyState(now);
    expect(s).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 0,
      monthly_tasks: 0,
      daily_tasks: 0,
    });
  });
});

// W38-S938: migration safety — old-shape DO records (monthly_cost_cents) must
// convert ×10,000 on read and never crash. Soft monthly meter also self-heals
// on the next rollover, but read-time convert keeps mid-month accuracy.
describe("migrateState — legacy cents → micro-cents", () => {
  it("converts a legacy monthly_cost_cents record ×10,000", () => {
    const legacy = {
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_cents: 50,
      monthly_tasks: 7,
      daily_tasks: 3,
    };
    expect(migrateState(legacy)).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 500_000,
      monthly_tasks: 7,
      daily_tasks: 3,
    });
  });

  it("passes a current micro-cent record through unchanged", () => {
    const current = {
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 123_456,
      monthly_tasks: 7,
      daily_tasks: 3,
    };
    expect(migrateState(current)).toEqual(current);
  });

  it("falls back to emptyState for null/garbage (never crashes)", () => {
    const now = new Date(Date.UTC(2026, 3, 28));
    expect(migrateState(null, now)).toEqual(emptyState(now));
    expect(migrateState(undefined, now)).toEqual(emptyState(now));
    expect(migrateState(42, now)).toEqual(emptyState(now));
    expect(migrateState("nope", now)).toEqual(emptyState(now));
  });

  it("tolerates a partial legacy record (missing fields default to 0/current period)", () => {
    const now = new Date(Date.UTC(2026, 3, 28));
    const partial = { monthly_cost_cents: 12 };
    expect(migrateState(partial, now)).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 120_000,
      monthly_tasks: 0,
      daily_tasks: 0,
    });
  });
});

describe("isLegacyShape", () => {
  it("true for a cents-only record, false for a micro-cent record", () => {
    expect(isLegacyShape({ monthly_cost_cents: 5 })).toBe(true);
    expect(isLegacyShape({ monthly_cost_microcents: 5 })).toBe(false);
  });

  it("false for null/non-object (emptyState handles those)", () => {
    expect(isLegacyShape(null)).toBe(false);
    expect(isLegacyShape(undefined)).toBe(false);
    expect(isLegacyShape(7)).toBe(false);
  });
});
