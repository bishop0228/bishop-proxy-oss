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
 * applyIncrement — carry the cap-comparison and period-rollover logic and
 * are unit-testable here without DO infrastructure.
 */

import { describe, it, expect } from "vitest";
import {
  currentPeriod,
  rollPeriod,
  emptyState,
  evaluateCheck,
  applyIncrement,
  type QuotaState,
} from "../src/durable-objects/quota-store";

function stateAt(opts: Partial<QuotaState> = {}): QuotaState {
  return {
    period_month: "2026-04",
    period_day: "2026-04-28",
    monthly_cost_cents: 0,
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
      monthly_cost_cents: 99,
      monthly_tasks: 150,
      daily_tasks: 10,
    });
    const now = new Date(Date.UTC(2026, 3, 1));
    const next = rollPeriod(s, now);
    expect(next.monthly_cost_cents).toBe(0);
    expect(next.monthly_tasks).toBe(0);
    expect(next.daily_tasks).toBe(0); // day also rolled
    expect(next.period_month).toBe("2026-04");
  });

  it("zeros only daily counter when day rolls but month doesn't", () => {
    const s = stateAt({
      period_month: "2026-04",
      period_day: "2026-04-27",
      monthly_cost_cents: 50,
      monthly_tasks: 25,
      daily_tasks: 30,
    });
    const now = new Date(Date.UTC(2026, 3, 28));
    const next = rollPeriod(s, now);
    expect(next.monthly_cost_cents).toBe(50);
    expect(next.monthly_tasks).toBe(25);
    expect(next.daily_tasks).toBe(0);
    expect(next.period_day).toBe("2026-04-28");
  });
});

describe("evaluateCheck — free tier", () => {
  it("allows when all caps would still be respected", () => {
    const s = stateAt({ monthly_cost_cents: 50, monthly_tasks: 100, daily_tasks: 5 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: true });
  });

  it("rejects when monthly_cost would be exceeded", () => {
    const s = stateAt({ monthly_cost_cents: 95, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });

  it("rejects when monthly_tasks would be exceeded (weight=3 from sonnet)", () => {
    const s = stateAt({ monthly_cost_cents: 0, monthly_tasks: 199, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 3, cost_cents_estimate: 0 });
    expect(r).toEqual({ ok: false, reason: "monthly_tasks_exceeded" });
  });

  it("rejects when daily_floor would be exceeded", () => {
    const s = stateAt({ monthly_cost_cents: 0, monthly_tasks: 0, daily_tasks: 30 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 0 });
    expect(r).toEqual({ ok: false, reason: "daily_floor_exceeded" });
  });

  it("cost-cap takes precedence over task-cap when both would fail", () => {
    const s = stateAt({ monthly_cost_cents: 100, monthly_tasks: 200, daily_tasks: 30 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 1 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });
});

describe("evaluateCheck — solo tier", () => {
  it("allows below 480¢ / 2000-task caps", () => {
    const s = stateAt({ monthly_cost_cents: 100, monthly_tasks: 500, daily_tasks: 999 });
    const r = evaluateCheck(s, { tier: "solo", weight: 3, cost_cents_estimate: 50 });
    expect(r).toEqual({ ok: true });
  });

  it("solo has no daily_floor — daily counter does not gate", () => {
    const s = stateAt({ monthly_cost_cents: 0, monthly_tasks: 0, daily_tasks: 9999 });
    const r = evaluateCheck(s, { tier: "solo", weight: 1, cost_cents_estimate: 1 });
    expect(r.ok).toBe(true);
  });

  it("rejects at solo monthly_cost cap (480¢)", () => {
    const s = stateAt({ monthly_cost_cents: 480, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "solo", weight: 1, cost_cents_estimate: 1 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });
});

describe("evaluateCheck — studio tier (D2 unmetered)", () => {
  it("always passes regardless of counters", () => {
    const s = stateAt({
      monthly_cost_cents: 999_999_999,
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
  it("adds cost and weight to all three counters", () => {
    const s = stateAt({ monthly_cost_cents: 10, monthly_tasks: 5, daily_tasks: 2 });
    const next = applyIncrement(s, { weight: 3, cost_cents: 25 });
    expect(next).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_cents: 35,
      monthly_tasks: 8,
      daily_tasks: 5,
    });
  });

  it("is a pure function — input not mutated", () => {
    const s = stateAt({ monthly_cost_cents: 10, monthly_tasks: 5, daily_tasks: 2 });
    applyIncrement(s, { weight: 3, cost_cents: 25 });
    expect(s.monthly_cost_cents).toBe(10);
    expect(s.monthly_tasks).toBe(5);
    expect(s.daily_tasks).toBe(2);
  });
});

describe("emptyState", () => {
  it("zeroes all counters and stamps current period", () => {
    const now = new Date(Date.UTC(2026, 3, 28));
    const s = emptyState(now);
    expect(s).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_cents: 0,
      monthly_tasks: 0,
      daily_tasks: 0,
    });
  });
});
