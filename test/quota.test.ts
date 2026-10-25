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
 * W38-S1165's two upload routes are driven through QuotaStoreDO.fetch over an
 * in-memory storage at the end of this file.
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
  evaluateUpload,
  reserveUpload,
  releaseUpload,
  QuotaStoreDO,
  type QuotaState,
} from "../src/durable-objects/quota-store";
import { UPLOAD_CAPS } from "../src/lib/pricing";

const C = 10_000; // micro-cents per cent (mirror of MICROCENTS_PER_CENT)

function stateAt(opts: Partial<QuotaState> = {}): QuotaState {
  return {
    period_month: "2026-04",
    period_day: "2026-04-28",
    monthly_cost_microcents: 0,
    monthly_tasks: 0,
    daily_tasks: 0,
    monthly_uploads: 0,
    monthly_upload_bytes: 0,
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
      monthly_uploads: 4,
      monthly_upload_bytes: 90,
    });
    const now = new Date(Date.UTC(2026, 3, 1));
    const next = rollPeriod(s, now);
    expect(next.monthly_cost_microcents).toBe(0);
    expect(next.monthly_tasks).toBe(0);
    expect(next.daily_tasks).toBe(0); // day also rolled
    expect(next.monthly_uploads).toBe(0); // W38-S1165: the upload limit is monthly too
    expect(next.monthly_upload_bytes).toBe(0);
    expect(next.period_month).toBe("2026-04");
  });

  it("zeros only daily counter when day rolls but month doesn't", () => {
    const s = stateAt({
      period_month: "2026-04",
      period_day: "2026-04-27",
      monthly_cost_microcents: 50 * C,
      monthly_tasks: 25,
      daily_tasks: 30,
      monthly_uploads: 4,
      monthly_upload_bytes: 90,
    });
    const now = new Date(Date.UTC(2026, 3, 28));
    const next = rollPeriod(s, now);
    expect(next.monthly_cost_microcents).toBe(50 * C);
    expect(next.monthly_tasks).toBe(25);
    expect(next.daily_tasks).toBe(0);
    expect(next.monthly_uploads).toBe(4);
    expect(next.monthly_upload_bytes).toBe(90);
    expect(next.period_day).toBe("2026-04-28");
  });
});

describe("evaluateCheck — free tier (cap 60¢ = 600,000 micro-cents)", () => {
  it("allows when all caps would still be respected", () => {
    const s = stateAt({ monthly_cost_microcents: 30 * C, monthly_tasks: 100, daily_tasks: 5 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: true });
  });

  it("rejects when monthly_cost would be exceeded", () => {
    const s = stateAt({ monthly_cost_microcents: 55 * C, monthly_tasks: 0, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 10 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });

  it("rejects when monthly_tasks would be exceeded (a multi-unit call, weight 3)", () => {
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
    const s = stateAt({ monthly_cost_microcents: 60 * C, monthly_tasks: 200, daily_tasks: 30 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 1 });
    expect(r).toEqual({ ok: false, reason: "monthly_cost_exceeded" });
  });

  // W38-S938: the metering-accuracy fix — sub-cent state below the cents-cap is
  // NOT rejected. 59.9¢ of real spend (just under the 60¢ cap) passes even though
  // the legacy per-request 1¢ floor would have inflated it past the cap long ago.
  it("sub-cent accuracy: 59.9¢ of real micro-cent spend is still under the cap", () => {
    const s = stateAt({ monthly_cost_microcents: 599_000, monthly_tasks: 10, daily_tasks: 1 });
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

  it("managed device at the monthly_tasks cap is STILL rejected (the wall stays)", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 200, daily_tasks: 0 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 0, account_mode: "managed",
    });
    expect(r).toEqual({ ok: false, reason: "monthly_tasks_exceeded" });
  });
});

// W38-S939: a CONNECTED (byok) device pays its own provider, so the free-tier
// monthly_tasks cap must NOT gate it either — the THIRD free-tier quota dimension
// (sibling of the S923 daily_floor + S937 monthly_cost fixes). This was the gap #21:
// a byok run 429'd on monthly_tasks_exceeded because the check had no byok guard.
describe("evaluateCheck — account_mode byok bypasses the monthly_tasks cap", () => {
  it("byok device over the monthly_tasks cap is NOT rejected", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 200, daily_tasks: 0 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 0, account_mode: "byok",
    });
    expect(r).toEqual({ ok: true });
  });

  it("managed device over the monthly_tasks cap is STILL rejected (the wall stays)", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 200, daily_tasks: 0 });
    const r = evaluateCheck(s, {
      tier: "free", weight: 1, cost_cents_estimate: 0, account_mode: "managed",
    });
    expect(r).toEqual({ ok: false, reason: "monthly_tasks_exceeded" });
  });

  it("omitted account_mode defaults to the metered (managed) monthly_tasks path", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 200, daily_tasks: 0 });
    const r = evaluateCheck(s, { tier: "free", weight: 1, cost_cents_estimate: 0 });
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

describe("evaluateCheck — solo tier (cap 600¢ = 6,000,000 micro-cents)", () => {
  it("allows below 600¢ / 2000-task caps", () => {
    const s = stateAt({ monthly_cost_microcents: 100 * C, monthly_tasks: 500, daily_tasks: 999 });
    const r = evaluateCheck(s, { tier: "solo", weight: 3, cost_cents_estimate: 50 });
    expect(r).toEqual({ ok: true });
  });

  it("solo has no daily_floor — daily counter does not gate", () => {
    const s = stateAt({ monthly_cost_microcents: 0, monthly_tasks: 0, daily_tasks: 9999 });
    const r = evaluateCheck(s, { tier: "solo", weight: 1, cost_cents_estimate: 1 });
    expect(r.ok).toBe(true);
  });

  it("rejects at solo monthly_cost cap (600¢)", () => {
    const s = stateAt({ monthly_cost_microcents: 600 * C, monthly_tasks: 0, daily_tasks: 0 });
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
      monthly_uploads: 0,
      monthly_upload_bytes: 0,
    });
  });

  it("is a pure function — input not mutated", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    applyIncrement(s, { weight: 3, cost_microcents: 25 });
    expect(s.monthly_cost_microcents).toBe(10);
    expect(s.monthly_tasks).toBe(5);
    expect(s.daily_tasks).toBe(2);
  });

  // W38-S939: a byok device touches NO free-tier counter — not the cost meter
  // (S937) and not the task counters (S939, the comprehensive sweep). A byok
  // increment is a complete no-op on every quota dimension.
  it("byok increment advances NO free-tier counter (cost + both task counters frozen)", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    const next = applyIncrement(s, { weight: 3, cost_microcents: 25, account_mode: "byok" });
    expect(next).toEqual({
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 10,
      monthly_tasks: 5,
      daily_tasks: 2,
      monthly_uploads: 0,
      monthly_upload_bytes: 0,
    });
  });

  it("managed increment still advances all three counters (unchanged, fail-closed)", () => {
    const s = stateAt({ monthly_cost_microcents: 10, monthly_tasks: 5, daily_tasks: 2 });
    const next = applyIncrement(s, { weight: 3, cost_microcents: 25, account_mode: "managed" });
    expect(next.monthly_cost_microcents).toBe(35);
    expect(next.monthly_tasks).toBe(8);
    expect(next.daily_tasks).toBe(5);
  });
});

// W38-S939: THE INVARIANT — end the whack-a-mole. A CONNECTED (byok) device pays
// its own provider, so it must clear EVERY free-tier quota gate on BOTH the check
// and the increment, no matter how many counters are past their caps. We fixed the
// gates piecemeal (S923 daily_floor, S937 monthly_cost, S939 monthly_tasks); this
// invariant proves the principle holds wholesale and forces a decision if a new
// cap dimension is ever added. Managed/FREE stays fail-closed + metered on all.
describe("W38-S939 INVARIANT — byok clears EVERY free-tier gate (no whack-a-mole)", () => {
  // A device whose daily_tasks, monthly_tasks AND monthly_cost are ALL past every
  // free-tier cap (daily_floor 30, monthly_tasks 200, monthly_cost 100¢).
  const overEveryCap = stateAt({
    monthly_cost_microcents: 1_000 * C, // 10× the 100¢ cap
    monthly_tasks: 10_000,              // 50× the 200 cap
    daily_tasks: 10_000,                // 333× the 30 daily_floor
  });

  it("byok over EVERY cap returns ok:true on the check (no *_exceeded on any dimension)", () => {
    const r = evaluateCheck(overEveryCap, {
      tier: "free", weight: 9999, cost_cents_estimate: 9999, account_mode: "byok",
    });
    expect(r).toEqual({ ok: true });
  });

  it("byok over EVERY cap advances NO free-tier counter on the increment", () => {
    const next = applyIncrement(overEveryCap, {
      weight: 9999, cost_microcents: 9_999_999, account_mode: "byok",
    });
    expect(next.monthly_cost_microcents).toBe(overEveryCap.monthly_cost_microcents);
    expect(next.monthly_tasks).toBe(overEveryCap.monthly_tasks);
    expect(next.daily_tasks).toBe(overEveryCap.daily_tasks);
  });

  it("managed over EVERY cap is STILL fail-closed (rejected) and STILL metered", () => {
    const r = evaluateCheck(overEveryCap, {
      tier: "free", weight: 1, cost_cents_estimate: 1, account_mode: "managed",
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/_exceeded$/);
    const next = applyIncrement(overEveryCap, {
      weight: 3, cost_microcents: 25, account_mode: "managed",
    });
    expect(next.monthly_cost_microcents).toBe(overEveryCap.monthly_cost_microcents + 25);
    expect(next.monthly_tasks).toBe(overEveryCap.monthly_tasks + 3);
    expect(next.daily_tasks).toBe(overEveryCap.daily_tasks + 3);
  });

  it("omitted account_mode (default managed) over EVERY cap is STILL fail-closed", () => {
    const r = evaluateCheck(overEveryCap, { tier: "free", weight: 1, cost_cents_estimate: 1 });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/_exceeded$/);
  });

  // W38-S1165's upload limit is the cap dimension added since: it gates uploads alone. A byok upload is never counted
  // (the Files route reserves only an upload served as managed: test/provider-files.test.ts), and a model call neither
  // reads nor moves the upload counters, in either mode.
  it("W38-S1165: the upload counters gate no model call and no increment moves them", () => {
    const uploadsFull = stateAt({ monthly_uploads: 10_000, monthly_upload_bytes: 10_000 * 1024 * 1024 });
    expect(evaluateCheck(uploadsFull, { tier: "free", weight: 1, cost_cents_estimate: 0 })).toEqual({ ok: true });
    for (const account_mode of ["managed", "byok"] as const) {
      const next = applyIncrement(uploadsFull, { weight: 3, cost_microcents: 25, account_mode });
      expect(next.monthly_uploads).toBe(uploadsFull.monthly_uploads);
      expect(next.monthly_upload_bytes).toBe(uploadsFull.monthly_upload_bytes);
    }
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
      monthly_uploads: 0,
      monthly_upload_bytes: 0,
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
      monthly_uploads: 0,
      monthly_upload_bytes: 0,
    });
  });

  it("passes a current micro-cent record through unchanged", () => {
    const current = {
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 123_456,
      monthly_tasks: 7,
      daily_tasks: 3,
      monthly_uploads: 2,
      monthly_upload_bytes: 40 * 1024 * 1024,
    };
    expect(migrateState(current)).toEqual(current);
  });

  it("W38-S1165: a record written before the upload limit reads no uploads", () => {
    const before = {
      period_month: "2026-04",
      period_day: "2026-04-28",
      monthly_cost_microcents: 123_456,
      monthly_tasks: 7,
      daily_tasks: 3,
    };
    expect(migrateState(before)).toEqual({ ...before, monthly_uploads: 0, monthly_upload_bytes: 0 });
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
      monthly_uploads: 0,
      monthly_upload_bytes: 0,
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

// W38-S1165 (founder decision 2026-10-25, (b)): a managed device's uploads to the Anthropic Files API are limited per
// month, by number and by total size. The values are read from UPLOAD_CAPS, so a change of the numbers moves no test
// here.
describe("W38-S1165 — the monthly upload limit", () => {
  const MIB = 1024 * 1024;
  const TIERS = ["free", "solo", "studio"] as const;

  it("allows the last upload the count limit names and refuses the next, on every tier", () => {
    for (const tier of TIERS) {
      const cap = UPLOAD_CAPS[tier];
      const before = stateAt({ monthly_uploads: cap.monthly_uploads - 1 });
      expect(evaluateUpload(before, { tier, bytes: MIB })).toEqual({ ok: true });
      const at = stateAt({ monthly_uploads: cap.monthly_uploads });
      expect(evaluateUpload(at, { tier, bytes: MIB })).toEqual({ ok: false, reason: "monthly_uploads_exceeded" });
    }
  });

  it("allows an upload that fills the size limit exactly and refuses one byte more", () => {
    for (const tier of TIERS) {
      const cap = UPLOAD_CAPS[tier];
      const s = stateAt({ monthly_upload_bytes: cap.monthly_upload_bytes - 10 * MIB });
      expect(evaluateUpload(s, { tier, bytes: 10 * MIB })).toEqual({ ok: true });
      expect(evaluateUpload(s, { tier, bytes: 10 * MIB + 1 })).toEqual({
        ok: false,
        reason: "monthly_upload_bytes_exceeded",
      });
    }
  });

  it("refuses an upload whose size is not a whole number of bytes", () => {
    for (const bytes of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(evaluateUpload(stateAt(), { tier: "solo", bytes })).toEqual({ ok: false, reason: "upload_size_unknown" });
    }
  });

  it("each tier's size limit leaves room for its count of the smallest file the daemon uploads (over 15 MiB)", () => {
    for (const tier of TIERS) {
      const cap = UPLOAD_CAPS[tier];
      expect(cap.monthly_uploads).toBeGreaterThan(0);
      expect(cap.monthly_upload_bytes).toBeGreaterThanOrEqual(cap.monthly_uploads * 15 * MIB);
    }
  });

  it("reserveUpload counts one upload and its bytes; releaseUpload gives them back, never below zero", () => {
    const s = stateAt({ monthly_uploads: 3, monthly_upload_bytes: 60 * MIB });
    const reserved = reserveUpload(s, 20 * MIB);
    expect(reserved.monthly_uploads).toBe(4);
    expect(reserved.monthly_upload_bytes).toBe(80 * MIB);
    expect(s.monthly_uploads).toBe(3); // pure: input not mutated
    const released = releaseUpload(reserved, 20 * MIB);
    expect(released.monthly_uploads).toBe(3);
    expect(released.monthly_upload_bytes).toBe(60 * MIB);
    const floor = releaseUpload(stateAt(), 20 * MIB);
    expect(floor.monthly_uploads).toBe(0);
    expect(floor.monthly_upload_bytes).toBe(0);
  });
});

// The store's two upload routes, driven through QuotaStoreDO.fetch over an in-memory storage. The in-memory transaction
// runs its body directly, so this checks what each route reads and writes; it does not check two requests at once.
describe("W38-S1165 — /upload-reserve and /upload-release on the store", () => {
  const MIB = 1024 * 1024;

  function store(initial?: unknown) {
    const data = new Map<string, unknown>();
    if (initial !== undefined) data.set("quota_state", initial);
    const storage = {
      get: async (k: string) => structuredClone(data.get(k)),
      put: async (k: string, v: unknown) => { data.set(k, structuredClone(v)); },
      transaction: async (fn: (txn: unknown) => Promise<void>) => fn(storage),
      setAlarm: async (_t: number) => {},
    };
    const quota = new QuotaStoreDO({ storage } as unknown as DurableObjectState, {});
    const post = (path: string, body: unknown) =>
      quota.fetch(new Request(`https://internal${path}`, { method: "POST", body: JSON.stringify(body) }));
    return { data, post, saved: () => data.get("quota_state") as QuotaState | undefined };
  }
  const month = currentPeriod().month;

  it("reserve counts the upload and names the month it was counted in", async () => {
    const q = store();
    const r = await q.post("/upload-reserve", { tier: "free", bytes: 20 * MIB });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true, period_month: month });
    expect(q.saved()?.monthly_uploads).toBe(1);
    expect(q.saved()?.monthly_upload_bytes).toBe(20 * MIB);
  });

  it("reserve at the limit is refused with 429 and counts nothing", async () => {
    const full = { ...emptyState(), monthly_uploads: UPLOAD_CAPS.free.monthly_uploads };
    const q = store(full);
    const r = await q.post("/upload-reserve", { tier: "free", bytes: 20 * MIB });
    expect(r.status).toBe(429);
    expect(await r.json()).toEqual({ ok: false, reason: "monthly_uploads_exceeded" });
    expect(q.saved()).toEqual(full);
  });

  it("reserve of a size that is not a whole number of bytes is refused and counts nothing", async () => {
    const q = store(emptyState());
    const r = await q.post("/upload-reserve", { tier: "free", bytes: -1 });
    expect(r.status).toBe(429);
    expect(q.saved()?.monthly_uploads).toBe(0);
  });

  it("release in the month of the reservation gives it back", async () => {
    const q = store();
    await q.post("/upload-reserve", { tier: "solo", bytes: 30 * MIB });
    const r = await q.post("/upload-release", { bytes: 30 * MIB, period_month: month });
    expect(r.status).toBe(200);
    expect(q.saved()?.monthly_uploads).toBe(0);
    expect(q.saved()?.monthly_upload_bytes).toBe(0);
  });

  it("release of a reservation from another month leaves this month's count alone", async () => {
    const q = store();
    await q.post("/upload-reserve", { tier: "solo", bytes: 30 * MIB });
    await q.post("/upload-release", { bytes: 30 * MIB, period_month: "1999-01" });
    expect(q.saved()?.monthly_uploads).toBe(1);
    expect(q.saved()?.monthly_upload_bytes).toBe(30 * MIB);
  });

  it("a record written before the upload limit is counted from zero", async () => {
    const p = currentPeriod();
    const q = store({ period_month: p.month, period_day: p.day, monthly_cost_microcents: 5, monthly_tasks: 2, daily_tasks: 1 });
    const r = await q.post("/upload-reserve", { tier: "free", bytes: 16 * MIB });
    expect(r.status).toBe(200);
    expect(q.saved()).toEqual({
      period_month: p.month,
      period_day: p.day,
      monthly_cost_microcents: 5,
      monthly_tasks: 2,
      daily_tasks: 1,
      monthly_uploads: 1,
      monthly_upload_bytes: 16 * MIB,
    });
  });
});
