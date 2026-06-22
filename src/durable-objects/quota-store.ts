/**
 * QuotaStoreDO.
 *
 * One DO instance per token (sharded by token_id UUID via idFromName).
 * Tracks per-token monthly cost/task spend and a daily task floor for free tier.
 *
 * Routes:
 *   POST /check     — preflight. Body: { tier, weight, cost_cents_estimate? }.
 *                     Returns { ok: true } | { ok: false, reason }. Does NOT
 *                     mutate counters.
 *   POST /increment — commit. Body: { weight, cost_cents, account_mode? }.
 *                     Atomically advances monthly_cost_cents, monthly_tasks,
 *                     daily_tasks (in a single storage.transaction). Rolls period
 *                     boundaries defensively. A byok account_mode skips the
 *                     monthly_cost meter (S937 — it pays its own provider).
 *   GET  /          — debug/observability. Returns the current state.
 *
 * Storage shape (G9):
 *   period_month       — "YYYY-MM" (UTC) — when state.period_month != current,
 *                        zero monthly counters
 *   period_day         — "YYYY-MM-DD" (UTC) — when stale, zero daily counter
 *   monthly_cost_cents — integer cents
 *   monthly_tasks      — integer (haiku=1, sonnet=3 weighting per pricing.ts)
 *   daily_tasks        — integer (same weighting; only enforced for free tier)
 *
 * Period rollover happens lazily on every read/write so we don't depend on
 * alarm() firing at the boundary; alarm() is set as a defensive sweep at the
 * next month boundary so dormant tokens still reset eventually.
 *
 * D2: studio tier is unmetered at P2.1 — /check always returns ok for studio.
 *
 * Cap evaluation logic is extracted as pure helpers for unit-testability
 * (test/quota.test.ts) since this repo does not include @cloudflare/vitest-pool-workers.
 */

import { TIER_CAPS, type Tier } from "../lib/pricing";

export interface QuotaState {
  period_month: string;       // "YYYY-MM" UTC
  period_day: string;         // "YYYY-MM-DD" UTC
  monthly_cost_cents: number;
  monthly_tasks: number;
  daily_tasks: number;
}

export interface CheckRequest {
  tier: Tier;
  weight: number;
  cost_cents_estimate?: number;
  // W38-S923: the device's account_mode. A CONNECTED (byok) device pays its OWN
  // provider, so the free-tier daily_floor must NOT apply to it — only managed
  // (FREE) devices are metered against the floor. Defaults to "managed" (the
  // metered path) when omitted, preserving the existing free-tier wall.
  account_mode?: "managed" | "byok";
}

export interface CheckResult {
  ok: boolean;
  reason?: "monthly_cost_exceeded" | "monthly_tasks_exceeded" | "daily_floor_exceeded";
}

export interface IncrementRequest {
  weight: number;
  cost_cents: number;
  // W38-S937: a CONNECTED (byok) device pays its OWN provider, so its inference
  // cost must NOT advance the proxy's free-tier monthly_cost meter (or the cap —
  // already byok-bypassed in evaluateCheck — would re-fire off a meter polluted
  // by traffic Bishop never pays for). The task counters (monthly_tasks abuse
  // bound) still advance. Defaults to "managed" (the metered path) when omitted.
  account_mode?: "managed" | "byok";
}

export function currentPeriod(now: Date = new Date()): { month: string; day: string } {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  return { month: `${y}-${m}`, day: `${y}-${m}-${d}` };
}

export function rollPeriod(state: QuotaState, now: Date = new Date()): QuotaState {
  const { month, day } = currentPeriod(now);
  const monthlyStale = state.period_month !== month;
  const dailyStale = state.period_day !== day;
  if (!monthlyStale && !dailyStale) return state;
  return {
    period_month: month,
    period_day: day,
    monthly_cost_cents: monthlyStale ? 0 : state.monthly_cost_cents,
    monthly_tasks: monthlyStale ? 0 : state.monthly_tasks,
    daily_tasks: dailyStale ? 0 : state.daily_tasks,
  };
}

export function emptyState(now: Date = new Date()): QuotaState {
  const { month, day } = currentPeriod(now);
  return {
    period_month: month,
    period_day: day,
    monthly_cost_cents: 0,
    monthly_tasks: 0,
    daily_tasks: 0,
  };
}

/**
 * Pre-flight cap evaluation. Adds the would-be increment to current totals
 * and compares against the tier cap. Studio (all-null caps) always passes.
 *
 * The check is "after-the-add" — i.e., cap=200 means the 200th task is allowed
 * but the 201st is not. cost_cents_estimate is treated as 0 if omitted (the
 * brief permits a permissive preflight that re-evaluates post-response via
 * /increment; the monthly_cost cap is enforced as a soft cap measured at
 * commit time).
 */
export function evaluateCheck(
  state: QuotaState,
  req: CheckRequest,
): CheckResult {
  const cap = TIER_CAPS[req.tier];
  const projectedCost = state.monthly_cost_cents + (req.cost_cents_estimate ?? 0);
  const projectedTasks = state.monthly_tasks + req.weight;
  const projectedDaily = state.daily_tasks + req.weight;

  // W38-S923/S937: a CONNECTED (byok) device pays its OWN provider, so the
  // free-tier COST meters — both the monthly_cost cap (S937) and the daily_floor
  // (S923) — must NOT gate it. Only managed/FREE devices are metered against the
  // proxy's free-tier walls. The monthly_tasks cap is an abuse bound and STILL
  // applies to byok (it is not a cost meter). Defaults to the metered path.
  const isByok = req.account_mode === "byok";
  if (!isByok && cap.monthly_cost_cents !== null && projectedCost > cap.monthly_cost_cents) {
    return { ok: false, reason: "monthly_cost_exceeded" };
  }
  if (cap.monthly_tasks !== null && projectedTasks > cap.monthly_tasks) {
    return { ok: false, reason: "monthly_tasks_exceeded" };
  }
  if (!isByok && cap.daily_floor !== null && projectedDaily > cap.daily_floor) {
    return { ok: false, reason: "daily_floor_exceeded" };
  }
  return { ok: true };
}

export function applyIncrement(
  state: QuotaState,
  req: IncrementRequest,
): QuotaState {
  // W38-S937: byok inference cost does not touch the free-tier cost meter.
  const isByok = req.account_mode === "byok";
  return {
    ...state,
    monthly_cost_cents: isByok
      ? state.monthly_cost_cents
      : state.monthly_cost_cents + req.cost_cents,
    monthly_tasks: state.monthly_tasks + req.weight,
    daily_tasks: state.daily_tasks + req.weight,
  };
}

const STATE_KEY = "quota_state";

export class QuotaStoreDO {
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      const stored = (await this.state.storage.get<QuotaState>(STATE_KEY)) ?? emptyState();
      const current = rollPeriod(stored);
      return new Response(JSON.stringify(current), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/check") {
      const body = (await request.json()) as CheckRequest;
      const stored = (await this.state.storage.get<QuotaState>(STATE_KEY)) ?? emptyState();
      const current = rollPeriod(stored);
      // Persist the rolled state if it changed so subsequent /check or
      // /increment calls observe the same boundary. Cheap because rollPeriod
      // is no-op when nothing rolled.
      if (current !== stored) {
        await this.state.storage.put(STATE_KEY, current);
      }
      const result = evaluateCheck(current, body);
      return new Response(JSON.stringify(result), {
        status: result.ok ? 200 : 429,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/increment") {
      const body = (await request.json()) as IncrementRequest;
      let next: QuotaState;
      await this.state.storage.transaction(async (txn) => {
        const stored = (await txn.get<QuotaState>(STATE_KEY)) ?? emptyState();
        const current = rollPeriod(stored);
        next = applyIncrement(current, body);
        await txn.put(STATE_KEY, next);
      });
      // schedule defensive month-boundary sweep
      await this._scheduleNextMonthAlarm();
      return new Response(JSON.stringify(next!), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }

  async alarm(): Promise<void> {
    // Defensive sweep: lazy rollover already handles correctness on access,
    // but for tokens that go dormant for a full month we still want the
    // counters cleared so observability of a dormant DO shows zero, not
    // last-month's totals.
    const stored = await this.state.storage.get<QuotaState>(STATE_KEY);
    if (stored) {
      const rolled = rollPeriod(stored);
      if (rolled !== stored) {
        await this.state.storage.put(STATE_KEY, rolled);
      }
    }
    await this._scheduleNextMonthAlarm();
  }

  private async _scheduleNextMonthAlarm(): Promise<void> {
    const now = new Date();
    const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 5));
    await this.state.storage.setAlarm(next.getTime());
  }
}
