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
 *   POST /increment — commit. Body: { weight, cost_microcents, account_mode? }.
 *                     Atomically advances monthly_cost_microcents, monthly_tasks,
 *                     daily_tasks (in a single storage.transaction). Rolls period
 *                     boundaries defensively. A byok account_mode skips ALL free-
 *                     tier counters — cost meter + task counters (S937/S939 — it
 *                     pays its own provider, so it touches no free-tier meter).
 *   POST /upload-reserve — W38-S1165: a managed device's upload to the Anthropic
 *                     Files API. Body: { tier, bytes }. Checks UPLOAD_CAPS and, if it
 *                     fits, counts it, in one transaction, so two uploads at once
 *                     cannot both slip under the limit. 429 { ok: false, reason }
 *                     when it does not fit; else { ok: true, period_month }.
 *   POST /upload-release — the upload failed upstream: give its reservation back.
 *                     Body: { bytes, period_month }. A no-op once the month rolled.
 *   GET  /          — debug/observability. Returns the current state.
 *
 * Storage shape (G9):
 *   period_month       — "YYYY-MM" (UTC) — when state.period_month != current,
 *                        zero monthly counters
 *   period_day         — "YYYY-MM-DD" (UTC) — when stale, zero daily counter
 *   monthly_cost_microcents — integer micro-cents (cents × 10,000); W38-S938.
 *                        Legacy monthly_cost_cents records are converted ×10,000
 *                        on read by migrateState() — never crash on an old shape.
 *   monthly_tasks      — integer (haiku=1, sonnet=3 weighting per pricing.ts)
 *   daily_tasks        — integer (same weighting; only enforced for free tier)
 *   monthly_uploads, monthly_upload_bytes — W38-S1165: a managed device's uploads to
 *                        the Anthropic Files API this month (0 on an older record)
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

import { TIER_CAPS, UPLOAD_CAPS, MICROCENTS_PER_CENT, type Tier } from "../lib/pricing";

export interface QuotaState {
  period_month: string;       // "YYYY-MM" UTC
  period_day: string;         // "YYYY-MM-DD" UTC
  // W38-S938: the monthly cost meter accumulates in micro-cents (cents × 10,000,
  // integer) so a typical sub-cent request is metered at its TRUE cost — the old
  // monthly_cost_cents field floored each request to ≥1¢, firing the $1 cap at
  // pennies of real spend. Old-shape records (monthly_cost_cents) are converted
  // ×10,000 on read by migrateState(); never crash on an old record.
  monthly_cost_microcents: number;
  monthly_tasks: number;
  daily_tasks: number;
  // W38-S1165: a managed device's uploads to the Anthropic Files API this month, and their total bytes.
  monthly_uploads: number;
  monthly_upload_bytes: number;
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
  // W38-S938: the per-request inference cost in micro-cents (cents × 10,000),
  // computed exactly (no per-request ceil-to-1¢ floor). See computeCostMicroCents.
  cost_microcents: number;
  // W38-S937/S939: a CONNECTED (byok) device pays its OWN provider, so NONE of
  // the proxy's free-tier counters apply to it — not the monthly_cost meter
  // (S937), and not the task counters either (monthly_tasks + daily_tasks, S939).
  // A byok device that advanced any free-tier counter would (a) be metered for
  // traffic Bishop never pays for and (b) eventually trip a cap that was already
  // byok-bypassed in evaluateCheck off a polluted meter. So a byok increment
  // touches NO free-tier counter. Defaults to "managed" (the metered path) when
  // omitted, preserving the existing free-tier wall.
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
    monthly_cost_microcents: monthlyStale ? 0 : state.monthly_cost_microcents,
    monthly_tasks: monthlyStale ? 0 : state.monthly_tasks,
    daily_tasks: dailyStale ? 0 : state.daily_tasks,
    monthly_uploads: monthlyStale ? 0 : state.monthly_uploads,
    monthly_upload_bytes: monthlyStale ? 0 : state.monthly_upload_bytes,
  };
}

export function emptyState(now: Date = new Date()): QuotaState {
  const { month, day } = currentPeriod(now);
  return {
    period_month: month,
    period_day: day,
    monthly_cost_microcents: 0,
    monthly_tasks: 0,
    daily_tasks: 0,
    monthly_uploads: 0,
    monthly_upload_bytes: 0,
  };
}

/**
 * Normalize a raw stored record into a current-shape QuotaState (W38-S938).
 *
 * Migration-safe by an additive read-time convert: a legacy record carries
 * `monthly_cost_cents` (integer cents); we convert it ×10,000 to micro-cents.
 * A current record carries `monthly_cost_microcents` and passes through. A
 * null/garbage record falls back to emptyState. NEVER crashes on an old shape.
 * (The monthly meter is also a SOFT cap that auto-zeroes on the next monthly
 * rollover, so even an unconverted record self-heals at the period boundary.)
 */
export function migrateState(raw: unknown, now: Date = new Date()): QuotaState {
  if (!raw || typeof raw !== "object") return emptyState(now);
  const r = raw as Record<string, unknown>;
  const { month, day } = currentPeriod(now);
  let microcents: number;
  if (typeof r.monthly_cost_microcents === "number") {
    microcents = r.monthly_cost_microcents;
  } else if (typeof r.monthly_cost_cents === "number") {
    microcents = r.monthly_cost_cents * MICROCENTS_PER_CENT;
  } else {
    microcents = 0;
  }
  return {
    period_month: typeof r.period_month === "string" ? r.period_month : month,
    period_day: typeof r.period_day === "string" ? r.period_day : day,
    monthly_cost_microcents: microcents,
    monthly_tasks: typeof r.monthly_tasks === "number" ? r.monthly_tasks : 0,
    daily_tasks: typeof r.daily_tasks === "number" ? r.daily_tasks : 0,
    monthly_uploads: typeof r.monthly_uploads === "number" ? r.monthly_uploads : 0,
    monthly_upload_bytes: typeof r.monthly_upload_bytes === "number" ? r.monthly_upload_bytes : 0,
  };
}

/**
 * True when a stored record is the legacy cents-only shape (no micro-cent
 * field) — used to trigger a one-time migration write so we don't re-convert
 * forever. A null/non-object record is not "legacy" (emptyState covers it).
 */
export function isLegacyShape(raw: unknown): boolean {
  return (
    !!raw &&
    typeof raw === "object" &&
    !("monthly_cost_microcents" in (raw as Record<string, unknown>))
  );
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
  // W38-S938: the meter is in micro-cents; the cap table is authored in cents and
  // converted at compare time. The estimate (if any) is supplied in cents, so it
  // is likewise converted. All callers currently pass 0 (the cost cap is enforced
  // as a soft cap measured at commit via /increment), so this is state-vs-cap.
  const capCostMicrocents =
    cap.monthly_cost_cents === null ? null : cap.monthly_cost_cents * MICROCENTS_PER_CENT;
  const projectedCost =
    state.monthly_cost_microcents + (req.cost_cents_estimate ?? 0) * MICROCENTS_PER_CENT;
  const projectedTasks = state.monthly_tasks + req.weight;
  const projectedDaily = state.daily_tasks + req.weight;

  // W38-S923/S937/S939: a CONNECTED (byok) device pays its OWN provider, so NONE
  // of the proxy's free-tier walls gate it — not the monthly_cost cap (S937), not
  // the daily_floor (S923), and not the monthly_tasks cap (S939). All three are
  // free-tier quota dimensions; a device off the free meter must clear every one
  // of them on BOTH the check (here) and the increment (applyIncrement). Only
  // managed/FREE devices are metered against these walls. Defaults to the metered
  // path. (INVARIANT: if a new cap dimension is added it must be gated on !isByok
  // too — see test/quota.test.ts "byok clears EVERY free-tier gate".)
  const isByok = req.account_mode === "byok";
  if (!isByok && capCostMicrocents !== null && projectedCost > capCostMicrocents) {
    return { ok: false, reason: "monthly_cost_exceeded" };
  }
  if (!isByok && cap.monthly_tasks !== null && projectedTasks > cap.monthly_tasks) {
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
  // W38-S937/S939: a byok device touches NO free-tier counter — not the cost
  // meter (S937), and not the task counters (S939). Advancing them would meter a
  // device that pays its own provider and could re-fire a cap that was already
  // byok-bypassed in evaluateCheck off a polluted counter. Managed/FREE devices
  // advance all three (unchanged, fail-closed).
  const isByok = req.account_mode === "byok";
  return {
    ...state,
    monthly_cost_microcents: isByok
      ? state.monthly_cost_microcents
      : state.monthly_cost_microcents + req.cost_microcents,
    monthly_tasks: isByok ? state.monthly_tasks : state.monthly_tasks + req.weight,
    daily_tasks: isByok ? state.daily_tasks : state.daily_tasks + req.weight,
  };
}

export interface UploadReserveRequest {
  tier: Tier;
  bytes: number;
}

export interface UploadResult {
  ok: boolean;
  reason?: "monthly_uploads_exceeded" | "monthly_upload_bytes_exceeded" | "upload_size_unknown";
}

/**
 * W38-S1165: whether one more managed upload of `bytes` fits this month's UPLOAD_CAPS for the tier ("after-the-add",
 * as evaluateCheck: a cap of 20 allows the 20th upload and refuses the 21st). A size that is not a non-negative whole
 * number is refused: the count would be wrong.
 */
export function evaluateUpload(state: QuotaState, req: UploadReserveRequest): UploadResult {
  if (!Number.isInteger(req.bytes) || req.bytes < 0) return { ok: false, reason: "upload_size_unknown" };
  const cap = UPLOAD_CAPS[req.tier];
  if (state.monthly_uploads + 1 > cap.monthly_uploads) return { ok: false, reason: "monthly_uploads_exceeded" };
  if (state.monthly_upload_bytes + req.bytes > cap.monthly_upload_bytes) {
    return { ok: false, reason: "monthly_upload_bytes_exceeded" };
  }
  return { ok: true };
}

export function reserveUpload(state: QuotaState, bytes: number): QuotaState {
  return {
    ...state,
    monthly_uploads: state.monthly_uploads + 1,
    monthly_upload_bytes: state.monthly_upload_bytes + bytes,
  };
}

export function releaseUpload(state: QuotaState, bytes: number): QuotaState {
  return {
    ...state,
    monthly_uploads: Math.max(0, state.monthly_uploads - 1),
    monthly_upload_bytes: Math.max(0, state.monthly_upload_bytes - Math.max(0, bytes)),
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
      const stored = await this.state.storage.get<unknown>(STATE_KEY);
      const current = rollPeriod(migrateState(stored));
      return new Response(JSON.stringify(current), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/check") {
      const body = (await request.json()) as CheckRequest;
      const stored = await this.state.storage.get<unknown>(STATE_KEY);
      const migrated = migrateState(stored);
      const current = rollPeriod(migrated);
      // Persist the rolled/migrated state if it changed so subsequent /check or
      // /increment calls observe the same boundary and a legacy cents-only record
      // is rewritten in micro-cent shape once. Cheap because rollPeriod is a
      // no-op when nothing rolled and most records are already current-shape.
      if (current !== migrated || isLegacyShape(stored)) {
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
        const stored = await txn.get<unknown>(STATE_KEY);
        const current = rollPeriod(migrateState(stored));
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

    if (request.method === "POST" && url.pathname === "/upload-reserve") {
      const body = (await request.json()) as UploadReserveRequest;
      let result: UploadResult = { ok: false };
      let period = "";
      await this.state.storage.transaction(async (txn) => {
        const stored = await txn.get<unknown>(STATE_KEY);
        const current = rollPeriod(migrateState(stored));
        period = current.period_month;
        result = evaluateUpload(current, body);
        if (result.ok) await txn.put(STATE_KEY, reserveUpload(current, body.bytes));
      });
      if (result.ok) await this._scheduleNextMonthAlarm();
      return new Response(JSON.stringify(result.ok ? { ok: true, period_month: period } : result), {
        status: result.ok ? 200 : 429,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/upload-release") {
      const body = (await request.json()) as { bytes: number; period_month: string };
      await this.state.storage.transaction(async (txn) => {
        const stored = await txn.get<unknown>(STATE_KEY);
        const current = rollPeriod(migrateState(stored));
        // A reservation made last month is not taken off this month's count.
        if (current.period_month === body.period_month) {
          await txn.put(STATE_KEY, releaseUpload(current, body.bytes));
        }
      });
      return new Response(JSON.stringify({ ok: true }), {
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
    const stored = await this.state.storage.get<unknown>(STATE_KEY);
    if (stored) {
      const migrated = migrateState(stored);
      const rolled = rollPeriod(migrated);
      if (rolled !== migrated || isLegacyShape(stored)) {
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
