/**
 * Test helper — clear the per-/24 per-day rate-limit counters for BOTH
 * /v1/challenge AND /v1/enroll against a freshly-booted dev worker.
 *
 * This is NOT a product surface. It drives the admin-only
 * POST /admin/rate-limit/clear endpoint (x-admin-token gated). The adopting
 * worker MUST set `ADMIN_TOKEN: "test_admin"` in its `unstable_dev` vars.
 *
 * WHY this exists (the test-isolation invariant):
 *   The full proxy suite runs SERIALLY (vitest `fileParallelism: false`) and
 *   every test file boots `unstable_dev("src/index.ts", { env: "staging" })`
 *   under the SAME worker name → the SAME on-disk AuthStoreDO state dir.
 *   Wrangler 3.x persists DO state to `.wrangler/state` even with
 *   `persist: false`, and `global-setup.ts` wipes that dir only ONCE per suite
 *   run (not per file). So the challenge-nonce store and the /v1/enroll
 *   rate-limit counter (10/24h per /24, keyed ip_prefix+endpoint+date — NOT
 *   per fingerprint) ACCUMULATE across serially-run files.
 *
 *   A file that enrolls in its `beforeAll` but does NOT reset both counters can
 *   hit the 429 cap purely as a function of how many enrolls ran in earlier
 *   files — a fragility that grows with every provider added to the roster.
 *   Every enrolling file therefore self-clears BOTH counters here, so it never
 *   depends on file ordering. (See tasks/lessons.md — the S964 "flake"
 *   mis-diagnosis: a full-serial-suite red is deterministic, not a flake.)
 */
import { expect } from "vitest";
import type { Unstable_DevWorker } from "wrangler";

export async function clearAuthRateLimits(
  worker: Unstable_DevWorker,
  ipPrefix = "127.0.0",
  adminToken = "test_admin",
): Promise<void> {
  const today = new Date().toISOString().slice(0, 10);
  for (const endpoint of ["challenge", "enroll"] as const) {
    const res = await worker.fetch("/admin/rate-limit/clear", {
      method: "POST",
      headers: { "content-type": "application/json", "x-admin-token": adminToken },
      body: JSON.stringify({ ip_prefix: ipPrefix, endpoint, date: today }),
    });
    expect(res.ok, `${endpoint} rate-limit clear failed: ${res.status}`).toBe(true);
    await res.json();
  }
}
