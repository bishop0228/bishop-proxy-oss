/**
 * AuthStoreDO test surface.
 *
 * Test-infra note: this repo does not depend on
 * `@cloudflare/vitest-pool-workers`, so DO `fetch()` cannot be invoked from
 * outside the worker. The pattern (`test/enroll.test.ts` exercises
 * AuthStoreDO `/issue` via public `/v1/enroll`) is followed for both:
 *
 * (a) Step 2 — `/verify-token` route. The four codified branches
 *     (`not_found` / `revoked` / `expired` / `valid`) are exercised at
 *     Step 8 in `test/messages.test.ts` as the 401-reason cases of
 *     `/v1/messages`. Cross-reference is intentional — the brief's Step 8
 *     test list ("401 on token not_found", "401 on token revoked",
 *     "401 on token expired") is the same surface this file would have
 *     tested in isolation.
 *
 * (b) Step 3.4 — best-effort token-keyed tier-cache seed in `_issueToken`.
 *     The seed write is exercised every time `test/enroll.test.ts` runs
 *     a fresh enrollment (regression coverage: any throw inside the seed
 *     call would propagate out of the swallow-block only if the call
 *     site itself crashed, which would fail enrollment). The read-side
 *     assertion — that after a fresh enrollment the token-keyed
 *     TierCacheDO returns `tier: "free"` — is exercised at Step 8 in
 *     `test/messages.test.ts` once `/v1/messages` reads the token-keyed
 *     cache. That same assertion implicitly verifies the D1 null-path
 *     (the seed writes `stripe_event_id: null`; if D1's null-path guard
 *     were broken, the seed would never land and Step 8 would observe a
 *     missing record).
 */

import { describe, it } from "vitest";

describe("AuthStoreDO surface (deferred to messages.test.ts at Step 8)", () => {
  it.todo("/verify-token: not_found / revoked / expired / valid via /v1/messages");
  it.todo("seed: token-keyed TierCacheDO returns free after fresh enrollment");
});
