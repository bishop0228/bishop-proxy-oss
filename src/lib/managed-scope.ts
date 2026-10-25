/**
 * Which routes serve a managed device, and the mode a request is served in.
 *
 * W38-S1165 (founder decision 2026-10-25, (b)): Bishop's included models are Anthropic's, served on /v1/messages, and a
 * managed device may upload a file for them (/v1/anthropic/files). Every other route that could spend an operator key
 * serves only a device's own key, so a managed device is refused there whatever operator keys the Worker binds. Those
 * routes call `isManaged` right after the token is verified, before the quota, the classifier or any key, and answer
 * 403 `managed_not_offered`.
 *
 * W38-S1168 (founder decision 2026-10-25, (a)): a paying device keeps its included models after it connects a provider of
 * its own. A device's record says byok for good once it connects anything (auth-store's one-way relabel), so the two
 * routes that serve the included models read the request through `servedMode`: a request from a paying device that
 * names no key of its own (`x-bishop-upstream-key`) is served and metered as managed, and the device's own key is used
 * only where the request names one. A free device that connected keeps today's meaning: its own key only.
 */

import type { Tier } from "./pricing";

export const MANAGED_NOT_OFFERED = "managed_not_offered";

export type AccountMode = "managed" | "byok";

export function isManaged(recordMode: AccountMode | null | undefined): boolean {
  return (recordMode ?? "managed") === "managed";
}

export function servedMode(
  recordMode: AccountMode | null | undefined,
  tier: Tier,
  incoming: Headers,
): AccountMode {
  const mode = recordMode ?? "managed";
  if (mode === "managed" || tier === "free") return mode;
  return (incoming.get("x-bishop-upstream-key") ?? "").trim() ? "byok" : "managed";
}
