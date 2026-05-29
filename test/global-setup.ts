import { rmSync } from "fs";
import { join } from "path";

export function setup() {
  // Wrangler 3.x writes Durable Object / KV state to .wrangler/state even when
  // unstable_dev is called with persist:false (worker-name-scoped DO dirs are
  // always created on disk). Stale state from a previous run bleeds into the
  // next run's workers because they share the same worker-name-keyed directories
  // (e.g. bishop-proxy-staging-AuthStoreDO). Wipe it before each suite so every
  // worker starts from an empty store.
  const statePath = join(process.cwd(), ".wrangler", "state");
  rmSync(statePath, { recursive: true, force: true });
}
