import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Serialize test-file execution so only one file's unstable_dev workers
    // touch ~/.config/.wrangler/registry at a time, preventing the ENOENT-on-utime
    // race when parallel workers share the same registry path.
    fileParallelism: false,
    // Allow beforeEach/afterEach hooks (e.g. mock.__reset fetch) up to 60s;
    // the default 10s is too short when a serialized unstable_dev worker is
    // still warming up from the previous file's teardown.
    hookTimeout: 60000,
    // Wipe .wrangler/state before each run so Durable Object / KV state from
    // a prior run does not bleed into fresh workers (wrangler 3.x writes
    // worker-name-scoped DO dirs to disk even when persist:false is set).
    globalSetup: ["./test/global-setup.ts"],
  },
});
