import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _dirname = dirname(fileURLToPath((import.meta as any).url));

describe("log-discipline (G7 grep assertion)", () => {
  it("no `console.log` calls land outside src/lib/log.ts in the src/ tree", () => {
    const srcDir = resolve(_dirname, "..", "src");
    let stdout = "";
    try {
      // grep returns exit 1 when no matches; that's the PASS case.
      stdout = execSync(`grep -rn "console\\.log" "${srcDir}"`, {
        encoding: "utf8",
      });
    } catch (e: any) {
      // exit code 1 = no matches found → PASS
      if (e.status === 1) {
        stdout = "";
      } else {
        throw e;
      }
    }
    // Filter to non-log.ts matches
    const violations = stdout
      .split("\n")
      .filter((line) => line.length > 0)
      .filter((line) => !line.includes("/src/lib/log.ts:"));
    expect(violations).toEqual([]);
  });
});
