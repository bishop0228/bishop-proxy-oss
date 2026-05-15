import { describe, it, expect } from "vitest";
import { rebuildHeaders } from "../src/lib/headers";

describe("rebuildHeaders — ZDR header enforcement", () => {
  it("sets x-bishop-zdr: 1 unconditionally when api key is provided", () => {
    const incoming = new Headers({ "content-type": "application/json" });
    const out = rebuildHeaders(incoming, "test-api-key");
    expect(out.get("x-bishop-zdr")).toBe("1");
  });

  it("sets x-bishop-zdr: 1 with empty incoming headers", () => {
    const out = rebuildHeaders(new Headers(), "test-api-key");
    expect(out.get("x-bishop-zdr")).toBe("1");
  });

  it("sets x-bishop-zdr: 1 and does not forward incoming x-bishop-zdr from client", () => {
    const incoming = new Headers({ "x-bishop-zdr": "0", "content-type": "application/json" });
    const out = rebuildHeaders(incoming, "test-api-key");
    expect(out.get("x-bishop-zdr")).toBe("1");
  });
});
