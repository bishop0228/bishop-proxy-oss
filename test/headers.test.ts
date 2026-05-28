import { describe, it, expect } from "vitest";
import { rebuildHeaders, resolveUpstreamKey } from "../src/lib/headers";

describe("resolveUpstreamKey — BYOK entitlement gate", () => {
  const OP_KEY = "op-key-abc";

  it("P1: managed mode → operator key (inbound upstream-key ignored if absent)", () => {
    const result = resolveUpstreamKey("managed", new Headers(), OP_KEY);
    expect(result).toEqual({ ok: true, key: OP_KEY });
  });

  it("P2: managed mode + inbound X-Bishop-Upstream-Key → still operator key (NEG: inbound ignored)", () => {
    const h = new Headers({ "x-bishop-upstream-key": "user-supplied-key" });
    const result = resolveUpstreamKey("managed", h, OP_KEY);
    expect(result).toEqual({ ok: true, key: OP_KEY });
  });

  it("P3: byok mode + present key → user key returned and !== operator key", () => {
    const h = new Headers({ "x-bishop-upstream-key": "user-supplied-key" });
    const result = resolveUpstreamKey("byok", h, OP_KEY);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.key).toBe("user-supplied-key");
      expect(result.key).not.toBe(OP_KEY);
    }
  });

  it("P4: byok mode + absent header → fail-closed {ok:false, reason:byok_key_missing}", () => {
    const result = resolveUpstreamKey("byok", new Headers(), OP_KEY);
    expect(result).toEqual({ ok: false, reason: "byok_key_missing" });
  });

  it("P5: byok mode + whitespace-only header → fail-closed (NEG: whitespace is not a valid key)", () => {
    const h = new Headers({ "x-bishop-upstream-key": "   " });
    const result = resolveUpstreamKey("byok", h, OP_KEY);
    expect(result).toEqual({ ok: false, reason: "byok_key_missing" });
  });

  it("P6: fail branch result has no key field", () => {
    const result = resolveUpstreamKey("byok", new Headers(), OP_KEY);
    expect(result.ok).toBe(false);
    expect("key" in result).toBe(false);
  });
});

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
