import { describe, it, expect } from "vitest";
import { rebuildHeaders, rebuildOpenAIHeaders, resolveUpstreamKey } from "../src/lib/headers";

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

describe("resolveUpstreamKey — managed-side generalization (§1.17.11-PROXY-V)", () => {
  const OP_KEY = "op-key-abc";

  it("V1: managed + non-null operator key → {ok:true, key:operatorKey} [regression]", () => {
    const result = resolveUpstreamKey("managed", new Headers(), OP_KEY);
    expect(result).toEqual({ ok: true, key: OP_KEY });
  });

  it("V2: managed + null operator → fail-closed managed_key_unavailable [fail-closed positive]", () => {
    const result = resolveUpstreamKey("managed", new Headers(), null);
    expect(result).toEqual({ ok: false, reason: "managed_key_unavailable" });
  });

  it("V3: managed + whitespace-only operator → managed_key_unavailable [boundary]", () => {
    const result = resolveUpstreamKey("managed", new Headers(), "   ");
    expect(result).toEqual({ ok: false, reason: "managed_key_unavailable" });
  });

  it("V4: NEG — managed + inbound upstream-key PRESENT + null operator → fail-closed, never reads inbound", () => {
    const h = new Headers({ "x-bishop-upstream-key": "user-supplied-key" });
    const result = resolveUpstreamKey("managed", h, null);
    expect(result).toEqual({ ok: false, reason: "managed_key_unavailable" });
    // Structural proof: even with an inbound key present, managed mode fails
    // closed and never surfaces the inbound value.
    if (!result.ok) {
      expect((result as { key?: string }).key).toBeUndefined();
    }
  });

  it("V5: byok + present key → user key [preserved cross-check after signature change]", () => {
    const h = new Headers({ "x-bishop-upstream-key": "user-supplied-key" });
    const result = resolveUpstreamKey("byok", h, OP_KEY);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.key).toBe("user-supplied-key");
      expect(result.key).not.toBe(OP_KEY);
    }
  });
});

describe("rebuildOpenAIHeaders — provider shape + identifier-strip (§1.17.11-PROXY-V)", () => {
  it("V6: sets authorization Bearer <key>, NO x-api-key/anthropic-version/x-bishop-zdr [provider-shape]", () => {
    const incoming = new Headers({ "content-type": "application/json" });
    const out = rebuildOpenAIHeaders(incoming, "sk-openai-123");
    expect(out.get("authorization")).toBe("Bearer sk-openai-123");
    expect(out.get("x-api-key")).toBeNull();
    expect(out.get("anthropic-version")).toBeNull();
    expect(out.get("x-bishop-zdr")).toBeNull();
  });

  it("V7: strips inbound authorization/cookie/x-bishop-upstream-key, forwards only content-type [Pillar 1]", () => {
    const incoming = new Headers({
      "authorization": "Bearer client-bishop-token",
      "cookie": "session=abc",
      "x-bishop-upstream-key": "user-supplied-key",
      "user-agent": "evil/1.0",
      "x-forwarded-for": "1.2.3.4",
      "content-type": "application/json",
    });
    const out = rebuildOpenAIHeaders(incoming, "sk-openai-123");
    // Injected Bearer replaces the inbound client token.
    expect(out.get("authorization")).toBe("Bearer sk-openai-123");
    expect(out.get("cookie")).toBeNull();
    expect(out.get("x-bishop-upstream-key")).toBeNull();
    expect(out.get("user-agent")).toBeNull();
    expect(out.get("x-forwarded-for")).toBeNull();
    expect(out.get("content-type")).toBe("application/json");
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
