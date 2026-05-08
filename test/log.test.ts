import { describe, it, expect, vi } from "vitest";
import { isProxyLogEvent, logEvent, ProxyLogShapeError, ProxyLogEvent } from "../src/lib/log";

function validEvent(): ProxyLogEvent {
  return {
    event_type: "request",
    timestamp: "2026-04-28T12:00:00.000Z",
    request_id: "00000000-0000-4000-8000-000000000001",
    token_id: "11111111-1111-4111-8111-111111111111",
    ip: "192.168.1.0",
    request_size_bytes: 256,
    response_status: 200,
    response_size_bytes: 1024,
    token_count_in: 32,
    token_count_out: 64,
    cached_tokens: 0,
    cache_creation_input_tokens: null,
    cache_read_input_tokens: null,
    classification_decision: "allow",
    classification_category: null,
    classifier_error_reason: null,
    duration_ms: 412,
    upstream_status: 200,
    cap_type_hit: null,
  };
}

describe("isProxyLogEvent (G7 type guard)", () => {
  it("accepts a fully-populated valid event", () => {
    expect(isProxyLogEvent(validEvent())).toBe(true);
  });

  it("accepts null token_id (e.g., /enroll)", () => {
    const e = validEvent();
    e.token_id = null;
    expect(isProxyLogEvent(e)).toBe(true);
  });

  it("rejects null/non-object input", () => {
    expect(isProxyLogEvent(null)).toBe(false);
    expect(isProxyLogEvent(undefined)).toBe(false);
    expect(isProxyLogEvent("string")).toBe(false);
    expect(isProxyLogEvent(42)).toBe(false);
  });

  it("rejects when a required field is missing", () => {
    const e = validEvent() as Partial<ProxyLogEvent>;
    delete e.duration_ms;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects an extra field (prompt) — privacy-allowlist enforcement", () => {
    const e = { ...validEvent(), prompt: "leaked content" } as Record<string, unknown>;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects an extra field (response_body)", () => {
    const e = { ...validEvent(), response_body: "leaked body" } as Record<string, unknown>;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects an extra field (fingerprint)", () => {
    const e = { ...validEvent(), fingerprint: "abc123" } as Record<string, unknown>;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects unknown event_type literal", () => {
    const e = { ...validEvent(), event_type: "bogus" } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects wrong type for response_status", () => {
    const e = { ...validEvent(), response_status: "200" } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects unknown classification_decision literal", () => {
    const e = { ...validEvent(), classification_decision: "maybe" } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects unknown classification_category literal", () => {
    const e = { ...validEvent(), classification_category: "spam" } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects unknown cap_type_hit literal", () => {
    const e = { ...validEvent(), cap_type_hit: "weekly" } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects non-finite numbers (NaN, Infinity)", () => {
    const e = { ...validEvent(), duration_ms: NaN } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
    const e2 = { ...validEvent(), request_size_bytes: Infinity } as unknown;
    expect(isProxyLogEvent(e2)).toBe(false);
  });

  it("rejects null where null is not allowed (event_type)", () => {
    const e = { ...validEvent(), event_type: null } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });

  it("rejects null timestamp", () => {
    const e = { ...validEvent(), timestamp: null } as unknown;
    expect(isProxyLogEvent(e)).toBe(false);
  });
});

describe("logEvent", () => {
  it("emits stringified JSON via console.log when shape is valid", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const e = validEvent();
      logEvent(e);
      expect(spy).toHaveBeenCalledTimes(1);
      const arg = spy.mock.calls[0][0];
      expect(typeof arg).toBe("string");
      const parsed = JSON.parse(arg as string);
      expect(parsed).toEqual(e);
    } finally {
      spy.mockRestore();
    }
  });

  it("throws ProxyLogShapeError on invalid shape and does NOT call console.log", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const bad = { ...validEvent(), prompt: "leaked" } as unknown as ProxyLogEvent;
      expect(() => logEvent(bad)).toThrow(ProxyLogShapeError);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});
