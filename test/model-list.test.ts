/**
 * Behavioral probes for the W38-S935 live-freshness model-list leg
 * (GET + X-Bishop-Provider → handleModelList).
 *
 * The §3.2 read-only operational-egress path the daemon's freshness layer GETs to
 * fetch the live per-provider model list (so retired ids auto-prune instead of
 * leaking from the bundled catalog). Unit-style (handleModelList + a stubbed
 * global fetch + DO stubs) so the legs are deterministic and no real network is
 * touched:
 *
 *   (1) ★ BYOK forward — deepseek/groq/mistral GET forwards to EXACTLY the frozen
 *       upstream host + model-list path with the FORWARDED user key as Bearer; the
 *       streamed id list is returned. Host + path are spec-derived, never request.
 *   (2) ★ managed — openai (Bearer) / claude (x-api-key+version) / gemini (?key=)
 *       use the OPERATOR key; the user's key is never read. gemini key rides the URL.
 *   (3) ★ unknown provider → 404 unknown_provider; fetch NOT called (→ bundled).
 *   (4) ★ auth — no Bearer → 401 missing_bearer; bad token → 401 token_not_found;
 *       fetch NOT called.
 *   (5) ★ byok_key_missing — forwarded provider w/o X-Bishop-Upstream-Key → 400,
 *       no forward; managed_key_unavailable — managed provider w/o operator key → 400.
 *   (6) ★ REDIRECT-BLOCKED — a 3xx to an off-allowlist host → 502, NO re-fetch.
 *   (7) ★ Pillar-1 audit — no logEvent line contains the forwarded/operator key;
 *       every line is a valid ProxyLogEvent.
 *   (8) quota — quota /check 429 → 429 quota_exceeded passthrough, fetch NOT called.
 *   (9) ★ deepseek AI-Gateway — CF_AIG_* set → forwards via gateway.ai.cloudflare.com
 *       (the /v1 segment stripped) with the cf-aig-authorization gateway token.
 *  (10) ★ zero-new-egress — every MODEL_LIST_SPECS host ∈ ALLOWED_OUTBOUND_HOSTS.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleModelList } from "../src/routes/model-list";
import { MODEL_LIST_SPECS } from "../src/lib/model-list-specs";
import {
  ALLOWED_OUTBOUND_HOSTS,
  isAnchoredEnterpriseHost,
} from "../src/lib/outbound-allowlist";
import { isProxyLogEvent } from "../src/lib/log";
import type { Env } from "../src/index";

// ── constants ──────────────────────────────────────────────────────────────

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
const BYOK_KEY = "sk-byok-" + "u".repeat(24);
const OPERATOR_KEY = "sk-operator-" + "o".repeat(24);

// ── DO stubs (mirror model-registry.test.ts) ────────────────────────────────

function makeStub(handler: (req: Request) => Promise<Response> | Response) {
  return {
    fetch: async (input: RequestInfo, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input as string, init);
      return handler(req);
    },
  };
}

function makeNamespace(handler: (req: Request) => Promise<Response> | Response): DurableObjectNamespace {
  return {
    idFromName: (_name: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    idFromString: (_s: string) => ({ toString: () => "id" } as unknown as DurableObjectId),
    newUniqueId: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    get: (_id: DurableObjectId) => makeStub(handler) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function makeCtx(): ExecutionContext {
  return {
    waitUntil: (_p: Promise<unknown>) => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
}

function makeAuthNamespace(valid: boolean) {
  const record = {
    token: DAEMON_BEARER,
    token_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-ml-0.1.0",
    account_mode: "byok" as const,
  };
  return makeNamespace(async () =>
    valid
      ? new Response(JSON.stringify({ valid: true, record, reason: null }), {
          headers: { "content-type": "application/json" },
        })
      : new Response(JSON.stringify({ valid: false, record: null, reason: "not_found" }), {
          headers: { "content-type": "application/json" },
        }),
  );
}

function makeTierNamespace() {
  return makeNamespace(async () =>
    new Response(JSON.stringify({ tier: "connected" }), { headers: { "content-type": "application/json" } }),
  );
}

function makeQuotaNamespace(status: 200 | 429) {
  return makeNamespace(async () =>
    status === 429
      ? new Response(JSON.stringify({ reason: "monthly_tasks_exceeded" }), {
          status: 429,
          headers: { "content-type": "application/json" },
        })
      : new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }),
  );
}

function makeEnv(opts: {
  authValid?: boolean;
  quotaStatus?: 200 | 429;
  operatorKeys?: boolean;
  aiGateway?: boolean;
} = {}): Env {
  const base: Record<string, unknown> = {
    AUTH_STORE: makeAuthNamespace(opts.authValid ?? true),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(opts.quotaStatus ?? 200),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
  };
  if (opts.operatorKeys ?? true) {
    base.OPENAI_API_KEY = OPERATOR_KEY;
    base.ANTHROPIC_API_KEY = OPERATOR_KEY;
    base.GEMINI_API_KEY = OPERATOR_KEY;
  }
  if (opts.aiGateway) {
    base.CF_AIG_ACCOUNT = "acct123";
    base.CF_AIG_GATEWAY = "gw456";
    base.CF_AIG_TOKEN = "cf-aig-tok";
  }
  return base as unknown as Env;
}

// ── request helper ───────────────────────────────────────────────────────────

function mlReq(
  provider: string | null,
  opts: { bearer?: string | null; upstreamKey?: string | null } = {},
): Request {
  const headers: Record<string, string> = { accept: "application/json" };
  if (provider !== null) headers["x-bishop-provider"] = provider;
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  const uk = opts.upstreamKey === undefined ? BYOK_KEY : opts.upstreamKey;
  if (uk !== null) headers["x-bishop-upstream-key"] = uk;
  // The inbound path is advisory — the proxy derives the real path from the spec.
  return new Request("http://proxy/v1/models", { method: "GET", headers });
}

// ── fetch-stub plumbing ──────────────────────────────────────────────────────

interface Capture {
  url: string;
  headers: Headers;
}

describe("W38-S935 model-list leg (GET + X-Bishop-Provider)", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  function installFetch(responder: (call: number, url: string) => Response) {
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const headers = input instanceof Request ? input.headers : new Headers(init?.headers);
      captures.push({ url, headers });
      return responder(captures.length - 1, url);
    });
    vi.stubGlobal("fetch", mockFetch);
  }

  function openAiListBody(...ids: string[]): Response {
    return new Response(
      JSON.stringify({ object: "list", data: ids.map((id) => ({ id, object: "model" })) }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }

  beforeEach(() => {
    captures = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── Probe 1: ★ BYOK forward happy ───────────────────────────────────────
  it("★ BYOK forward: deepseek/groq/mistral reach the frozen host + path with the forwarded key as Bearer", async () => {
    const cases: Array<{ provider: string; host: string; path: string }> = [
      { provider: "deepseek", host: "api.deepseek.com", path: "/v1/models" },
      { provider: "groq", host: "api.groq.com", path: "/openai/v1/models" },
      { provider: "mistral", host: "api.mistral.ai", path: "/v1/models" },
      { provider: "fireworks", host: "api.fireworks.ai", path: "/inference/v1/models" },
    ];
    for (const c of cases) {
      captures = [];
      installFetch(() => openAiListBody("model-a", "model-b"));
      const resp = await handleModelList(mlReq(c.provider), makeEnv(), makeCtx());
      expect(resp.status).toBe(200);
      expect(mockFetch).toHaveBeenCalledOnce();
      const u = new URL(captures[0].url);
      expect(u.hostname).toBe(c.host);
      expect(u.pathname).toBe(c.path);
      // Forwarded user key as Bearer; the daemon's device Bearer is NOT forwarded.
      expect(captures[0].headers.get("authorization")).toBe(`Bearer ${BYOK_KEY}`);
      expect(captures[0].headers.get("authorization")).not.toContain(DAEMON_BEARER);
      // The id list is streamed straight back for the daemon to parse.
      const body = (await resp.json()) as { data: Array<{ id: string }> };
      expect(body.data.map((m) => m.id)).toEqual(["model-a", "model-b"]);
      vi.unstubAllGlobals();
    }
  });

  // ── Probe 2: ★ managed providers use the operator key in the right auth shape ──
  it("★ managed: openai=Bearer, claude=x-api-key+version, gemini=?key= — operator key, user key never read", async () => {
    // openai → Bearer operator key
    installFetch(() => openAiListBody("gpt-x"));
    let resp = await handleModelList(mlReq("openai", { upstreamKey: null }), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    let u = new URL(captures[0].url);
    expect(u.hostname).toBe("api.openai.com");
    expect(u.pathname).toBe("/v1/models");
    expect(captures[0].headers.get("authorization")).toBe(`Bearer ${OPERATOR_KEY}`);
    vi.unstubAllGlobals();

    // claude → x-api-key + anthropic-version, NOT Bearer
    captures = [];
    installFetch(() => openAiListBody("claude-x"));
    resp = await handleModelList(mlReq("claude", { upstreamKey: null }), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    u = new URL(captures[0].url);
    expect(u.hostname).toBe("api.anthropic.com");
    expect(captures[0].headers.get("x-api-key")).toBe(OPERATOR_KEY);
    expect(captures[0].headers.get("anthropic-version")).toBe("2023-06-01");
    expect(captures[0].headers.get("authorization")).toBeNull();
    vi.unstubAllGlobals();

    // gemini → ?key= in the URL (native /v1beta/models), no auth header
    captures = [];
    installFetch(
      () =>
        new Response(JSON.stringify({ models: [{ name: "models/gemini-x" }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    resp = await handleModelList(mlReq("gemini", { upstreamKey: null }), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    u = new URL(captures[0].url);
    expect(u.hostname).toBe("generativelanguage.googleapis.com");
    expect(u.pathname).toBe("/v1beta/models");
    expect(u.searchParams.get("key")).toBe(OPERATOR_KEY);
    expect(captures[0].headers.get("authorization")).toBeNull();
    expect(captures[0].headers.get("x-api-key")).toBeNull();
  });

  // ── Probe 3: ★ unknown provider → 404, no forward ───────────────────────
  it("★ unknown provider → 404 unknown_provider; no forward (daemon degrades to bundled)", async () => {
    installFetch(() => new Response("nope", { status: 200 }));
    for (const p of ["github_copilot", "ollama", "openai_codex", "made_up"]) {
      const resp = await handleModelList(mlReq(p), makeEnv(), makeCtx());
      expect(resp.status).toBe(404);
      expect(((await resp.json()) as { error: string }).error).toBe("unknown_provider");
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 4: ★ auth — missing/invalid → 401, no forward ─────────────────
  it("★ auth: missing bearer → 401 missing_bearer; invalid token → 401 token_not_found; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const noBearer = await handleModelList(mlReq("deepseek", { bearer: null }), makeEnv(), makeCtx());
    expect(noBearer.status).toBe(401);
    expect(((await noBearer.json()) as { error: string }).error).toBe("missing_bearer");

    const badToken = await handleModelList(
      mlReq("deepseek", { bearer: "z".repeat(40) }),
      makeEnv({ authValid: false }),
      makeCtx(),
    );
    expect(badToken.status).toBe(401);
    expect(((await badToken.json()) as { error: string }).error).toBe("token_not_found");

    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 5: ★ credential fail-closed ───────────────────────────────────
  it("★ byok_key_missing: forwarded provider w/o upstream key → 400; managed_key_unavailable: managed w/o operator key → 400; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const noByokKey = await handleModelList(mlReq("deepseek", { upstreamKey: null }), makeEnv(), makeCtx());
    expect(noByokKey.status).toBe(400);
    expect(((await noByokKey.json()) as { error: string }).error).toBe("byok_key_missing");

    const noOpKey = await handleModelList(
      mlReq("openai", { upstreamKey: null }),
      makeEnv({ operatorKeys: false }),
      makeCtx(),
    );
    expect(noOpKey.status).toBe(400);
    expect(((await noOpKey.json()) as { error: string }).error).toBe("managed_key_unavailable");

    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 6: ★ REDIRECT-BLOCKED — off-allowlist 3xx → 502, no re-fetch ──
  it("★ redirect-blocked: a 3xx Location to an off-allowlist host → 502, NO re-fetch (open-redirect block)", async () => {
    installFetch((call) => {
      if (call === 0) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://evil-cdn.attacker.example/v1/models" },
        });
      }
      return new Response("LEAKED", { status: 200 });
    });

    const resp = await handleModelList(mlReq("deepseek"), makeEnv(), makeCtx());
    expect(resp.status).toBe(502);
    expect(((await resp.json()) as { error: string }).error).toBe("model_list_redirect_blocked");
    // Exactly ONE fetch — the off-allowlist redirect was refused, never followed.
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  // ── Probe 7: ★ Pillar-1 audit — no credential in logs; valid events ─────
  it("★ Pillar-1: no logEvent line contains the forwarded/operator key; every line is a valid ProxyLogEvent", async () => {
    installFetch(() => openAiListBody("m1"));
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      // A BYOK forward (forwarded key) + a managed forward (operator key).
      await handleModelList(mlReq("groq"), makeEnv(), makeCtx());
      await handleModelList(mlReq("openai", { upstreamKey: null }), makeEnv(), makeCtx());

      for (const call of logSpy.mock.calls) {
        const line = String(call[0]);
        expect(line).not.toContain(BYOK_KEY);
        expect(line).not.toContain(OPERATOR_KEY);
      }
      expect(logSpy.mock.calls.length).toBeGreaterThan(0);
      const allValid = logSpy.mock.calls.every((call) => {
        try {
          return isProxyLogEvent(JSON.parse(String(call[0])));
        } catch {
          return false;
        }
      });
      expect(allValid).toBe(true);
    } finally {
      logSpy.mockRestore();
    }
  });

  // ── Probe 8: quota — /check 429 → 429 passthrough, no forward ───────────
  it("quota: a quota /check 429 → 429 quota_exceeded passthrough; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));
    const resp = await handleModelList(mlReq("deepseek"), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(resp.status).toBe(429);
    expect(((await resp.json()) as { error: string }).error).toBe("quota_exceeded");
    expect(resp.headers.get("X-Bishop-Cap-Type")).toBe("monthly_tasks");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 9: ★ deepseek via Cloudflare AI Gateway when CF_AIG_* is set ───
  it("★ deepseek AI-Gateway: CF_AIG_* set → forwards via gateway.ai.cloudflare.com (/v1 stripped) + cf-aig-authorization", async () => {
    installFetch(() => openAiListBody("deepseek-chat"));
    const resp = await handleModelList(mlReq("deepseek"), makeEnv({ aiGateway: true }), makeCtx());
    expect(resp.status).toBe(200);
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe("gateway.ai.cloudflare.com");
    expect(u.pathname).toBe("/v1/acct123/gw456/deepseek/models");
    expect(captures[0].headers.get("authorization")).toBe(`Bearer ${BYOK_KEY}`);
    expect(captures[0].headers.get("cf-aig-authorization")).toBe("Bearer cf-aig-tok");
  });

  // ── Probe 10: ★ zero-new-egress — every spec host is already allowlisted ──
  it("★ zero-new-egress: every MODEL_LIST_SPECS host ∈ ALLOWED_OUTBOUND_HOSTS (or anchored enterprise)", () => {
    for (const [provider, spec] of Object.entries(MODEL_LIST_SPECS)) {
      const allowed =
        (ALLOWED_OUTBOUND_HOSTS as readonly string[]).includes(spec.upstreamHost) ||
        isAnchoredEnterpriseHost(spec.upstreamHost);
      expect(allowed, `${provider} host ${spec.upstreamHost} must be allowlisted`).toBe(true);
    }
  });
});
