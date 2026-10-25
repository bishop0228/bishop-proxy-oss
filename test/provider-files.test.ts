/**
 * Behavioral probes for the OpenAI + Anthropic Files API passthrough (point/ship
 * large-media upload, leg A — provider-agnostic): POST /v1/<provider>/files and
 * DELETE /v1/<provider>/files/{id}.
 *
 * Same single-seal §3.2 posture as the Gemini route: upstream host FROZEN server-side
 * (api.openai.com / api.anthropic.com) — never request-derived; the upstream key is the
 * operator's for a managed Anthropic upload and the user's x-bishop-upstream-key for a
 * byok one; the inbound daemon Bearer never leaks. Multipart body forwarded verbatim (no
 * JSON parse, no classifier). Every probe installs the REAL allowlist interceptor over a
 * stubbed fetch, so the host gate is genuine.
 *
 *   (1) ★ OpenAI upload managed → 403 managed_not_offered, NO forward (W38-S1165: a managed
 *       device's included models are Anthropic's), with or without an operator key bound.
 *   (2) ★ Anthropic upload managed → 200, api.anthropic.com/v1/files, x-api-key=operator,
 *       anthropic-beta forwarded, daemon Bearer NOT forwarded; counted against the month's
 *       upload limit before it is forwarded (W38-S1165).
 *   (3) ★ the limit: over it → 429, NO forward; a managed upload that does not say its size
 *       → 411; one the provider refuses is given back; a byok upload is not counted.
 *   (4) ★ W38-S1168: a paying byok device's keyless Anthropic upload is served and counted as
 *       managed; with its own key it uses that key; a free byok device keeps byok_key_missing.
 *   (5) ★ byok (both) → upstream key = the user's x-bishop-upstream-key.
 *   (6) ★ delete (both) → .../v1/files/{id}, DELETE, no body; a delete is not counted.
 *   (7) ★ bad-token / quota 429 / over-cap 413 / host-frozen — fail-closed, NO forward.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleProviderFiles } from "../src/routes/provider-files";
import { installFetchAllowlist, _resetForTesting } from "../src/lib/outbound-allowlist";
import type { Env } from "../src/index";

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
const OPENAI_KEY = "operator-openai-key";
const ANTHROPIC_KEY = "operator-anthropic-key";
const BYOK_KEY = "user-byok-key";
const BODY = "----bishopBOUNDARY\r\nRAW-MEDIA\r\n";
const BODY_LEN = String(new TextEncoder().encode(BODY).length);
const PERIOD = "2026-10";

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
    idFromName: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    idFromString: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    newUniqueId: () => ({ toString: () => "id" } as unknown as DurableObjectId),
    get: () => makeStub(handler) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}
function makeCtx(): ExecutionContext {
  return { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;
}
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
function makeAuthNamespace(valid: boolean, accountMode: "managed" | "byok" = "managed") {
  const record = {
    token: DAEMON_BEARER, token_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    issued_at: "2026-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32), status: "active", last_seen: null,
    refresh_count: 0, client_version: "test-pfiles-0.1.0", account_mode: accountMode,
  };
  return makeNamespace(async () =>
    valid
      ? json({ valid: true, record, reason: null })
      : json({ valid: false, record: null, reason: "not_found" }));
}
function makeTierNamespace(tier: "free" | "solo" | "studio") {
  return makeNamespace(async () => json({ tier }));
}

interface QuotaCall { path: string; body: Record<string, unknown> }

/** The quota store, routed by path: /check answers `status`, /upload-reserve fits unless `full`, /upload-release is
 *  recorded. Every call lands in `calls`. */
function makeQuotaNamespace(status: 200 | 429, full: boolean, calls: QuotaCall[]) {
  return makeNamespace(async (req) => {
    const path = new URL(req.url).pathname;
    const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    calls.push({ path, body });
    if (path === "/check") {
      return status === 429 ? json({ reason: "monthly_tasks_exceeded" }, 429) : json({ ok: true });
    }
    if (path === "/upload-reserve") {
      return full ? json({ ok: false, reason: "monthly_uploads_exceeded" }, 429) : json({ ok: true, period_month: PERIOD });
    }
    return json({ ok: true });
  });
}
function makeEnv(opts: {
  authValid?: boolean; quotaStatus?: 200 | 429; accountMode?: "managed" | "byok"; openaiKey?: string | null;
  tier?: "free" | "solo" | "studio"; full?: boolean; calls?: QuotaCall[];
} = {}): Env {
  return {
    AUTH_STORE: makeAuthNamespace(opts.authValid ?? true, opts.accountMode ?? "managed"),
    TIER_CACHE: makeTierNamespace(opts.tier ?? "free"),
    QUOTA_STORE: makeQuotaNamespace(opts.quotaStatus ?? 200, opts.full ?? false, opts.calls ?? []),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: ANTHROPIC_KEY,
    OPENAI_API_KEY: opts.openaiKey === undefined ? OPENAI_KEY : (opts.openaiKey ?? undefined),
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
  } as unknown as Env;
}

const MULTIPART = "multipart/form-data; boundary=----bishopBOUNDARY";

function uploadReq(provider: "openai" | "anthropic", opts: { bearer?: string | null; byokKey?: string; contentLength?: string | null; extraHeaders?: Record<string, string> } = {}): Request {
  const headers: Record<string, string> = { "content-type": MULTIPART };
  if (provider === "anthropic") {
    headers["anthropic-beta"] = "files-api-2025-04-14";
    headers["anthropic-version"] = "2023-06-01";
  }
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  if (opts.byokKey) headers["x-bishop-upstream-key"] = opts.byokKey;
  // The declared size, as the daemon sends it; null leaves it out.
  const length = opts.contentLength === undefined ? BODY_LEN : opts.contentLength;
  if (length !== null) headers["content-length"] = length;
  Object.assign(headers, opts.extraHeaders ?? {});
  return new Request(`http://proxy/v1/${provider}/files`, { method: "POST", headers, body: BODY });
}
function deleteReq(provider: "openai" | "anthropic", fileId: string, byokKey?: string): Request {
  const headers: Record<string, string> = { authorization: `Bearer ${DAEMON_BEARER}` };
  if (byokKey) headers["x-bishop-upstream-key"] = byokKey;
  return new Request(`http://proxy/v1/${provider}/files/${fileId}`, { method: "DELETE", headers });
}

interface Capture { url: string; headers: Headers; method: string; hasBody: boolean }

describe("OpenAI + Anthropic Files API passthrough (/v1/<provider>/files)", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  function installFetch(upstreamStatus = 200) {
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const headers = input instanceof Request ? input.headers : new Headers(init?.headers);
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")) || "GET";
      const hasBody = (init?.body ?? (input instanceof Request ? input.body : null)) != null;
      captures.push({ url, headers, method, hasBody });
      return json(upstreamStatus === 200 ? { id: "file-abc" } : { error: "upstream" }, upstreamStatus);
    });
    vi.stubGlobal("fetch", mockFetch);
    installFetchAllowlist();
  }
  const reserves = (calls: QuotaCall[]) => calls.filter((c) => c.path === "/upload-reserve");
  const releases = (calls: QuotaCall[]) => calls.filter((c) => c.path === "/upload-release");

  beforeEach(() => { captures = []; });
  afterEach(() => { _resetForTesting(); vi.unstubAllGlobals(); });

  it("★ OpenAI upload managed: 403 managed_not_offered, NO forward, with or without an operator key (W38-S1165)", async () => {
    installFetch();
    for (const openaiKey of [undefined, null]) {
      const resp = await handleProviderFiles(uploadReq("openai"), makeEnv({ openaiKey }), makeCtx());
      expect(resp.status).toBe(403);
      expect(((await resp.json()) as { error: string }).error).toBe("managed_not_offered");
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ OpenAI upload byok: 200, api.openai.com/v1/files, POST, body, Bearer = the user's key, multipart preserved", async () => {
    installFetch();
    const resp = await handleProviderFiles(uploadReq("openai", { byokKey: BYOK_KEY }), makeEnv({ accountMode: "byok" }), makeCtx());
    expect(resp.status).toBe(200);
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe("api.openai.com");
    expect(u.pathname).toBe("/v1/files");
    expect(captures[0].method.toUpperCase()).toBe("POST");
    expect(captures[0].hasBody).toBe(true);
    const fwd = captures[0].headers;
    expect(fwd.get("authorization")).toBe(`Bearer ${BYOK_KEY}`); // the user's key, NOT the daemon Bearer
    expect(fwd.get("content-type")).toBe(MULTIPART);              // boundary preserved
  });

  it("★ Anthropic upload managed: 200, api.anthropic.com/v1/files, x-api-key=operator, anthropic-beta forwarded, daemon Bearer NOT forwarded; reserved before it is sent", async () => {
    installFetch();
    const calls: QuotaCall[] = [];
    const resp = await handleProviderFiles(uploadReq("anthropic"), makeEnv({ calls }), makeCtx());
    expect(resp.status).toBe(200);
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe("api.anthropic.com");
    expect(u.pathname).toBe("/v1/files");
    const fwd = captures[0].headers;
    expect(fwd.get("x-api-key")).toBe(ANTHROPIC_KEY);
    expect(fwd.get("anthropic-beta")).toBe("files-api-2025-04-14");
    expect(fwd.get("authorization")).toBeNull(); // daemon Bearer never leaks (Pillar 1)
    expect(fwd.get("content-type")).toBe(MULTIPART);
    expect(reserves(calls)).toEqual([{ path: "/upload-reserve", body: { tier: "free", bytes: Number(BODY_LEN) } }]);
    expect(releases(calls)).toEqual([]); // taken by the provider: stays counted
  });

  it("★ over the month's upload limit: 429 upload_limit_reached, NO forward (W38-S1165)", async () => {
    installFetch();
    const resp = await handleProviderFiles(uploadReq("anthropic"), makeEnv({ full: true }), makeCtx());
    expect(resp.status).toBe(429);
    const body = (await resp.json()) as { error: string; reason: string };
    expect(body.error).toBe("upload_limit_reached");
    expect(body.reason).toBe("monthly_uploads_exceeded");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ a managed upload that does not say its size: 411 length_required, NO forward, nothing reserved", async () => {
    installFetch();
    const calls: QuotaCall[] = [];
    const resp = await handleProviderFiles(uploadReq("anthropic", { contentLength: null }), makeEnv({ calls }), makeCtx());
    expect(resp.status).toBe(411);
    expect(((await resp.json()) as { error: string }).error).toBe("length_required");
    expect(mockFetch).not.toHaveBeenCalled();
    expect(reserves(calls)).toEqual([]);
  });

  it("★ an upload the provider refuses is given back, for the month it was counted in", async () => {
    installFetch(500);
    const calls: QuotaCall[] = [];
    const resp = await handleProviderFiles(uploadReq("anthropic"), makeEnv({ calls }), makeCtx());
    expect(resp.status).toBe(500);
    expect(releases(calls)).toEqual([{ path: "/upload-release", body: { bytes: Number(BODY_LEN), period_month: PERIOD } }]);
  });

  it("★ an upload whose forward throws is given back, and the error still reaches the caller", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network down"); }));
    installFetchAllowlist();
    const calls: QuotaCall[] = [];
    await expect(handleProviderFiles(uploadReq("anthropic"), makeEnv({ calls }), makeCtx())).rejects.toThrow("network down");
    expect(releases(calls)).toEqual([{ path: "/upload-release", body: { bytes: Number(BODY_LEN), period_month: PERIOD } }]);
  });

  it("★ a byok upload is not counted", async () => {
    installFetch();
    const calls: QuotaCall[] = [];
    const resp = await handleProviderFiles(uploadReq("anthropic", { byokKey: BYOK_KEY }), makeEnv({ accountMode: "byok", calls }), makeCtx());
    expect(resp.status).toBe(200);
    expect(reserves(calls)).toEqual([]);
  });

  it("★ W38-S1168: a paying byok device's keyless Anthropic upload is served with the operator key and counted as managed", async () => {
    installFetch();
    const calls: QuotaCall[] = [];
    const resp = await handleProviderFiles(uploadReq("anthropic"), makeEnv({ accountMode: "byok", tier: "solo", calls }), makeCtx());
    expect(resp.status).toBe(200);
    expect(captures[0].headers.get("x-api-key")).toBe(ANTHROPIC_KEY);
    expect(calls.find((c) => c.path === "/check")?.body.account_mode).toBe("managed");
    expect(reserves(calls)).toEqual([{ path: "/upload-reserve", body: { tier: "solo", bytes: Number(BODY_LEN) } }]);
  });

  it("★ W38-S1168 CONTROL: with its own key, a paying byok device uses that key, uncounted", async () => {
    installFetch();
    const calls: QuotaCall[] = [];
    const resp = await handleProviderFiles(uploadReq("anthropic", { byokKey: BYOK_KEY }), makeEnv({ accountMode: "byok", tier: "solo", calls }), makeCtx());
    expect(resp.status).toBe(200);
    expect(captures[0].headers.get("x-api-key")).toBe(BYOK_KEY);
    expect(calls.find((c) => c.path === "/check")?.body.account_mode).toBe("byok");
    expect(reserves(calls)).toEqual([]);
  });

  it("★ W38-S1168 CONTROL: a free byok device's keyless upload keeps today's meaning, 400 byok_key_missing", async () => {
    installFetch();
    const resp = await handleProviderFiles(uploadReq("anthropic"), makeEnv({ accountMode: "byok", tier: "free" }), makeCtx());
    expect(resp.status).toBe(400);
    expect(((await resp.json()) as { error: string }).error).toBe("byok_key_missing");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ byok: upstream key = the user's x-bishop-upstream-key (openai Bearer + anthropic x-api-key)", async () => {
    installFetch();
    const o = await handleProviderFiles(uploadReq("openai", { byokKey: BYOK_KEY }), makeEnv({ accountMode: "byok" }), makeCtx());
    expect(o.status).toBe(200);
    expect(captures[0].headers.get("authorization")).toBe(`Bearer ${BYOK_KEY}`);
    captures = [];
    const a = await handleProviderFiles(uploadReq("anthropic", { byokKey: BYOK_KEY }), makeEnv({ accountMode: "byok" }), makeCtx());
    expect(a.status).toBe(200);
    expect(captures[0].headers.get("x-api-key")).toBe(BYOK_KEY);
  });

  it("★ delete (both): forwarded to .../v1/files/{id}, DELETE, no body; not counted", async () => {
    installFetch();
    const o = await handleProviderFiles(deleteReq("openai", "file-abc", BYOK_KEY), makeEnv({ accountMode: "byok" }), makeCtx());
    expect(o.status).toBe(200);
    expect(new URL(captures[0].url).pathname).toBe("/v1/files/file-abc");
    expect(captures[0].method.toUpperCase()).toBe("DELETE");
    expect(captures[0].hasBody).toBe(false);
    captures = [];
    const calls: QuotaCall[] = [];
    const a = await handleProviderFiles(deleteReq("anthropic", "file_011abc"), makeEnv({ calls }), makeCtx());
    expect(a.status).toBe(200);
    expect(new URL(captures[0].url).hostname).toBe("api.anthropic.com");
    expect(new URL(captures[0].url).pathname).toBe("/v1/files/file_011abc");
    expect(reserves(calls)).toEqual([]);
  });

  it("★ bad-token / quota 429 / over-cap 413 / host-frozen: fail-closed, NO forward", async () => {
    // bad token
    installFetch();
    const bad = await handleProviderFiles(uploadReq("anthropic", { bearer: null }), makeEnv(), makeCtx());
    expect(bad.status).toBe(401);
    expect(mockFetch).not.toHaveBeenCalled();

    // quota 429
    captures = [];
    const q = await handleProviderFiles(uploadReq("anthropic"), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(q.status).toBe(429);
    expect(mockFetch).not.toHaveBeenCalled();

    // over the leg-A ceiling → 413, before anything is reserved
    captures = [];
    const calls: QuotaCall[] = [];
    const big = await handleProviderFiles(uploadReq("anthropic", { contentLength: String(100 * 1024 * 1024 + 1) }), makeEnv({ calls }), makeCtx());
    expect(big.status).toBe(413);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(reserves(calls)).toEqual([]);

    // host-frozen — an attacker target header can't redirect the host
    captures = [];
    const hf = await handleProviderFiles(uploadReq("anthropic", { extraHeaders: { "x-bishop-egress-target": "https://evil.example/exfil" } }), makeEnv(), makeCtx());
    expect(hf.status).toBe(200);
    expect(new URL(captures[0].url).hostname).toBe("api.anthropic.com");
  });
});
