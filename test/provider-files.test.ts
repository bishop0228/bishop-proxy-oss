/**
 * Behavioral probes for the OpenAI + Anthropic Files API passthrough (point/ship
 * large-media upload, leg A — provider-agnostic): POST /v1/<provider>/files and
 * DELETE /v1/<provider>/files/{id}.
 *
 * Same single-seal §3.2 posture as the Gemini route: upstream host FROZEN server-side
 * (api.openai.com / api.anthropic.com) — never request-derived; operator key
 * substituted (managed → operator, byok → the user's x-bishop-upstream-key); the
 * inbound daemon Bearer never leaks. Multipart body forwarded verbatim (no JSON parse,
 * no classifier). Every probe installs the REAL allowlist interceptor over a stubbed
 * fetch, so the host gate is genuine.
 *
 *   (1) ★ OpenAI upload managed → 200, api.openai.com/v1/files, POST, body present,
 *       Authorization=Bearer <operator>, multipart content-type preserved.
 *   (2) ★ Anthropic upload managed → 200, api.anthropic.com/v1/files, x-api-key=operator,
 *       anthropic-beta forwarded, daemon Bearer NOT forwarded.
 *   (3) ★ byok (both) → upstream key = the user's x-bishop-upstream-key.
 *   (4) ★ OpenAI managed-no-key → 400 managed_key_unavailable, NO forward.
 *   (5) ★ delete (both) → .../v1/files/{id}, DELETE, no body.
 *   (6) ★ bad-token / quota 429 / over-cap 413 / host-frozen — fail-closed, NO forward.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleProviderFiles } from "../src/routes/provider-files";
import { installFetchAllowlist, _resetForTesting } from "../src/lib/outbound-allowlist";
import type { Env } from "../src/index";

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
const OPENAI_KEY = "operator-openai-key";
const ANTHROPIC_KEY = "operator-anthropic-key";
const BYOK_KEY = "user-byok-key";

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
function makeAuthNamespace(valid: boolean, accountMode: "managed" | "byok" = "managed") {
  const record = {
    token: DAEMON_BEARER, token_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    issued_at: "2026-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32), status: "active", last_seen: null,
    refresh_count: 0, client_version: "test-pfiles-0.1.0", account_mode: accountMode,
  };
  return makeNamespace(async () =>
    valid
      ? new Response(JSON.stringify({ valid: true, record, reason: null }), { headers: { "content-type": "application/json" } })
      : new Response(JSON.stringify({ valid: false, record: null, reason: "not_found" }), { headers: { "content-type": "application/json" } }));
}
function makeTierNamespace() {
  return makeNamespace(async () => new Response(JSON.stringify({ tier: "free" }), { headers: { "content-type": "application/json" } }));
}
function makeQuotaNamespace(status: 200 | 429) {
  return makeNamespace(async () =>
    status === 429
      ? new Response(JSON.stringify({ reason: "monthly_tasks_exceeded" }), { status: 429, headers: { "content-type": "application/json" } })
      : new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }));
}
function makeEnv(opts: { authValid?: boolean; quotaStatus?: 200 | 429; accountMode?: "managed" | "byok"; openaiKey?: string | null } = {}): Env {
  return {
    AUTH_STORE: makeAuthNamespace(opts.authValid ?? true, opts.accountMode ?? "managed"),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(opts.quotaStatus ?? 200),
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

function uploadReq(provider: "openai" | "anthropic", opts: { bearer?: string | null; byokKey?: string; contentLength?: string; extraHeaders?: Record<string, string> } = {}): Request {
  const headers: Record<string, string> = { "content-type": MULTIPART };
  if (provider === "anthropic") {
    headers["anthropic-beta"] = "files-api-2025-04-14";
    headers["anthropic-version"] = "2023-06-01";
  }
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  if (opts.byokKey) headers["x-bishop-upstream-key"] = opts.byokKey;
  if (opts.contentLength) headers["content-length"] = opts.contentLength;
  Object.assign(headers, opts.extraHeaders ?? {});
  return new Request(`http://proxy/v1/${provider}/files`, { method: "POST", headers, body: "----bishopBOUNDARY\r\nRAW-MEDIA\r\n" });
}
function deleteReq(provider: "openai" | "anthropic", fileId: string): Request {
  return new Request(`http://proxy/v1/${provider}/files/${fileId}`, { method: "DELETE", headers: { authorization: `Bearer ${DAEMON_BEARER}` } });
}

interface Capture { url: string; headers: Headers; method: string; hasBody: boolean }

describe("OpenAI + Anthropic Files API passthrough (/v1/<provider>/files)", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  function installFetch() {
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const headers = input instanceof Request ? input.headers : new Headers(init?.headers);
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")) || "GET";
      const hasBody = (init?.body ?? (input instanceof Request ? input.body : null)) != null;
      captures.push({ url, headers, method, hasBody });
      return new Response(JSON.stringify({ id: "file-abc" }), { status: 200, headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", mockFetch);
    installFetchAllowlist();
  }

  beforeEach(() => { captures = []; });
  afterEach(() => { _resetForTesting(); vi.unstubAllGlobals(); });

  it("★ OpenAI upload managed: 200, api.openai.com/v1/files, POST, body, Bearer=operator, multipart preserved", async () => {
    installFetch();
    const resp = await handleProviderFiles(uploadReq("openai"), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe("api.openai.com");
    expect(u.pathname).toBe("/v1/files");
    expect(captures[0].method.toUpperCase()).toBe("POST");
    expect(captures[0].hasBody).toBe(true);
    const fwd = captures[0].headers;
    expect(fwd.get("authorization")).toBe(`Bearer ${OPENAI_KEY}`); // operator key, NOT the daemon Bearer
    expect(fwd.get("content-type")).toBe(MULTIPART);               // boundary preserved
  });

  it("★ Anthropic upload managed: 200, api.anthropic.com/v1/files, x-api-key=operator, anthropic-beta forwarded, daemon Bearer NOT forwarded", async () => {
    installFetch();
    const resp = await handleProviderFiles(uploadReq("anthropic"), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe("api.anthropic.com");
    expect(u.pathname).toBe("/v1/files");
    const fwd = captures[0].headers;
    expect(fwd.get("x-api-key")).toBe(ANTHROPIC_KEY);
    expect(fwd.get("anthropic-beta")).toBe("files-api-2025-04-14");
    expect(fwd.get("authorization")).toBeNull(); // daemon Bearer never leaks (Pillar 1)
    expect(fwd.get("content-type")).toBe(MULTIPART);
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

  it("★ OpenAI managed-no-key: 400 managed_key_unavailable, NO forward", async () => {
    installFetch();
    const resp = await handleProviderFiles(uploadReq("openai"), makeEnv({ openaiKey: null }), makeCtx());
    expect(resp.status).toBe(400);
    expect(((await resp.json()) as { error: string }).error).toBe("managed_key_unavailable");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ delete (both): forwarded to .../v1/files/{id}, DELETE, no body", async () => {
    installFetch();
    const o = await handleProviderFiles(deleteReq("openai", "file-abc"), makeEnv(), makeCtx());
    expect(o.status).toBe(200);
    expect(new URL(captures[0].url).pathname).toBe("/v1/files/file-abc");
    expect(captures[0].method.toUpperCase()).toBe("DELETE");
    expect(captures[0].hasBody).toBe(false);
    captures = [];
    const a = await handleProviderFiles(deleteReq("anthropic", "file_011abc"), makeEnv(), makeCtx());
    expect(a.status).toBe(200);
    expect(new URL(captures[0].url).hostname).toBe("api.anthropic.com");
    expect(new URL(captures[0].url).pathname).toBe("/v1/files/file_011abc");
  });

  it("★ bad-token / quota 429 / over-cap 413 / host-frozen: fail-closed, NO forward", async () => {
    // bad token
    installFetch();
    const bad = await handleProviderFiles(uploadReq("openai", { bearer: null }), makeEnv(), makeCtx());
    expect(bad.status).toBe(401);
    expect(mockFetch).not.toHaveBeenCalled();

    // quota 429
    captures = [];
    const q = await handleProviderFiles(uploadReq("openai"), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(q.status).toBe(429);
    expect(mockFetch).not.toHaveBeenCalled();

    // over the leg-A ceiling → 413
    captures = [];
    const big = await handleProviderFiles(uploadReq("anthropic", { contentLength: String(100 * 1024 * 1024 + 1) }), makeEnv(), makeCtx());
    expect(big.status).toBe(413);
    expect(mockFetch).not.toHaveBeenCalled();

    // host-frozen — an attacker target header can't redirect the host
    captures = [];
    const hf = await handleProviderFiles(uploadReq("openai", { extraHeaders: { "x-bishop-egress-target": "https://evil.example/exfil" } }), makeEnv(), makeCtx());
    expect(hf.status).toBe(200);
    expect(new URL(captures[0].url).hostname).toBe("api.openai.com");
  });
});
