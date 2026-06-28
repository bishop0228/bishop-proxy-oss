/**
 * Behavioral probes for the Gemini Files API passthrough (point/ship large-media
 * upload, leg A): POST /v1beta/files:upload and DELETE /v1beta/files/{id}.
 *
 * Same single-seal §3.2 posture as the generateContent route: the upstream host is
 * FROZEN server-side (generativelanguage.googleapis.com) — never request-derived — and
 * auth is the native x-goog-api-key (managed → operator GEMINI_API_KEY; byok → the
 * user key), never the inbound daemon Bearer. The body is raw bytes, forwarded verbatim
 * (no JSON parse, no classifier). Every probe installs the REAL allowlist interceptor
 * over a stubbed global fetch, so the host gate is exercised genuinely.
 *
 *   (1) ★ upload managed → 200, forwarded to EXACTLY the frozen upload host/path, POST,
 *       body present, x-goog-api-key = operator key, daemon Bearer stripped.
 *   (2) ★ upload byok → x-goog-api-key = the user's x-bishop-upstream-key.
 *   (3) ★ entitlement managed-no-key → 400 managed_key_unavailable, NO forward.
 *   (4) ★ delete → forwarded to the frozen files base + the path-validated id, DELETE,
 *       no body.
 *   (5) ★ bad-token → 401, NO forward.
 *   (6) ★ quota 429 → 429 passthrough, NO forward.
 *   (7) ★ over-cap upload (content-length > leg-A ceiling) → 413, NO forward (leg B).
 *   (8) ★ host-frozen → an attacker X-Bishop-Egress-Target can't redirect the host.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleGeminiFiles } from "../src/routes/gemini-files";
import { installFetchAllowlist, _resetForTesting } from "../src/lib/outbound-allowlist";
import type { Env } from "../src/index";

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
const UPLOAD_HOST = "generativelanguage.googleapis.com";
const OPERATOR_KEY = "operator-gemini-key";
const BYOK_KEY = "user-byok-gemini-key";

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
    refresh_count: 0, client_version: "test-files-0.1.0", account_mode: accountMode,
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
function makeEnv(opts: { authValid?: boolean; quotaStatus?: 200 | 429; accountMode?: "managed" | "byok"; geminiKey?: string | null } = {}): Env {
  return {
    AUTH_STORE: makeAuthNamespace(opts.authValid ?? true, opts.accountMode ?? "managed"),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(opts.quotaStatus ?? 200),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    GEMINI_API_KEY: opts.geminiKey === undefined ? OPERATOR_KEY : (opts.geminiKey ?? undefined),
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
  } as unknown as Env;
}

function uploadReq(opts: { bearer?: string | null; mime?: string; byokKey?: string; contentLength?: string; extraHeaders?: Record<string, string> } = {}): Request {
  const headers: Record<string, string> = { "content-type": opts.mime ?? "application/pdf" };
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  if (opts.byokKey) headers["x-bishop-upstream-key"] = opts.byokKey;
  if (opts.contentLength) headers["content-length"] = opts.contentLength;
  Object.assign(headers, opts.extraHeaders ?? {});
  return new Request(`http://proxy/v1beta/files:upload`, { method: "POST", headers, body: "RAW-MEDIA-BYTES" });
}
function deleteReq(fileId = "files/abc", bearer: string | null = DAEMON_BEARER): Request {
  const headers: Record<string, string> = {};
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  return new Request(`http://proxy/v1beta/${fileId}`, { method: "DELETE", headers });
}

interface Capture { url: string; headers: Headers; method: string; hasBody: boolean }

describe("Gemini Files API passthrough (POST /v1beta/files:upload, DELETE /v1beta/files/{id})", () => {
  let captures: Capture[];
  let mockFetch: ReturnType<typeof vi.fn>;

  function installFetch() {
    mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const headers = input instanceof Request ? input.headers : new Headers(init?.headers);
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")) || "GET";
      const hasBody = (init?.body ?? (input instanceof Request ? input.body : null)) != null;
      captures.push({ url, headers, method, hasBody });
      return new Response(JSON.stringify({ file: { uri: "https://x/files/abc", name: "files/abc" } }), { status: 200, headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", mockFetch);
    installFetchAllowlist();
  }

  beforeEach(() => { captures = []; });
  afterEach(() => { _resetForTesting(); vi.unstubAllGlobals(); });

  it("★ upload managed: 200, forwarded to EXACTLY the frozen upload host/path; POST; body present; operator key; daemon Bearer stripped", async () => {
    installFetch();
    const resp = await handleGeminiFiles(uploadReq(), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe(UPLOAD_HOST);
    expect(u.pathname).toBe("/upload/v1beta/files");
    expect(captures[0].method.toUpperCase()).toBe("POST");
    expect(captures[0].hasBody).toBe(true);
    const fwd = captures[0].headers;
    expect(fwd.get("x-goog-api-key")).toBe(OPERATOR_KEY);
    expect(fwd.get("authorization")).toBeNull();          // daemon Bearer never leaks (Pillar 1)
    expect(fwd.get("content-type")).toBe("application/pdf"); // the mime is preserved
  });

  it("★ upload byok: x-goog-api-key = the user's key (never the inbound Bearer)", async () => {
    installFetch();
    const resp = await handleGeminiFiles(
      uploadReq({ byokKey: BYOK_KEY, mime: "image/png" }),
      makeEnv({ accountMode: "byok" }), makeCtx());
    expect(resp.status).toBe(200);
    expect(captures[0].headers.get("x-goog-api-key")).toBe(BYOK_KEY);
  });

  it("★ entitlement managed-no-key: 400 managed_key_unavailable, NO forward (never reads inbound key)", async () => {
    installFetch();
    const resp = await handleGeminiFiles(uploadReq(), makeEnv({ geminiKey: null }), makeCtx());
    expect(resp.status).toBe(400);
    expect(((await resp.json()) as { error: string }).error).toBe("managed_key_unavailable");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ delete: forwarded to the frozen files base + path-validated id, DELETE, no body", async () => {
    installFetch();
    const resp = await handleGeminiFiles(deleteReq("files/abc"), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe(UPLOAD_HOST);
    expect(u.pathname).toBe("/v1beta/files/abc");
    expect(captures[0].method.toUpperCase()).toBe("DELETE");
    expect(captures[0].hasBody).toBe(false);
  });

  it("★ bad-token: missing bearer → 401, NO forward", async () => {
    installFetch();
    const resp = await handleGeminiFiles(uploadReq({ bearer: null }), makeEnv(), makeCtx());
    expect(resp.status).toBe(401);
    expect(((await resp.json()) as { error: string }).error).toBe("missing_bearer");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ quota 429 → 429 passthrough, NO forward", async () => {
    installFetch();
    const resp = await handleGeminiFiles(uploadReq(), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(resp.status).toBe(429);
    expect(((await resp.json()) as { error: string }).error).toBe("quota_exceeded");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ over-cap upload (content-length > leg-A ceiling) → 413, NO forward (leg B's job)", async () => {
    installFetch();
    const tooBig = String(100 * 1024 * 1024 + 1);
    const resp = await handleGeminiFiles(uploadReq({ contentLength: tooBig }), makeEnv(), makeCtx());
    expect(resp.status).toBe(413);
    expect(((await resp.json()) as { error: string }).error).toBe("upload_too_large");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("★ host-frozen: an attacker X-Bishop-Egress-Target does NOT redirect the upload host", async () => {
    installFetch();
    const resp = await handleGeminiFiles(
      uploadReq({ extraHeaders: { "x-bishop-egress-target": "https://evil-cdn.attacker.example/exfil" } }),
      makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(new URL(captures[0].url).hostname).toBe(UPLOAD_HOST);
    expect(new URL(captures[0].url).hostname).not.toBe("evil-cdn.attacker.example");
  });
});
