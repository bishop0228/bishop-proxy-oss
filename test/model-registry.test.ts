/**
 * Behavioral probes for the B1 governed model-registry egress leg
 * (GET /model-registry/<path>).
 *
 * The §3.2 read-only operational-egress path for Ollama public model-registry
 * lookups. Unit-style (handleModelRegistry + stubbed global fetch + DO stubs) so
 * the redirect legs are deterministic and no real network is touched:
 *
 *   (1) ★ forward happy — valid bearer + /v2/ path → 200, forwards to EXACTLY the
 *       frozen registry host; the daemon Bearer is NEVER forwarded upstream
 *       (Pillar 1 identifier-strip — anonymous public registry).
 *   (2) ★ auth — no Bearer → 401 missing_bearer; bad token → 401 token_not_found;
 *       fetch NOT called.
 *   (3) ★ path-guard — a non-/v2/ path → 404 model_registry_path_not_allowed;
 *       fetch NOT called.
 *   (4) ★ REDIRECT-BLOCKED — a 3xx to an off-allowlist host → 502
 *       model_registry_redirect_blocked, NO re-fetch (open-redirect → exfil block).
 *   (5) redirect-allowed — a 3xx to an allow-listed host → re-fetched explicitly,
 *       final 200 streamed back (2 fetches; 2nd hop = the allow-listed host).
 *   (6) ★ Pillar-1 audit — no logEvent line contains the daemon Bearer; every
 *       line is a valid ProxyLogEvent.
 *   (7) quota — quota /check 429 → 429 quota_exceeded passthrough, fetch NOT called.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleModelRegistry } from "../src/routes/model-registry";
import { isProxyLogEvent } from "../src/lib/log";
import type { Env } from "../src/index";

// ── constants ──────────────────────────────────────────────────────────────

const DAEMON_BEARER = "bsk_staging_" + "v".repeat(24);
const REGISTRY_HOST = "registry.ollama.ai";
const MANIFEST_PATH = "/model-registry/v2/library/llama3/manifests/latest";

// ── DO stubs (mirror the unit-style env helpers in mcp.test.ts) ─────────────

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
    token: "bsk_staging_" + "v".repeat(24),
    token_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    fingerprint_hash: "cc".repeat(32),
    status: "active",
    last_seen: null,
    refresh_count: 0,
    client_version: "test-mr-0.1.0",
    account_mode: "managed" as const,
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
    new Response(JSON.stringify({ tier: "free" }), { headers: { "content-type": "application/json" } }),
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

function makeEnv(opts: { authValid?: boolean; quotaStatus?: 200 | 429 } = {}): Env {
  return {
    AUTH_STORE: makeAuthNamespace(opts.authValid ?? true),
    TIER_CACHE: makeTierNamespace(),
    QUOTA_STORE: makeQuotaNamespace(opts.quotaStatus ?? 200),
    ENROLL_KV: {} as KVNamespace,
    STRIPE_WEBHOOK_SECRET: "test_secret",
    ANTHROPIC_API_KEY: "test_key",
    USER_INDEX_HMAC_KEY: "test_hmac_key",
    ADMIN_TOKEN: "test_admin",
    MOCK_AI: "1",
  } as unknown as Env;
}

// ── request helper ───────────────────────────────────────────────────────────

function mrReq(path: string, opts: { bearer?: string | null } = {}): Request {
  const headers: Record<string, string> = {
    accept: "application/vnd.oci.image.manifest.v1+json",
  };
  const bearer = opts.bearer === undefined ? DAEMON_BEARER : opts.bearer;
  if (bearer !== null) headers["authorization"] = `Bearer ${bearer}`;
  return new Request(`http://proxy${path}`, { method: "GET", headers });
}

// ── fetch-stub plumbing ──────────────────────────────────────────────────────

interface Capture {
  url: string;
  headers: Headers;
}

describe("B1 model-registry egress leg (GET /model-registry/<path>)", () => {
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

  beforeEach(() => {
    captures = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── Probe 1: ★ forward happy + Pillar-1 daemon-bearer strip ─────────────
  it("★ forward: /v2/ GET reaches EXACTLY the frozen registry host; daemon Bearer NOT forwarded", async () => {
    installFetch(() =>
      new Response(JSON.stringify({ schemaVersion: 2 }), {
        status: 200,
        headers: { "content-type": "application/vnd.oci.image.manifest.v1+json", "content-length": "21" },
      }),
    );

    const resp = await handleModelRegistry(mrReq(MANIFEST_PATH), makeEnv(), makeCtx());
    expect(resp.status).toBe(200);
    expect(mockFetch).toHaveBeenCalledOnce();

    // Forwarded to EXACTLY the frozen host + the /v2/ sub-path (host never request-derived).
    const u = new URL(captures[0].url);
    expect(u.hostname).toBe(REGISTRY_HOST);
    expect(u.pathname).toBe("/v2/library/llama3/manifests/latest");

    // Pillar 1 — the daemon Bearer is NEVER forwarded upstream (anonymous registry).
    expect(captures[0].headers.get("authorization")).toBeNull();
    // accept survives for media-type negotiation.
    expect(captures[0].headers.get("accept")).toContain("oci.image.manifest");

    // content-type + content-length preserved on the streamed response.
    expect(resp.headers.get("content-type")).toContain("oci.image.manifest");
    expect(resp.headers.get("content-length")).toBe("21");
  });

  // ── Probe 2: ★ auth — no bearer / invalid token → 401; no forward ───────
  it("★ auth: missing bearer → 401 missing_bearer; invalid token → 401 token_not_found; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const noBearer = await handleModelRegistry(mrReq(MANIFEST_PATH, { bearer: null }), makeEnv(), makeCtx());
    expect(noBearer.status).toBe(401);
    expect(((await noBearer.json()) as { error: string }).error).toBe("missing_bearer");

    const badToken = await handleModelRegistry(
      mrReq(MANIFEST_PATH, { bearer: "z".repeat(40) }),
      makeEnv({ authValid: false }),
      makeCtx(),
    );
    expect(badToken.status).toBe(401);
    expect(((await badToken.json()) as { error: string }).error).toBe("token_not_found");

    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 3: ★ path-guard — non-/v2/ path → 404; no forward ─────────────
  it("★ path-guard: a non-/v2/ path → 404 model_registry_path_not_allowed; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    for (const bad of ["/model-registry/v1/library/llama3", "/model-registry/secrets", "/model-registry/"]) {
      const resp = await handleModelRegistry(mrReq(bad), makeEnv(), makeCtx());
      expect(resp.status).toBe(404);
      expect(((await resp.json()) as { error: string }).error).toBe("model_registry_path_not_allowed");
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── Probe 4: ★ REDIRECT-BLOCKED — off-allowlist 3xx → 502, no re-fetch ──
  it("★ redirect-blocked: a 3xx Location to an off-allowlist host → 502, NO re-fetch", async () => {
    installFetch((call) => {
      if (call === 0) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://evil-cdn.attacker.example/blobs/sha256:abc" },
        });
      }
      // A re-fetch MUST NOT happen — if it does, surface it loudly as a 200.
      return new Response("LEAKED", { status: 200 });
    });

    const resp = await handleModelRegistry(
      mrReq("/model-registry/v2/library/llama3/blobs/sha256:abc"),
      makeEnv(),
      makeCtx(),
    );
    expect(resp.status).toBe(502);
    expect(((await resp.json()) as { error: string }).error).toBe("model_registry_redirect_blocked");
    // Exactly ONE fetch — the off-allowlist redirect was refused, never followed.
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  // ── Probe 5: redirect-allowed — allow-listed 3xx → explicit re-fetch → 200 ──
  it("redirect-allowed: a 3xx to an allow-listed host is re-fetched explicitly → final 200", async () => {
    installFetch((call) => {
      if (call === 0) {
        return new Response(null, {
          status: 307,
          headers: { location: `https://${REGISTRY_HOST}/v2/library/llama3/blobs/sha256:def` },
        });
      }
      return new Response("blob-bytes", {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
      });
    });

    const resp = await handleModelRegistry(
      mrReq("/model-registry/v2/library/llama3/blobs/sha256:def"),
      makeEnv(),
      makeCtx(),
    );
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("blob-bytes");
    // Two fetches — the allow-listed redirect was followed by an EXPLICIT re-fetch.
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(new URL(captures[1].url).hostname).toBe(REGISTRY_HOST);
  });

  // ── Probe 6: ★ Pillar-1 audit — no daemon bearer in logs; valid events ──
  it("★ Pillar-1: no logEvent line contains the daemon Bearer; every line is a valid ProxyLogEvent", async () => {
    installFetch(() =>
      new Response(JSON.stringify({ schemaVersion: 2 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const resp = await handleModelRegistry(mrReq(MANIFEST_PATH), makeEnv(), makeCtx());
      expect(resp.status).toBe(200);

      for (const call of logSpy.mock.calls) {
        const line = String(call[0]);
        expect(line).not.toContain(DAEMON_BEARER);
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

  // ── Probe 7: quota — /check 429 → 429 passthrough, no forward ───────────
  it("quota: a quota /check 429 → 429 quota_exceeded passthrough; no forward", async () => {
    installFetch(() => new Response("nope", { status: 200 }));

    const resp = await handleModelRegistry(mrReq(MANIFEST_PATH), makeEnv({ quotaStatus: 429 }), makeCtx());
    expect(resp.status).toBe(429);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe("quota_exceeded");
    expect(resp.headers.get("X-Bishop-Cap-Type")).toBe("monthly_tasks");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
