/**
 * POST /v1/messages.
 *
 * Eleven-step flow per the brief:
 *   1. Parse Bearer token from Authorization header.
 *   2. AuthStoreDO /verify-token RPC → 401 on not_found / revoked / expired.
 *   3. TierCacheDO read keyed by token_id (G4) → default "free" if no record.
 *   4. QuotaStoreDO /check (token_id-keyed) → 429 on cap exceeded.
 *   5. Classifier — Llama Guard 3 8B inspection on request body messages.
 *   6. rebuildHeaders — strip client identifiers, add operator API key.
 *   7. Upstream fetch + retry (G8): one retry on 5xx with 200ms backoff.
 *   8. Stream tee() — client gets one branch immediately, observer gets the
 *      other for usage extraction. NO buffer assembly of the response body.
 *   9. waitUntil(extractUsageFromSSE → /increment → log).
 *  10. Response headers: bishop-tier, bishop-monthly-cost-remaining-cents, etc.
 *  11. ProxyLogEvent emitted via logEvent().
 */

import type { Env } from "../index";
import { rebuildHeaders, resolveUpstreamKey } from "../lib/headers";
import { extractUsageFromSSE } from "../lib/sse-usage";
import { classify } from "../lib/classifier";
import { logEvent, type ProxyLogEvent } from "../lib/log";
import {
  computeCostCents,
  modelFamily,
  taskWeight,
  TIER_CAPS,
  type ModelFamily,
  type Tier,
} from "../lib/pricing";
import type { AuthRecord } from "../durable-objects/auth-store";
import type { TierRecord } from "../durable-objects/tier-cache";
import type { QuotaState } from "../durable-objects/quota-store";

interface VerifyTokenResult {
  valid: boolean;
  record: AuthRecord | null;
  reason: "not_found" | "revoked" | "expired" | null;
}

const BISHOP_SYSTEM_PROMPT =
  "You are Claude, accessed through Bishop — a local AI automation agent. " +
  "The user is operating Bishop on their own device. " +
  "Respond to the user's message directly.";

function injectSystemCacheControl(
  body: Record<string, unknown>,
): Record<string, unknown> {
  if (body.system !== undefined) return body;
  return {
    ...body,
    system: [
      {
        type: "text",
        text: BISHOP_SYSTEM_PROMPT,
        cache_control: { type: "ephemeral" },
      },
    ],
  };
}

export function ip24From(request: Request): string {
  const cf = request.headers.get("cf-connecting-ip") ?? "0.0.0.0";
  // IPv4 /24 truncation. IPv6 falls through (treat as opaque).
  const parts = cf.split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
  }
  return cf;
}

export function jsonError(status: number, error: string, extras: Record<string, unknown> = {}): Response {
  return new Response(JSON.stringify({ error, ...extras }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export async function handleMessages(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  const requestSize = Number(request.headers.get("content-length") ?? "0");
  const ip = ip24From(request);

  // Step 1 — Bearer parsing.
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    emitError(requestId, ip, requestSize, 401, "missing_bearer", startedAt);
    return jsonError(401, "missing_bearer");
  }
  const token = auth.slice(7).trim();
  if (token.length < 16) {
    emitError(requestId, ip, requestSize, 401, "malformed_bearer", startedAt);
    return jsonError(401, "malformed_bearer");
  }

  // Step 2 — token verification via AuthStoreDO /verify-token.
  const authStub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const verifyResp = await authStub.fetch("https://internal/verify-token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  const verify = (await verifyResp.json()) as VerifyTokenResult;
  if (!verify.valid || !verify.record) {
    const reason = verify.reason ?? "not_found";
    emitError(requestId, ip, requestSize, 401, `token_${reason}`, startedAt);
    return jsonError(401, `token_${reason}`);
  }
  const record = verify.record;
  const tokenId = record.token_id;

  // Step 3 — tier-cache read keyed by token_id (G4).
  const tier = await readTier(env, tokenId);

  // Parse body to read model id BEFORE quota check (we need the model family
  // for task weighting). Body is JSON for streaming requests; max size is
  // bounded by Cloudflare worker request limits. We do NOT log the body.
  let body: { model?: string; stream?: boolean } & Record<string, unknown>;
  let bodyText: string;
  try {
    bodyText = await request.text();
    body = JSON.parse(bodyText) as typeof body;
  } catch {
    emitError(requestId, ip, requestSize, 400, "bad_json", startedAt, tokenId);
    return jsonError(400, "bad_json");
  }
  const family = typeof body.model === "string" ? modelFamily(body.model) : null;
  if (!family) {
    emitError(requestId, ip, requestSize, 400, "unsupported_model", startedAt, tokenId);
    return jsonError(400, "unsupported_model");
  }
  const weight = taskWeight(family);

  // Step 4 — quota /check.
  const quotaStub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
  const checkResp = await quotaStub.fetch("https://internal/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    // W38-S923: forward account_mode so a CONNECTED (byok) device bypasses the
    // free-tier daily_floor (it pays its own provider); managed/FREE stays metered.
    body: JSON.stringify({
      tier,
      weight,
      cost_cents_estimate: 0,
      account_mode: record.account_mode ?? "managed",
    }),
  });
  if (checkResp.status === 429) {
    const cr = (await checkResp.json()) as { reason?: string };
    const cap = capTypeFromReason(cr.reason);
    emitRateLimit(requestId, ip, requestSize, tokenId, cap, startedAt);
    return new Response(
      JSON.stringify({ error: "quota_exceeded", reason: cr.reason ?? null }),
      {
        status: 429,
        headers: {
          "content-type": "application/json",
          "X-Bishop-Cap-Type": capTypeHeaderValue(cap),
        },
      },
    );
  }

  // Step 5 — content classifier.
  const cls = await classify(body, env);

  // Step 5.5a — allow-path audit event: emit classification record for every passing request.
  if (cls.decision === "allow") {
    const allowEvent: ProxyLogEvent = {
      event_type: "classification",
      timestamp: new Date().toISOString(),
      request_id: requestId,
      token_id: tokenId,
      ip,
      request_size_bytes: requestSize,
      response_status: 0,
      response_size_bytes: 0,
      token_count_in: null,
      token_count_out: null,
      cached_tokens: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      classification_decision: "allow",
      classification_category: cls.category,
      classifier_error_reason: cls.classifier_error_reason,
      duration_ms: Date.now() - startedAt,
      upstream_status: null,
      cap_type_hit: null,
    };
    try { logEvent(allowEvent); } catch { /* shape error is itself an audit signal */ }
  }

  // Step 5.5b — block path: fail-closed on any non-allow decision.
  if (cls.decision === "block") {
    const blockEvent: ProxyLogEvent = {
      event_type: "classification",
      timestamp: new Date().toISOString(),
      request_id: requestId,
      token_id: tokenId,
      ip,
      request_size_bytes: requestSize,
      response_status: 451,
      response_size_bytes: 0,
      token_count_in: null,
      token_count_out: null,
      cached_tokens: null,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      classification_decision: "block",
      classification_category: cls.category,
      classifier_error_reason: cls.classifier_error_reason,
      duration_ms: Date.now() - startedAt,
      upstream_status: null,
      cap_type_hit: null,
    };
    try { logEvent(blockEvent); } catch { /* shape error is itself an audit signal */ }
    return new Response(
      JSON.stringify({
        type: "error",
        error: {
          type: "content_policy_violation",
          message: "Request blocked by content classifier.",
        },
      }),
      { status: 451, headers: { "content-type": "application/json" } },
    );
  }

  // Step 6 — BYOK entitlement gate: resolve upstream key (fail-closed).
  const accountMode = (record.account_mode ?? "managed") as "managed" | "byok";
  const keyResolution = resolveUpstreamKey(accountMode, request.headers, env.ANTHROPIC_API_KEY);
  if (!keyResolution.ok) {
    emitError(requestId, ip, requestSize, 400, keyResolution.reason, startedAt, tokenId);
    return jsonError(400, keyResolution.reason);
  }
  const upstreamHeaders = rebuildHeaders(request.headers, keyResolution.key);

  // Step 7 — upstream fetch with G8 retry policy (one retry on 5xx).
  const upstreamUrl =
    (env as Env & { ANTHROPIC_BASE_URL?: string }).ANTHROPIC_BASE_URL ??
    "https://api.anthropic.com";
  const upstream = await fetchWithRetry(`${upstreamUrl}/v1/messages`, {
    method: "POST",
    headers: upstreamHeaders,
    body: JSON.stringify(injectSystemCacheControl(body)),
  });

  // Step 8 — tee() the response stream.
  const isStream = body.stream === true && upstream.body !== null;
  let clientBody: ReadableStream<Uint8Array> | null = upstream.body;
  let observerBody: ReadableStream<Uint8Array> | null = null;
  if (isStream && upstream.body) {
    const [a, b] = upstream.body.tee();
    clientBody = a;
    observerBody = b;
  }

  // Step 10 — response headers (computed pre-increment; "remaining" is
  // current state, not post-this-request).
  const respHeaders = await buildResponseHeaders(env, tokenId, tier, upstream.headers);

  // Step 9 + 11 — usage extraction + /increment + log, after response is
  // returned to the client. waitUntil keeps the worker alive for the
  // observer pipeline.
  ctx.waitUntil((async () => {
    let usage = { input_tokens: 0, output_tokens: 0, cached_tokens: 0, cache_creation_input_tokens: 0 };
    if (observerBody) {
      try {
        usage = await extractUsageFromSSE(observerBody);
      } catch {
        // observer failure must not affect the client; counters fall back to 0.
      }
    }
    const costCents = computeCostCents(family, usage);
    if (upstream.ok) {
      try {
        await quotaStub.fetch("https://internal/increment", {
          method: "POST",
          headers: { "content-type": "application/json" },
          // W38-S937: forward account_mode so a CONNECTED (byok) device's
          // inference cost does not advance the proxy's free-tier monthly_cost
          // meter (it pays its own provider). Mirrors the S923 /check forwarding.
          body: JSON.stringify({ weight, cost_cents: costCents, account_mode: accountMode }),
        });
      } catch {
        // best-effort: increment failure is logged below by event_type=error.
      }
    }
    emitResponse({
      request_id: requestId,
      token_id: tokenId,
      ip,
      request_size_bytes: requestSize,
      response_status: upstream.status,
      response_size_bytes: 0, // body streamed; we don't measure to keep privacy
      input_tokens: usage.input_tokens,
      output_tokens: usage.output_tokens,
      cached_tokens: usage.cached_tokens,
      cache_creation_input_tokens: usage.cache_creation_input_tokens,
      classification_decision: cls.decision,
      classification_category: cls.category,
      classifier_error_reason: cls.classifier_error_reason,
      duration_ms: Date.now() - startedAt,
      upstream_status: upstream.status,
    });
  })());

  return new Response(clientBody, {
    status: upstream.status,
    headers: respHeaders,
  });
}

export async function readTier(env: Env, tokenId: string): Promise<Tier> {
  try {
    const stub = env.TIER_CACHE.get(env.TIER_CACHE.idFromName(tokenId));
    const resp = await stub.fetch("https://internal/", { method: "GET" });
    if (resp.status !== 200) return "free";
    const r = (await resp.json()) as TierRecord;
    return r.tier ?? "free";
  } catch {
    return "free";
  }
}

// X-Bishop-Quota-Remaining carries the remaining monthly cost in cents
// (the dollar-denominated cap is the user-visible billing surface).
// X-Bishop-Cap-Type is "null" on success-with-headroom; the 429 path uses
// "monthly_cost" / "monthly_tasks" / "daily" via emitRateLimit's header set.
export async function buildResponseHeaders(
  env: Env,
  tokenId: string,
  tier: Tier,
  upstreamHeaders: Headers,
): Promise<Headers> {
  const h = new Headers();
  const ct = upstreamHeaders.get("content-type");
  if (ct) h.set("content-type", ct);

  let state: QuotaState | null = null;
  try {
    const stub = env.QUOTA_STORE.get(env.QUOTA_STORE.idFromName(tokenId));
    const resp = await stub.fetch("https://internal/", { method: "GET" });
    if (resp.status === 200) {
      state = (await resp.json()) as QuotaState;
    }
  } catch {
    // headers are observability — failures are non-fatal.
  }

  const cap = TIER_CAPS[tier];
  if (state && cap.monthly_cost_cents !== null) {
    h.set(
      "X-Bishop-Quota-Remaining",
      String(Math.max(0, cap.monthly_cost_cents - state.monthly_cost_cents)),
    );
  } else {
    h.set("X-Bishop-Quota-Remaining", "unlimited");
  }
  h.set("X-Bishop-Cap-Type", "null");
  return h;
}

// G8: 3 total attempts on 5xx / network / timeout, with exponential backoff
// 200ms, 800ms between attempts. NO retry on 4xx (client error — pass through).
// Streaming retry constraint: this only fires before tee() begins; once the
// body has been split and returned to the client, no retry is attempted.
export const RETRY_BACKOFF_MS = [200, 800];

export async function fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, RETRY_BACKOFF_MS[attempt - 1]));
    }
    try {
      const resp = await fetch(url, init);
      if (resp.status < 500) return resp;
      // 5xx — cancel body and retry. The unread body is treated as cancelled
      // by the runtime; we don't await it.
      lastError = resp;
      if (attempt === 2) return resp; // budget exhausted
    } catch (err) {
      lastError = err;
      if (attempt === 2) throw err;
    }
  }
  // Unreachable in practice — the loop always returns or throws by attempt 2.
  if (lastError instanceof Response) return lastError;
  throw lastError;
}

export function capTypeFromReason(reason: string | undefined): ProxyLogEvent["cap_type_hit"] {
  if (reason === "monthly_cost_exceeded") return "monthly_cost";
  if (reason === "monthly_tasks_exceeded") return "monthly_tasks";
  if (reason === "daily_floor_exceeded") return "daily_floor";
  return "rate_limit";
}

// "daily" is the X-Bishop-Cap-Type value for daily-floor 429s. Internal
// cap_type_hit is "daily_floor" for log consistency; the header value is
// the user-visible label.
export function capTypeHeaderValue(cap: ProxyLogEvent["cap_type_hit"]): string {
  if (cap === "daily_floor") return "daily";
  return cap ?? "null";
}

export function emitError(
  request_id: string,
  ip: string,
  request_size_bytes: number,
  response_status: number,
  _note: string,
  startedAt: number,
  token_id: string | null = null,
): void {
  const event: ProxyLogEvent = {
    event_type: "error",
    timestamp: new Date().toISOString(),
    request_id,
    token_id,
    ip,
    request_size_bytes,
    response_status,
    response_size_bytes: 0,
    token_count_in: null,
    token_count_out: null,
    cached_tokens: null,
    cache_creation_input_tokens: null,
    cache_read_input_tokens: null,
    classification_decision: null,
    classification_category: null,
    classifier_error_reason: null,
    duration_ms: Date.now() - startedAt,
    upstream_status: null,
    cap_type_hit: null,
  };
  try { logEvent(event); } catch { /* shape error is itself an audit signal */ }
}

export function emitRateLimit(
  request_id: string,
  ip: string,
  request_size_bytes: number,
  token_id: string,
  cap_type_hit: ProxyLogEvent["cap_type_hit"],
  startedAt: number,
): void {
  const event: ProxyLogEvent = {
    event_type: "rate_limit",
    timestamp: new Date().toISOString(),
    request_id,
    token_id,
    ip,
    request_size_bytes,
    response_status: 429,
    response_size_bytes: 0,
    token_count_in: null,
    token_count_out: null,
    cached_tokens: null,
    cache_creation_input_tokens: null,
    cache_read_input_tokens: null,
    classification_decision: null,
    classification_category: null,
    classifier_error_reason: null,
    duration_ms: Date.now() - startedAt,
    upstream_status: null,
    cap_type_hit,
  };
  try { logEvent(event); } catch { /* */ }
}

export interface ResponseLogParams {
  request_id: string;
  token_id: string;
  ip: string;
  request_size_bytes: number;
  response_status: number;
  response_size_bytes: number;
  input_tokens: number;
  output_tokens: number;
  cached_tokens: number;
  cache_creation_input_tokens: number;
  classification_decision: ProxyLogEvent["classification_decision"];
  classification_category: ProxyLogEvent["classification_category"];
  classifier_error_reason: ProxyLogEvent["classifier_error_reason"];
  duration_ms: number;
  upstream_status: number;
}

export function emitResponse(p: ResponseLogParams): void {
  const event: ProxyLogEvent = {
    event_type: "response",
    timestamp: new Date().toISOString(),
    request_id: p.request_id,
    token_id: p.token_id,
    ip: p.ip,
    request_size_bytes: p.request_size_bytes,
    response_status: p.response_status,
    response_size_bytes: p.response_size_bytes,
    token_count_in: p.input_tokens,
    token_count_out: p.output_tokens,
    cached_tokens: p.cached_tokens,
    cache_creation_input_tokens: p.cache_creation_input_tokens,
    cache_read_input_tokens: p.cached_tokens,
    classification_decision: p.classification_decision,
    classification_category: p.classification_category,
    classifier_error_reason: p.classifier_error_reason,
    duration_ms: p.duration_ms,
    upstream_status: p.upstream_status,
    cap_type_hit: null,
  };
  try { logEvent(event); } catch { /* */ }
}

// re-export to silence unused-import warnings if pricing types need extending later
export type { ModelFamily };
