/**
 * ProxyLogEvent — typed allowlist for proxy log emission.
 *
 * Audit artifact for the log-content-discipline claim made in the README:
 * NO log line in this codebase carries prompt content, response bodies,
 * or auth headers. The shape below is the only permitted log payload.
 * The runtime type guard `isProxyLogEvent` enforces the shape on every
 * emission.
 *
 * Q8 deferred-ratification anchor: this file IS the answer. No other
 * console.log call may be added; existing console.log calls outside
 * this module must be migrated or removed.
 */

export interface ProxyLogEvent {
  event_type: "request" | "response" | "classification" | "enrollment" | "rate_limit" | "error";
  timestamp: string;             // ISO-8601 UTC
  request_id: string;            // proxy-generated UUID
  token_id: string | null;       // null for /enroll
  ip: string;                    // /24-truncated for IPv4, /48-truncated for IPv6
  request_size_bytes: number;
  response_status: number;
  response_size_bytes: number;
  token_count_in: number | null;
  token_count_out: number | null;
  cached_tokens: number | null;
  cache_creation_input_tokens: number | null;
  cache_read_input_tokens: number | null;
  classification_decision: "allow" | "block" | "review" | "unavailable" | null;
  classification_category: "safe" | "profanity" | "pii" | "weapons" | "csam" | "self_harm" | "other" | null;
  duration_ms: number;
  upstream_status: number | null;
  cap_type_hit: "monthly_cost" | "monthly_tasks" | "daily_floor" | "rate_limit" | null;
  classifier_error_reason: "timeout" | "ai_binding_error" | null;
  // NEVER: prompt, response_body, headers, fingerprint, raw_ip, user_agent
}

const ALLOWED_KEYS = new Set<string>([
  "event_type",
  "timestamp",
  "request_id",
  "token_id",
  "ip",
  "request_size_bytes",
  "response_status",
  "response_size_bytes",
  "token_count_in",
  "token_count_out",
  "cached_tokens",
  "cache_creation_input_tokens",
  "cache_read_input_tokens",
  "classification_decision",
  "classification_category",
  "duration_ms",
  "upstream_status",
  "cap_type_hit",
  "classifier_error_reason",
]);

const EVENT_TYPES = new Set<string>([
  "request",
  "response",
  "classification",
  "enrollment",
  "rate_limit",
  "error",
]);

const CLASSIFICATION_DECISIONS = new Set<string>(["allow", "block", "review", "unavailable"]);

const CLASSIFICATION_CATEGORIES = new Set<string>([
  "safe",
  "profanity",
  "pii",
  "weapons",
  "csam",
  "self_harm",
  "other",
]);

const CAP_TYPES = new Set<string>([
  "monthly_cost",
  "monthly_tasks",
  "daily_floor",
  "rate_limit",
]);

const CLASSIFIER_ERROR_REASONS = new Set<string>(["timeout", "ai_binding_error"]);

function isStringOrNull(v: unknown): v is string | null {
  return v === null || typeof v === "string";
}

function isNumberOrNull(v: unknown): v is number | null {
  return v === null || (typeof v === "number" && Number.isFinite(v));
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

export function isProxyLogEvent(x: unknown): x is ProxyLogEvent {
  if (x === null || typeof x !== "object") return false;
  const o = x as Record<string, unknown>;

  // Key-set comparison: reject any unknown field AND require every allowed
  // field to be present (presence-by-key, type-checked below).
  const keys = Object.keys(o);
  if (keys.length !== ALLOWED_KEYS.size) return false;
  for (const k of keys) {
    if (!ALLOWED_KEYS.has(k)) return false;
  }

  if (typeof o.event_type !== "string" || !EVENT_TYPES.has(o.event_type)) return false;
  if (typeof o.timestamp !== "string") return false;
  if (typeof o.request_id !== "string") return false;
  if (!isStringOrNull(o.token_id)) return false;
  if (typeof o.ip !== "string") return false;
  if (!isFiniteNumber(o.request_size_bytes)) return false;
  if (!isFiniteNumber(o.response_status)) return false;
  if (!isFiniteNumber(o.response_size_bytes)) return false;
  if (!isNumberOrNull(o.token_count_in)) return false;
  if (!isNumberOrNull(o.token_count_out)) return false;
  if (!isNumberOrNull(o.cached_tokens)) return false;
  if (!isNumberOrNull(o.cache_creation_input_tokens)) return false;
  if (!isNumberOrNull(o.cache_read_input_tokens)) return false;
  if (o.classification_decision !== null
    && (typeof o.classification_decision !== "string"
      || !CLASSIFICATION_DECISIONS.has(o.classification_decision))) return false;
  if (o.classification_category !== null
    && (typeof o.classification_category !== "string"
      || !CLASSIFICATION_CATEGORIES.has(o.classification_category))) return false;
  if (!isFiniteNumber(o.duration_ms)) return false;
  if (!isNumberOrNull(o.upstream_status)) return false;
  if (o.cap_type_hit !== null
    && (typeof o.cap_type_hit !== "string"
      || !CAP_TYPES.has(o.cap_type_hit))) return false;
  if (o.classifier_error_reason !== null
    && (typeof o.classifier_error_reason !== "string"
      || !CLASSIFIER_ERROR_REASONS.has(o.classifier_error_reason))) return false;

  return true;
}

export class ProxyLogShapeError extends Error {
  constructor() {
    super("proxy_log_shape_violation");
    this.name = "ProxyLogShapeError";
  }
}

export function logEvent(event: ProxyLogEvent): void {
  if (!isProxyLogEvent(event)) {
    throw new ProxyLogShapeError();
  }
  console.log(JSON.stringify(event));
}
