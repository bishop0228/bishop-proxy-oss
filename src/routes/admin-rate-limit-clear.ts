/**
 * POST /admin/rate-limit/clear
 *
 * Narrow-scope admin endpoint: deletes a single rate-limit counter
 * key from AuthStoreDO storage. Cannot delete any other state.
 *
 * Auth: requires `X-Admin-Token` header matching env.ADMIN_TOKEN.
 *
 * Body: { "ip_prefix": string, "endpoint": string, "date": string }
 *   - `ip_prefix`: e.g. "2600:880a:2718" (IPv6 /48) or "192.168.1" (IPv4 /24)
 *   - `endpoint`: "challenge" or "enroll"
 *   - `date`: "YYYY-MM-DD" UTC
 *
 * Response: 200 with { "deleted": <key>, "existed": <boolean> }, or
 *           401 unauthorized, or 400 bad request.
 *
 * Narrow scope: admin token compromise can clear rate-limit counters but
 * cannot read or modify auth tokens, enrollment records, or tier-cache
 * state.
 */

export interface AdminEnv {
  AUTH_STORE: DurableObjectNamespace;
  ADMIN_TOKEN: string;
}

interface AdminRateLimitClearRequest {
  ip_prefix: string;
  endpoint: string;
  date: string;
}

export async function handleAdminRateLimitClear(
  request: Request,
  env: AdminEnv,
): Promise<Response> {
  const adminToken = request.headers.get("X-Admin-Token");
  if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
    return new Response(
      JSON.stringify({ error: "unauthorized" }),
      { status: 401, headers: { "content-type": "application/json" } },
    );
  }

  let body: AdminRateLimitClearRequest;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "invalid_json" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  // Defense-in-depth: constrain inputs to rate-limit-key shape even if admin
  // token leaks. ip_prefix: hex digits, dots, colons only (covers IPv4 /24
  // and IPv6 /48 prefixes). endpoint: lowercase alpha only. date: YYYY-MM-DD.
  if (
    typeof body.ip_prefix !== "string" ||
    !/^[0-9a-fA-F.:]+$/.test(body.ip_prefix) ||
    body.ip_prefix.length > 64 ||
    typeof body.endpoint !== "string" ||
    !/^[a-z]+$/.test(body.endpoint) ||
    body.endpoint.length > 32 ||
    typeof body.date !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(body.date)
  ) {
    return new Response(
      JSON.stringify({ error: "invalid_parameters" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const doResp = await stub.fetch("https://auth-store/clear-rate-limit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ip_prefix: body.ip_prefix,
      endpoint: body.endpoint,
      date: body.date,
    }),
  });

  if (!doResp.ok) {
    return new Response(
      JSON.stringify({ error: "do_error", status: doResp.status }),
      { status: 500, headers: { "content-type": "application/json" } },
    );
  }

  const doResult = await doResp.json();
  return new Response(JSON.stringify(doResult), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
