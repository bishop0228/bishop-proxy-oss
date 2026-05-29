/**
 * POST /admin/token/revoke
 *
 * Narrow-scope admin endpoint: flips a single session token to status="revoked"
 * by token_id (non-secret correlation id) via AuthStoreDO /revoke. This route
 * can flip a token to revoked by token_id and nothing else; it never reads or
 * returns the secret token value (Pillar 1).
 *
 * Auth: requires `X-Admin-Token` header matching env.ADMIN_TOKEN.
 *
 * Body: { "token_id": string (UUID) }
 *
 * Response: 200 with { "revoked": boolean, "existed": boolean }, or
 *           401 unauthorized, 400 invalid_json / invalid_parameters, 500 do_error.
 */

export interface AdminEnv {
  AUTH_STORE: DurableObjectNamespace;
  ADMIN_TOKEN: string;
}

export async function handleAdminTokenRevoke(
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

  let body: { token_id?: unknown };
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "invalid_json" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  // Defense-in-depth: require token_id to be a UUID-shaped string even if
  // admin token leaks. Prevents accidental or malicious free-form key probes.
  if (
    typeof body.token_id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.token_id)
  ) {
    return new Response(
      JSON.stringify({ error: "invalid_parameters" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const doResp = await stub.fetch("https://auth-store/revoke", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token_id: body.token_id }),
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
