/**
 * POST /v1/tier/bind.
 *
 * Authenticated route that binds a user_id to the caller's token_id in
 * AuthStoreDO under the key user:<HMAC(user_id)>. The HMAC is computed at
 * the route layer using USER_INDEX_HMAC_KEY so the DO never sees raw user_id.
 *
 * The bind allows the Stripe webhook (which only knows user_id) to fan out
 * to the token-keyed TierCacheDO shard via /lookup-user.
 */

import type { Env } from "../index";
import { verifyBearer } from "../lib/auth";
import { computeUserHash } from "../lib/user-hash";

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export async function handleTierBind(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await verifyBearer(request, env);
  if (!auth.ok) return auth.response;

  let body: { user_id?: unknown };
  try {
    body = (await request.json()) as { user_id?: unknown };
  } catch {
    return jsonError(400, "invalid_json");
  }
  if (typeof body.user_id !== "string" || body.user_id.length < 1) {
    return jsonError(400, "missing_user_id");
  }

  const user_hash = await computeUserHash(body.user_id, env.USER_INDEX_HMAC_KEY);

  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const bindResp = await stub.fetch("https://internal/bind-user", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user_hash, token_id: auth.record.token_id }),
  });
  if (!bindResp.ok) {
    return jsonError(502, "bind_failed");
  }

  return new Response(JSON.stringify({ status: "bound" }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
