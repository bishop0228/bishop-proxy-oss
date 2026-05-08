/**
 * Shared bearer-auth helper.
 *
 * Parses Authorization: Bearer <token>, RPC's AuthStoreDO /verify-token,
 * and returns either the AuthRecord (200 path) or a Response that the route
 * can return verbatim (4xx path). Centralizes the bearer parse + verify
 * pattern previously open-coded in routes/messages.ts.
 */

import type { Env } from "../index";
import type { AuthRecord } from "../durable-objects/auth-store";

interface VerifyTokenResult {
  valid: boolean;
  record: AuthRecord | null;
  reason: "not_found" | "revoked" | "expired" | null;
}

export type BearerAuthOutcome =
  | { ok: true; record: AuthRecord; token: string }
  | { ok: false; response: Response };

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export async function verifyBearer(
  request: Request,
  env: Env,
): Promise<BearerAuthOutcome> {
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    return { ok: false, response: jsonError(401, "missing_bearer") };
  }
  const token = auth.slice(7).trim();
  if (token.length < 16) {
    return { ok: false, response: jsonError(401, "malformed_bearer") };
  }

  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const verifyResp = await stub.fetch("https://internal/verify-token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  const verify = (await verifyResp.json()) as VerifyTokenResult;
  if (!verify.valid || !verify.record) {
    const reason = verify.reason ?? "not_found";
    return { ok: false, response: jsonError(401, `token_${reason}`) };
  }
  return { ok: true, record: verify.record, token };
}
