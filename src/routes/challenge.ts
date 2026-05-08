/**
 * GET /v1/challenge
 *
 * Issues a one-time PoW challenge nonce. Rate-limited to 10/24h per /24.
 * Nonce stored in ENROLL_KV with 5-minute TTL (overridable via CHALLENGE_TTL env var).
 */

export interface ChallengeEnv {
  ENROLL_KV: KVNamespace;
  AUTH_STORE: DurableObjectNamespace;
  CHALLENGE_TTL?: string;
  TARGET_ZERO_BITS?: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getIp24(request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP") ?? "0.0.0.0";
  const parts = ip.split(".");
  if (parts.length === 4) return parts.slice(0, 3).join(".");
  // IPv6 — use first 48 bits (6 groups of 4 hex) as the /48 prefix
  return ip.split(":").slice(0, 3).join(":");
}

export async function handleChallenge(
  request: Request,
  env: ChallengeEnv,
): Promise<Response> {
  const ip24 = getIp24(request);
  const ttl = parseInt(env.CHALLENGE_TTL ?? "300", 10);
  const difficulty = parseInt(env.TARGET_ZERO_BITS ?? "22", 10);

  // Rate limit: 10 challenge requests per /24 per day
  const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
  const rlResp = await stub.fetch("https://auth-store/rate-limit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ip24, endpoint: "challenge", max: 10 }),
  });
  if (!rlResp.ok) {
    return new Response(
      JSON.stringify({ error: "rate_limited", retry_after: 86400 }),
      { status: 429, headers: { "content-type": "application/json" } },
    );
  }

  // Generate 16-byte nonce → 32 hex chars
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = toHex(nonceBytes);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  // CF KV minimum expirationTtl is 60 seconds; clamp for local dev / short test values
  await env.ENROLL_KV.put(
    `nonce:${nonce}`,
    JSON.stringify({ issued_at: now.toISOString(), ip_hint: ip24, ttl }),
    { expirationTtl: Math.max(60, ttl) },
  );

  return new Response(
    JSON.stringify({
      nonce,
      expires_at: expiresAt.toISOString(),
      difficulty,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}
