/**
 * token↔user-hash correlation.
 *
 * HMAC-SHA256(USER_INDEX_HMAC_KEY, user_id) → 64 hex chars.
 *
 * The HMAC key is held only by the Cloudflare Worker. It is the only way to
 * compute the index key for the AuthStoreDO `user:<user_hash>` → token_id
 * mapping. An attacker with read access to AuthStoreDO storage cannot reverse
 * the mapping back to a raw user_id without the secret.
 */

export async function computeUserHash(
  userId: string,
  secret: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBytes = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(userId),
  );
  return Array.from(new Uint8Array(sigBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
