import { argon2id } from "@noble/hashes/argon2.js";

interface FeasibilityRequest {
  fingerprint_hex: string;  // 64 hex chars
  nonce_hex: string;        // 16 hex chars
}

interface FeasibilityResponse {
  hash_hex: string | null;
  duration_ms: number;
  error: string | null;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/v1/pow-feasibility-test") {
      let body: FeasibilityRequest;
      try {
        body = (await request.json()) as FeasibilityRequest;
      } catch {
        return Response.json(
          { hash_hex: null, duration_ms: 0, error: "invalid_json" } satisfies FeasibilityResponse,
          { status: 400 }
        );
      }

      if (typeof body.fingerprint_hex !== "string" || !/^[0-9a-f]{64}$/i.test(body.fingerprint_hex)) {
        return Response.json(
          { hash_hex: null, duration_ms: 0, error: "invalid_fingerprint_hex" } satisfies FeasibilityResponse,
          { status: 400 }
        );
      }
      if (typeof body.nonce_hex !== "string" || !/^[0-9a-f]{16}$/i.test(body.nonce_hex)) {
        return Response.json(
          { hash_hex: null, duration_ms: 0, error: "invalid_nonce_hex" } satisfies FeasibilityResponse,
          { status: 400 }
        );
      }

      const fpBytes = hexToBytes(body.fingerprint_hex);
      const nonceBytes = hexToBytes(body.nonce_hex);

      const startMs = performance.now();
      let hash: Uint8Array | null = null;
      let error: string | null = null;
      try {
        hash = argon2id(fpBytes, nonceBytes, { t: 1, m: 65536, p: 1, dkLen: 32 });
      } catch (e) {
        error = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      }
      const durationMs = Math.round(performance.now() - startMs);

      return Response.json(
        {
          hash_hex: hash !== null ? bytesToHex(hash) : null,
          duration_ms: durationMs,
          error,
        } satisfies FeasibilityResponse,
        { status: error !== null ? 500 : 200 }
      );
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ ok: true, service: "bishop-proxy-spike" });
    }

    return Response.json({ error: "not_found", path: url.pathname }, { status: 404 });
  },
};
