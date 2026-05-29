/**
 * AuthStoreDO — auth-store Durable Object.
 *
 * Single global instance (idFromName("global")) per environment.
 * Dual-indexed token storage: primary by token value, secondary by fingerprint hash.
 * Both index entries are written atomically via storage.transaction().
 *
 * Also owns per-/24 per-day rate-limit counters for /v1/challenge and /v1/enroll.
 *
 * Token issuance, fingerprint idempotency, rate limiting.
 * /verify-token RPC; best-effort token-keyed tier-cache seed
 *   on first issuance (G4 ratification — TierCacheDO is token-keyed at P2.1).
 */

export interface AuthRecord {
  token: string;              // bsk_staging_<base64url(32 bytes)> — ~55 chars
  token_id: string;           // UUID for log correlation
  issued_at: string;          // ISO8601
  expires_at: string;         // issued_at + 365d, ISO8601
  fingerprint_hash: string;   // 64 hex chars (sha256)
  status: "active" | "revoked";
  last_seen: string | null;   // P2 populates on /v1/messages
  refresh_count: number;      // 0 at P1; P2 increments
  client_version: string;
  account_mode: "managed" | "byok";
}

export interface AuthStoreEnv {
  TIER_CACHE: DurableObjectNamespace;
}

function toBase64url(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...Array.from(bytes)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class AuthStoreDO {
  private state: DurableObjectState;
  private env: AuthStoreEnv;

  constructor(state: DurableObjectState, env: AuthStoreEnv) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/issue") {
      const body = (await request.json()) as {
        fingerprint_hash: string;
        client_version: string;
        account_mode?: string;
        test_ttl_ms?: number;
      };
      const accountMode: "managed" | "byok" =
        body.account_mode === "byok" ? "byok" : "managed";
      const { record, isNew } = await this._issueToken(
        body.fingerprint_hash,
        body.client_version,
        accountMode,
        body.test_ttl_ms,
      );
      return new Response(JSON.stringify(record), {
        status: isNew ? 201 : 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "GET" && url.pathname === "/lookup") {
      const fp = url.searchParams.get("fp");
      if (!fp) {
        return new Response(JSON.stringify({ error: "missing_fp" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      const record = await this._lookupByFingerprint(fp);
      if (!record) {
        return new Response(JSON.stringify({ error: "not_found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify(record), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/verify-token") {
      const body = (await request.json()) as { token: string };
      const record = await this.state.storage.get<AuthRecord>(`token:${body.token}`);
      if (!record) {
        return new Response(JSON.stringify({ valid: false, record: null, reason: "not_found" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (record.status !== "active") {
        return new Response(JSON.stringify({ valid: false, record, reason: "revoked" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (Date.now() >= new Date(record.expires_at).getTime()) {
        return new Response(JSON.stringify({ valid: false, record, reason: "expired" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ valid: true, record, reason: null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/bind-user") {
      const body = (await request.json()) as {
        user_hash: string;
        token_id: string;
      };
      if (!body.user_hash || !body.token_id) {
        return new Response(JSON.stringify({ error: "missing_fields" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      // Latest-bind-wins. Multi-device support is a future extension; for now
      // a single user_hash → token_id mapping is sufficient.
      await this.state.storage.put(`user:${body.user_hash}`, body.token_id);
      return new Response(JSON.stringify({ status: "bound" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "GET" && url.pathname === "/lookup-user") {
      const h = url.searchParams.get("h");
      if (!h) {
        return new Response(JSON.stringify({ error: "missing_h" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      const tokenId = await this.state.storage.get<string>(`user:${h}`);
      if (!tokenId) {
        return new Response(JSON.stringify({ error: "not_found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ token_id: tokenId }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/rate-limit") {
      const body = (await request.json()) as {
        ip24: string;
        endpoint: string;
        max: number;
      };
      const ok = await this._checkRateLimit(body.ip24, body.endpoint, body.max);
      return new Response(JSON.stringify({ ok }), {
        status: ok ? 200 : 429,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/clear-rate-limit") {
      const body = (await request.json()) as {
        ip_prefix: string;
        endpoint: string;
        date: string;
      };
      const key = `rl:${body.ip_prefix}:${body.endpoint}:${body.date}`;
      let existed = false;
      await this.state.storage.transaction(async (txn) => {
        const current = await txn.get<number>(key);
        existed = current !== undefined && current !== null;
        if (existed) {
          await txn.delete(key);
        }
      });
      return new Response(JSON.stringify({ deleted: key, existed }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "POST" && url.pathname === "/revoke") {
      const body = (await request.json()) as { token_id?: string };
      if (!body.token_id) {
        return new Response(JSON.stringify({ error: "missing_token_id" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      const token = await this.state.storage.get<string>(`tid:${body.token_id}`);
      if (!token) {
        return new Response(JSON.stringify({ revoked: false, existed: false }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      let revoked = false;
      await this.state.storage.transaction(async (txn) => {
        const rec = await txn.get<AuthRecord>(`token:${token}`);
        if (rec) {
          rec.status = "revoked";
          await txn.put(`token:${token}`, rec);
          revoked = true;
        }
      });
      return new Response(JSON.stringify({ revoked, existed: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }

  private async _lookupByFingerprint(fpHash: string): Promise<AuthRecord | null> {
    const tokenValue = await this.state.storage.get<string>(`fp:${fpHash}`);
    if (!tokenValue) return null;
    return (await this.state.storage.get<AuthRecord>(`token:${tokenValue}`)) ?? null;
  }

  private async _issueToken(
    fingerprint_hash: string,
    client_version: string,
    account_mode: "managed" | "byok" = "managed",
    test_ttl_ms?: number,
  ): Promise<{ record: AuthRecord; isNew: boolean }> {
    // Pre-transaction idempotency check
    const existing = await this._lookupByFingerprint(fingerprint_hash);
    if (existing) return { record: existing, isNew: false };

    const tokenBytes = new Uint8Array(32);
    crypto.getRandomValues(tokenBytes);
    const token = `bsk_staging_${toBase64url(tokenBytes)}`;
    const token_id = crypto.randomUUID();
    const now = new Date();
    const ttlMs =
      typeof test_ttl_ms === "number" && Number.isFinite(test_ttl_ms)
        ? test_ttl_ms
        : 365 * 24 * 3600 * 1000;
    const expires = new Date(now.getTime() + ttlMs);

    const candidate: AuthRecord = {
      token,
      token_id,
      issued_at: now.toISOString(),
      expires_at: expires.toISOString(),
      fingerprint_hash,
      status: "active",
      last_seen: null,
      refresh_count: 0,
      client_version,
      account_mode,
    };

    // Atomic dual-index write inside a single transaction
    await this.state.storage.transaction(async (txn) => {
      // Re-check inside transaction to guard against concurrent issuance races
      const existingToken = await txn.get<string>(`fp:${fingerprint_hash}`);
      if (!existingToken) {
        await txn.put(`token:${token}`, candidate);
        await txn.put(`fp:${fingerprint_hash}`, token);
        await txn.put(`tid:${token_id}`, token); // §1.17.20 reverse index → enables revoke-by-token_id
      }
    });

    // Re-read post-transaction to resolve any race (the winner's record is authoritative)
    const authoritative = await this._lookupByFingerprint(fingerprint_hash);
    const finalRecord = authoritative ?? candidate;
    const isNew = !authoritative || authoritative.token === token;

    // Best-effort token_id-keyed tier-cache seed on
    // first issuance only. Failures here MUST NOT fail enrollment: the seed
    // is an optimization for /v1/messages tier reads, not a correctness gate.
    // stripe_event_id: null is the documented sentinel for "non-Stripe seed
    // write" — TierCacheDO's idempotency guard intentionally does not
    // short-circuit on null (per D1). Keyed by token_id (UUID) per G4.
    if (isNew) {
      try {
        const tierStub = this.env.TIER_CACHE.get(
          this.env.TIER_CACHE.idFromName(finalRecord.token_id),
        );
        const validUntil = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
        const seedResp = await tierStub.fetch("https://internal/set", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            tier: "free",
            valid_until: validUntil,
            stripe_event_id: null,
          }),
        });
      } catch (err) {
        void err;
      }
    }

    return { record: finalRecord, isNew };
  }

  private async _checkRateLimit(ip24: string, endpoint: string, max: number): Promise<boolean> {
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC
    const key = `rl:${ip24}:${endpoint}:${today}`;
    let allowed = true;
    await this.state.storage.transaction(async (txn) => {
      const current = (await txn.get<number>(key)) ?? 0;
      if (current >= max) {
        allowed = false;
        return;
      }
      await txn.put(key, current + 1);
    });
    return allowed;
  }
}
