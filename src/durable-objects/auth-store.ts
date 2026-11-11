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

/** A billing id's Stripe customer (W38-S1326 (a)), kept under customer:<billing id> with its subscription's creation
 *  time (Stripe's `created`, seconds since the epoch), so an older subscription's event cannot replace it. */
export interface CustomerRecord {
  customer: string;
  subscription_created: number;
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

    // W38-S1326 (a): the Stripe customer of a billing id, recorded by the webhook from the subscription's own events, so
    // the billing portal can open for a subscription made seconds ago: Stripe's subscription search is not read-after-
    // write ("data is searchable in under 1 minute"). Keyed by the billing id, an HMAC the proxy derives from a token.
    // The customer id is held to Stripe's documented form and no narrower: "Make sure that your integration can handle
    // Stripe-generated object IDs, which can contain up to 255 characters", and a change of "length or format",
    // "adding or removing fixed prefixes", is one Stripe calls backward-compatible (docs.stripe.com/api-versions);
    // customer IDs "can only contain alphanumeric and `_-` characters" (docs.stripe.com/changelog/2018-05-21).
    // The record keeps the customer of the newest subscription: an event of a subscription created before the one
    // recorded is refused (409) and the record kept, because Stripe "doesn't guarantee the delivery of events in the
    // order that they're generated" and retries a failed delivery "for up to three days" (docs.stripe.com/webhooks). A
    // subscription created in the same second may replace it.
    if (request.method === "POST" && url.pathname === "/bind-customer") {
      const body = (await request.json()) as {
        billing_id?: unknown;
        customer?: unknown;
        subscription_created?: unknown;
      };
      const created = body.subscription_created;
      if (
        typeof body.billing_id !== "string" || !/^[0-9a-f]{64}$/.test(body.billing_id) ||
        typeof body.customer !== "string" || !/^[A-Za-z0-9_-]{1,255}$/.test(body.customer) ||
        typeof created !== "number" || !Number.isSafeInteger(created) || created < 0
      ) {
        return new Response(JSON.stringify({ error: "invalid_fields" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        });
      }
      const key = `customer:${body.billing_id}`;
      const record: CustomerRecord = { customer: body.customer, subscription_created: created };
      let kept = false;
      await this.state.storage.transaction(async (txn) => {
        const existing = await txn.get<CustomerRecord>(key);
        if (existing && existing.subscription_created > created) {
          kept = true;
          return;
        }
        await txn.put(key, record);
      });
      if (kept) {
        return new Response(JSON.stringify({ error: "older_subscription" }), {
          status: 409,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ status: "bound" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (request.method === "GET" && url.pathname === "/lookup-customer") {
      const b = url.searchParams.get("b") ?? "";
      const customer = /^[0-9a-f]{64}$/.test(b)
        ? (await this.state.storage.get<CustomerRecord>(`customer:${b}`))?.customer
        : undefined;
      if (!customer) {
        return new Response(JSON.stringify({ error: "not_found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ customer }), {
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
    // Pre-transaction idempotency check.
    const existing = await this._lookupByFingerprint(fingerprint_hash);
    if (existing) {
      // FREE→CONNECTED relabel (W38-S872g model): when an already-enrolled device
      // connects its first BYOK key / subscription / local model, the daemon
      // re-enrolls with account_mode="byok". Honor that ONE-DIRECTIONAL upgrade by
      // updating the existing record in place (the fp:/tid: indexes still point at
      // the same token, so only the record's account_mode field changes). The
      // free tier ends the moment the user connects anything — there is no
      // free-tier fallback once connected. The reverse (byok→managed) is NOT
      // auto-applied here: downgrading to Bishop's managed/operator key is
      // billing-sensitive and must stay fail-closed (a deliberate, gated action),
      // never a side effect of a re-enroll.
      if (existing.account_mode === "managed" && account_mode === "byok") {
        const relabeled: AuthRecord = { ...existing, account_mode: "byok" };
        await this.state.storage.put(`token:${existing.token}`, relabeled);
        return { record: relabeled, isNew: false };
      }
      return { record: existing, isNew: false };
    }

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
