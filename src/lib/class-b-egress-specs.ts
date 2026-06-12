/**
 * CLASS_B_EGRESS_SPECS — frozen per-server descriptor table for the generic
 * worker-microVM egress leg, POST /egress/<server_id> (W38-S822-FIX, S5b-1).
 *
 * Same shape as MCP_SERVER_SPECS (src/lib/mcp-specs.ts) and the SAME §3.2
 * discipline: the entry keyed by the path segment at /egress/<server_id> is the
 * SOLE source of truth for the upstream host. The handler (src/routes/egress.ts)
 * reads spec.host SERVER-SIDE at request time and NEVER derives the host from the
 * inbound request — exactly the W9.7 /mcp/<server_id> "host from frozen spec,
 * never from request, SSRF-safe" rule. A (compromised) worker names only the
 * server_id (the path); it can reach ONLY that server_id's own spec host, not
 * any other allowlisted host (the cross-server egress / SSRF pattern §3.2 avoids).
 *
 *   • FIXED-host spec: host = spec.host (frozen); defense-in-depth asserts it ∈
 *     ALLOWED_OUTBOUND_HOSTS (the installed installFetchAllowlist is the runtime
 *     backstop) — a spec whose host is not allow-listed fails closed (500).
 *   • PER-ACCOUNT spec (hostFromUpstream): host = the daemon-supplied
 *     X-Bishop-Upstream-Host, admitted ONLY when it matches THIS spec's OWN
 *     anchored hostPattern (spec-bind; fail-closed on missing/mismatch).
 *
 * NO real Class B vendor host is added here. The 9 Class B worker hosts are added
 * per-worker in S5c (founder-reviewed, like the W9.7 per-account/fixed-host arcs)
 * as host-already-present spec entries; `fetch` (arbitrary URL) is NOT served by
 * this route — it goes to gateway-per-request approval in S5c. The entries below
 * are TEST-ONLY fixtures that exercise the fixed-host and per-account mechanism.
 */

import { SNOWFLAKE_HOST_PATTERN } from "./outbound-allowlist";
import type { McpServerSpec } from "./mcp-specs";

export const CLASS_B_EGRESS_SPECS: Readonly<Record<string, McpServerSpec>> = Object.freeze({
  // TEST-ONLY fixed-host fixture. api.perplexity.ai is ALREADY in
  // ALLOWED_OUTBOUND_HOSTS, so the defense-in-depth assertion passes. Not a real
  // Class B worker host — the real host-adds are per-worker in S5c.
  "test-fixed": {
    host: "api.perplexity.ai",
    pathPrefix: "/v1/",
    authStyle: "bearer",
    baseUrlVar: "EGRESS_TEST_FIXED_BASE_URL",
  },

  // TEST-ONLY per-account fixture. Reuses the snowflake anchored pattern (already
  // an ENTERPRISE_HOST_PATTERNS conjunct, so the fetch backstop admits a matching
  // host) ONLY to exercise the spec-bound per-account branch — there is no real
  // snowflake Class B egress here. A daemon-supplied X-Bishop-Upstream-Host is
  // admitted iff it matches THIS spec's hostPattern (spec-bind, fail-closed).
  "test-peraccount": {
    hostFromUpstream: true,
    hostPattern: [SNOWFLAKE_HOST_PATTERN],
    pathPrefix: "/api/v2/",
    authStyle: "bearer",
    baseUrlVar: "EGRESS_TEST_PERACCOUNT_BASE_URL",
  },
});
