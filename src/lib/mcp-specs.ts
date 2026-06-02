/**
 * MCP_SERVER_SPECS — frozen per-server descriptor table for the /mcp/ forward leg (§1.18.15).
 *
 * Keyed by the URL path segment at position [2] of /mcp/<server_id>. Each entry
 * is the SOLE source of truth for the upstream host: the handler
 * (src/routes/mcp.ts) reads spec.host SERVER-SIDE at request time and NEVER
 * derives the host from the inbound request (SSRF-safe — the byok/azure/vertex
 * "host from frozen spec, never from request" discipline).
 *
 * This is the §3.2-mandated operational-egress path: Bishop's daemon routes
 * every operational outbound MCP connection through this proxy + its fixed
 * ALLOWED_OUTBOUND_HOSTS allowlist (no inference here — MCP is not a model call,
 * so there is no tier/classify/cost-meter on this leg, only a flat abuse-bound
 * quota check).
 *
 * Do NOT add an entry here without a corresponding host already present in
 * src/lib/outbound-allowlist.ts (the host must NOT widen the allowlist — Block 4
 * adds the remaining servers as host-already-present spec entries) and a
 * <SERVER>_BASE_URL env field in src/index.ts Env (test seam only).
 */

export interface McpServerSpec {
  /** Upstream MCP host — frozen, server-side, MUST already be in ALLOWED_OUTBOUND_HOSTS. */
  host: string;
  /** Path prefix appended to the upstream host when forwarding the JSON-RPC POST. */
  pathPrefix: string;
  /** Upstream auth scheme. All current MCP servers rebuild a Bearer header. */
  authStyle: "bearer";
  /** Env var name for a base-URL override (test seam — never set in production). */
  baseUrlVar: string;
}

export const MCP_SERVER_SPECS: Readonly<Record<string, McpServerSpec>> = Object.freeze({
  // github — GitHub remote MCP. api.githubcopilot.com is ALREADY in
  // ALLOWED_OUTBOUND_HOSTS (founder-approved 2026-06-02, first MCP egress host).
  github: {
    host: "api.githubcopilot.com",
    pathPrefix: "/mcp/",
    authStyle: "bearer",
    baseUrlVar: "MCP_GITHUB_BASE_URL",
  },
});
