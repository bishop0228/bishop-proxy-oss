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

  // ── W38-S731 Block 4 — the 49 verified static-host remote MCP servers ──
  // Each replicates the github shape (host frozen + server-side; pathPrefix is
  // the path after the host in the verified endpoint; baseUrlVar is the
  // test-seam override, never set in production). Every host below is ALREADY
  // in src/lib/outbound-allowlist.ts (Block 4 added them in the same change) —
  // the route (src/routes/mcp.ts step 3) refuses any spec whose host is not
  // allow-listed. Source of truth: W38-S730 VERIFIED FINAL (corrected
  // endpoints: atlassian /v1/mcp/authv2, monday /mcp). Root-path servers
  // (box/hubspot/lovable/stripe/vercel) carry pathPrefix "".
  "amplitude": {
    host: "mcp.amplitude.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_AMPLITUDE_BASE_URL",
  },
  "asana": {
    host: "mcp.asana.com",
    pathPrefix: "/v2/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_ASANA_BASE_URL",
  },
  "atlassian": {
    host: "mcp.atlassian.com",
    pathPrefix: "/v1/mcp/authv2",
    authStyle: "bearer",
    baseUrlVar: "MCP_ATLASSIAN_BASE_URL",
  },
  "attio": {
    host: "mcp.attio.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_ATTIO_BASE_URL",
  },
  "base44": {
    host: "app.base44.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_BASE44_BASE_URL",
  },
  "bigquery": {
    host: "bigquery.googleapis.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_BIGQUERY_BASE_URL",
  },
  "box": {
    host: "mcp.box.com",
    pathPrefix: "",
    authStyle: "bearer",
    baseUrlVar: "MCP_BOX_BASE_URL",
  },
  "brex": {
    host: "api.brex.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_BREX_BASE_URL",
  },
  "canva": {
    host: "mcp.canva.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_CANVA_BASE_URL",
  },
  "close": {
    host: "mcp.close.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_CLOSE_BASE_URL",
  },
  "cloudflare": {
    host: "mcp.cloudflare.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_CLOUDFLARE_BASE_URL",
  },
  "context7": {
    host: "mcp.context7.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_CONTEXT7_BASE_URL",
  },
  "datadog": {
    host: "mcp.datadoghq.com",
    pathPrefix: "/api/unstable/mcp-server/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_DATADOG_BASE_URL",
  },
  "dropbox": {
    host: "mcp.dropbox.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_DROPBOX_BASE_URL",
  },
  "exa": {
    host: "mcp.exa.ai",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_EXA_BASE_URL",
  },
  "fathom": {
    host: "api.fathom.ai",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_FATHOM_BASE_URL",
  },
  "figma": {
    host: "mcp.figma.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_FIGMA_BASE_URL",
  },
  "firecrawl": {
    host: "mcp.firecrawl.dev",
    pathPrefix: "/v2/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_FIRECRAWL_BASE_URL",
  },
  "fireflies": {
    host: "api.fireflies.ai",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_FIREFLIES_BASE_URL",
  },
  "gitlab": {
    host: "gitlab.com",
    pathPrefix: "/api/v4/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_GITLAB_BASE_URL",
  },
  "gmail": {
    host: "gmailmcp.googleapis.com",
    pathPrefix: "/mcp/v1",
    authStyle: "bearer",
    baseUrlVar: "MCP_GMAIL_BASE_URL",
  },
  "google-calendar": {
    host: "calendarmcp.googleapis.com",
    pathPrefix: "/mcp/v1",
    authStyle: "bearer",
    baseUrlVar: "MCP_GOOGLE_CALENDAR_BASE_URL",
  },
  "google-drive": {
    host: "drivemcp.googleapis.com",
    pathPrefix: "/mcp/v1",
    authStyle: "bearer",
    baseUrlVar: "MCP_GOOGLE_DRIVE_BASE_URL",
  },
  "grafana": {
    host: "mcp.grafana.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_GRAFANA_BASE_URL",
  },
  "granola": {
    host: "mcp.granola.ai",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_GRANOLA_BASE_URL",
  },
  "honeycomb": {
    host: "mcp.honeycomb.io",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_HONEYCOMB_BASE_URL",
  },
  "hubspot": {
    host: "mcp.hubspot.com",
    pathPrefix: "",
    authStyle: "bearer",
    baseUrlVar: "MCP_HUBSPOT_BASE_URL",
  },
  "ifttt": {
    host: "ifttt.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_IFTTT_BASE_URL",
  },
  "linear": {
    host: "mcp.linear.app",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_LINEAR_BASE_URL",
  },
  "lovable": {
    host: "mcp.lovable.dev",
    pathPrefix: "",
    authStyle: "bearer",
    baseUrlVar: "MCP_LOVABLE_BASE_URL",
  },
  "make": {
    host: "mcp.make.com",
    pathPrefix: "/sse",
    authStyle: "bearer",
    baseUrlVar: "MCP_MAKE_BASE_URL",
  },
  "mixpanel": {
    host: "mcp.mixpanel.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_MIXPANEL_BASE_URL",
  },
  "monday": {
    host: "mcp.monday.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_MONDAY_BASE_URL",
  },
  "neon": {
    host: "mcp.neon.tech",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_NEON_BASE_URL",
  },
  "notion": {
    host: "mcp.notion.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_NOTION_BASE_URL",
  },
  "pagerduty": {
    host: "mcp.pagerduty.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_PAGERDUTY_BASE_URL",
  },
  "paypal": {
    host: "mcp.paypal.com",
    pathPrefix: "/sse",
    authStyle: "bearer",
    baseUrlVar: "MCP_PAYPAL_BASE_URL",
  },
  "posthog": {
    host: "mcp.posthog.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_POSTHOG_BASE_URL",
  },
  "ramp": {
    host: "mcp.ramp.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_RAMP_BASE_URL",
  },
  "sentry": {
    host: "mcp.sentry.dev",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_SENTRY_BASE_URL",
  },
  "slack": {
    host: "mcp.slack.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_SLACK_BASE_URL",
  },
  "square": {
    host: "mcp.squareup.com",
    pathPrefix: "/sse",
    authStyle: "bearer",
    baseUrlVar: "MCP_SQUARE_BASE_URL",
  },
  "stripe": {
    host: "mcp.stripe.com",
    pathPrefix: "",
    authStyle: "bearer",
    baseUrlVar: "MCP_STRIPE_BASE_URL",
  },
  "supabase": {
    host: "mcp.supabase.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_SUPABASE_BASE_URL",
  },
  "tavily": {
    host: "mcp.tavily.com",
    pathPrefix: "/mcp/",
    authStyle: "bearer",
    baseUrlVar: "MCP_TAVILY_BASE_URL",
  },
  "vercel": {
    host: "mcp.vercel.com",
    pathPrefix: "",
    authStyle: "bearer",
    baseUrlVar: "MCP_VERCEL_BASE_URL",
  },
  "workato": {
    host: "app.workato.com",
    pathPrefix: "/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_WORKATO_BASE_URL",
  },
  "zapier": {
    host: "mcp.zapier.com",
    pathPrefix: "/api/v1/connect",
    authStyle: "bearer",
    baseUrlVar: "MCP_ZAPIER_BASE_URL",
  },
  "zoom": {
    host: "mcp-us.zoom.us",
    pathPrefix: "/mcp/zoom/streamable",
    authStyle: "bearer",
    baseUrlVar: "MCP_ZOOM_BASE_URL",
  },
});
