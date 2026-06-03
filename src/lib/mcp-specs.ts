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
 * Do NOT add a FIXED-host entry here without a corresponding host already present
 * in src/lib/outbound-allowlist.ts (the host must NOT widen the allowlist — Block
 * 4 adds the remaining servers as host-already-present spec entries) and a
 * <SERVER>_BASE_URL env field in src/index.ts Env (test seam only).
 *
 * W38-S735 PER-ACCOUNT specs (snowflake/netsuite/databricks/shopify): the upstream
 * host is per-customer and CANNOT be frozen. Such a spec carries `hostFromUpstream:
 * true` + `hostPattern` (the SPECIFIC anchored vendor pattern(s) from
 * outbound-allowlist.ts bound to THIS spec) instead of a `host`. The handler
 * (src/routes/mcp.ts) reads the host from the daemon-supplied X-Bishop-Upstream-Host
 * header and admits it ONLY when it matches this spec's OWN hostPattern (spec-bind,
 * SSRF-bounded to the vendor domain). The per-account host is never added to
 * ALLOWED_OUTBOUND_HOSTS — it is an anchored ENTERPRISE_HOST_PATTERNS conjunct.
 *
 * W38-S736 FROZEN-HOST-WITH-TEMPLATED-TENANT-PATH specs (microsoft-365 +
 * onedrive-sharepoint): the host is STILL frozen + allow-listed
 * (agent365.svc.cloud.microsoft) — only the per-tenant id varies, and it lives in
 * the PATH, not the host. Such a spec carries a normal frozen `host` PLUS
 * `pathTenantFromUpstream: true` and a `pathPrefix` containing a literal
 * `{tenantId}` placeholder. The handler reads a daemon-supplied
 * X-Bishop-Upstream-Path-Tenant header, GUID-validates it (a bare lowercase GUID —
 * which blocks `/`, `.`, `..` and every path-injection), and substitutes it into
 * the placeholder server-side. A path segment cannot redirect egress off a frozen
 * allow-listed host, so this is strictly lower-risk than the per-account case.
 * salesforce is a plain frozen-host spec (api.salesforce.com; org via OAuth token,
 * no per-tenant path).
 */

import {
  SNOWFLAKE_HOST_PATTERN,
  NETSUITE_HOST_PATTERN,
  SHOPIFY_HOST_PATTERN,
  DATABRICKS_AWS_HOST_PATTERN,
  DATABRICKS_AZURE_HOST_PATTERN,
  DATABRICKS_GCP_HOST_PATTERN,
} from "./outbound-allowlist";

export interface McpServerSpec {
  /**
   * Upstream MCP host for a FIXED-host server — frozen, server-side, MUST already
   * be in ALLOWED_OUTBOUND_HOSTS. `undefined` for a per-account spec (see
   * `hostFromUpstream`), where the host arrives daemon-supplied + pattern-validated.
   */
  host?: string;
  /**
   * W38-S735 — true for a per-account server whose host is per-customer and so
   * cannot be frozen. The host is read from the X-Bishop-Upstream-Host request
   * header and validated against `hostPattern` (this spec's OWN bound vendor
   * pattern). Mutually exclusive with `host`.
   */
  hostFromUpstream?: boolean;
  /**
   * W38-S735 — the SPECIFIC anchored vendor pattern(s) bound to this per-account
   * spec (spec-bind). A daemon-supplied host is admitted only when it matches one
   * of these (databricks carries 3 — one per cloud). Required iff `hostFromUpstream`.
   */
  hostPattern?: RegExp[];
  /**
   * Path prefix appended to the upstream host when forwarding the JSON-RPC POST.
   * For a `pathTenantFromUpstream` spec this contains a literal `{tenantId}`
   * placeholder the route substitutes server-side with a GUID-validated tenant.
   */
  pathPrefix: string;
  /**
   * W38-S736 — true for a frozen-host server whose PATH carries a per-tenant id
   * (microsoft-365 / onedrive-sharepoint on the shared Agent 365 host). The host
   * stays frozen + allow-listed; only `pathPrefix`'s `{tenantId}` placeholder is
   * substituted, from a daemon-supplied X-Bishop-Upstream-Path-Tenant header that
   * the route GUID-validates (bare lowercase GUID → no path-injection). Compatible
   * with `host` (the host is still frozen); never combined with `hostFromUpstream`.
   */
  pathTenantFromUpstream?: boolean;
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

  // ── W38-S731 Block 4 — the 42 verified static-host remote MCP servers ──
  // (W38-S736 adds 3 more fixed-host specs at the bottom → 45 fixed-host total.)
  // (W38-S734 removed 7 → native-covered: granola/fireflies/fathom meeting [UC1],
  //  zapier/make/ifttt/workato automation [UC16]. otter/n8n were never wired.)
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
  "zoom": {
    host: "mcp-us.zoom.us",
    pathPrefix: "/mcp/zoom/streamable",
    authStyle: "bearer",
    baseUrlVar: "MCP_ZOOM_BASE_URL",
  },

  // ── W38-S735 — the 4 PER-ACCOUNT remote MCP servers ──────────────────────
  // No frozen `host`: each upstream host is per-customer. The handler reads it
  // from X-Bishop-Upstream-Host and admits it ONLY when it matches THIS spec's
  // hostPattern (spec-bind — a snowflake request can never reach a netsuite host).
  // pathPrefix is the fixed vendor portion of the verified endpoint; the per-
  // account object path (snowflake mcp-servers/<name>, databricks
  // vector-search|functions|genie|sql/<...>) is appended at wire time and the
  // exact path is live-verified at W13.16. The host-binding is the §3.2 boundary.
  "snowflake": {
    hostFromUpstream: true,
    hostPattern: [SNOWFLAKE_HOST_PATTERN],
    // Snowflake-managed MCP: /api/v2/databases/{db}/schemas/{schema}/mcp-servers/{name}
    pathPrefix: "/api/v2",
    authStyle: "bearer",
    baseUrlVar: "MCP_SNOWFLAKE_BASE_URL",
  },
  "netsuite": {
    hostFromUpstream: true,
    hostPattern: [NETSUITE_HOST_PATTERN],
    // NetSuite SuiteTalk REST base (per-account MCP path live-verified W13.16).
    pathPrefix: "/services/rest",
    authStyle: "bearer",
    baseUrlVar: "MCP_NETSUITE_BASE_URL",
  },
  "databricks": {
    hostFromUpstream: true,
    // MULTI-CLOUD: AWS / Azure / GCP — the spec accepts ONLY databricks hosts.
    hostPattern: [
      DATABRICKS_AWS_HOST_PATTERN,
      DATABRICKS_AZURE_HOST_PATTERN,
      DATABRICKS_GCP_HOST_PATTERN,
    ],
    // Databricks managed MCP: /api/2.0/mcp/{vector-search|functions|genie|sql}/...
    pathPrefix: "/api/2.0/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_DATABRICKS_BASE_URL",
  },
  "shopify": {
    hostFromUpstream: true,
    hostPattern: [SHOPIFY_HOST_PATTERN],
    // Shopify Storefront MCP — fixed path on every store: https://<shop>.myshopify.com/api/mcp
    pathPrefix: "/api/mcp",
    authStyle: "bearer",
    baseUrlVar: "MCP_SHOPIFY_BASE_URL",
  },

  // ── W38-S736 — the 3 fixed-host remote MCP servers (last formerly-deferred) ──
  // microsoft-365 + onedrive-sharepoint share ONE frozen Microsoft Agent 365 host;
  // the per-tenant id is in the PATH (pathTenantFromUpstream) — a daemon-supplied,
  // route-GUID-validated {tenantId} segment substituted server-side. The host is
  // still frozen + allow-listed (a path segment cannot redirect egress off it).
  // salesforce is a plain frozen-host spec (org via OAuth token, no tenant path).
  // Primary server-id per entry is best-effort; the exact server-id/path suffix is
  // W13.16-live-verified (same posture as the per-account pathPrefix).
  "microsoft-365": {
    host: "agent365.svc.cloud.microsoft",
    // Work IQ Mail (primary); a future Mail/Calendar/User split is a separate item.
    pathPrefix: "/agents/tenants/{tenantId}/servers/mcp_MailTools",
    pathTenantFromUpstream: true,
    authStyle: "bearer",
    baseUrlVar: "MCP_MICROSOFT_365_BASE_URL",
  },
  "onedrive-sharepoint": {
    host: "agent365.svc.cloud.microsoft",
    // SharePoint document libraries + OneDrive ('me'); a discrete OneDrive entry
    // (mcp_OneDriveRemoteServer) is a possible future item.
    pathPrefix: "/agents/tenants/{tenantId}/servers/mcp_SharePointRemoteServer",
    pathTenantFromUpstream: true,
    authStyle: "bearer",
    baseUrlVar: "MCP_ONEDRIVE_SHAREPOINT_BASE_URL",
  },
  "salesforce": {
    host: "api.salesforce.com",
    // Salesforce Hosted MCP (GA April 2026); prod tier /platform/ (NOT /sandbox/).
    // sobject-all = full CRUD (CRM write → HIGH; gateway gates writes per-call).
    pathPrefix: "/platform/mcp/v1/platform/sobject-all",
    authStyle: "bearer",
    baseUrlVar: "MCP_SALESFORCE_BASE_URL",
  },
});
