/**
 * §1.17.19 Google Vertex AI Bearer distinct-auth BYOK leg.
 *
 * NO operatorKeyVar — Vertex is BYOK-only; managed mode fails closed
 * (vertex_requires_byok, 400). Operator path is structurally unrepresentable.
 *
 * Auth model: the DAEMON mints a short-lived OAuth2 access token from the
 * Service-Account key (daemon token-lifecycle, like the Copilot secondary mint)
 * and sends it as x-bishop-upstream-key="<region>:<accessToken>". The proxy
 * forwards it as Authorization: Bearer — it never sees the SA private key, never
 * signs a JWT, and never fetches oauth2.googleapis.com (egress surface stays narrow).
 */

export interface VertexUpstreamSpec {
  hostSuffix: string;
  baseUrlVar: string;
}

export const VERTEX_UPSTREAM: VertexUpstreamSpec = {
  hostSuffix: "-aiplatform.googleapis.com",
  baseUrlVar: "VERTEX_BASE_URL",
};
