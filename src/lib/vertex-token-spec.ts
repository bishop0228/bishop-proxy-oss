/**
 * §1.17.19 Vertex SA-token mint leg.
 *
 * The daemon signs an RS256 JWT (SA private key stays in daemon vault),
 * posts the jwt-bearer grant here, and receives back a short-lived
 * access_token. The SA private key never transits the proxy.
 */

export const VERTEX_TOKEN_UPSTREAM = Object.freeze({
  tokenHost: "oauth2.googleapis.com",
  tokenPath: "/token",
  tokenBaseUrlVar: "VERTEX_TOKEN_BASE_URL", // test override; falls back to https://<tokenHost>
} as const);
