/**
 * Server-side OIDC flow for TideCloak authentication.
 *
 * Handles authorization URL construction, code exchange, token refresh,
 * and logout URL construction. Uses Node.js native fetch — no extra deps.
 */

import { randomBytes } from "crypto";
import type { TidecloakConfig } from "../config.js";

export interface OidcEndpoints {
  authorization: string;
  token: string;
  logout: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  refresh_expires_in?: number;
  token_type: string;
}

/**
 * Derive OIDC endpoints from TideCloak config.
 * @param baseUrlOverride — Optional public URL for browser-facing endpoints
 *   (e.g. ngrok URL). Server-side endpoints always use config auth-server-url.
 */
export function getOidcEndpoints(
  config: TidecloakConfig,
  baseUrlOverride?: string
): OidcEndpoints {
  const base = (baseUrlOverride || config["auth-server-url"]).replace(
    /\/$/,
    ""
  );
  const realmPath = `${base}/realms/${config.realm}/protocol/openid-connect`;

  return {
    authorization: `${realmPath}/auth`,
    token: `${realmPath}/token`,
    logout: `${realmPath}/logout`,
  };
}

/**
 * Build the authorization redirect URL.
 * State encodes the original URL the user was trying to access.
 */
export function buildAuthUrl(
  endpoints: OidcEndpoints,
  clientId: string,
  redirectUri: string,
  originalUrl: string
): { url: string; state: string } {
  const state = Buffer.from(
    JSON.stringify({
      nonce: randomBytes(16).toString("hex"),
      redirect: originalUrl || "/",
    })
  ).toString("base64url");

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid",
    state,
  });

  return {
    url: `${endpoints.authorization}?${params}`,
    state,
  };
}

/**
 * Exchange authorization code for tokens.
 */
export async function exchangeCode(
  endpoints: OidcEndpoints,
  clientId: string,
  code: string,
  redirectUri: string
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
  });

  const res = await fetch(endpoints.token, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  return (await res.json()) as TokenResponse;
}

/**
 * Refresh an access token using a refresh token.
 */
export async function refreshAccessToken(
  endpoints: OidcEndpoints,
  clientId: string,
  refreshToken: string
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refreshToken,
  });

  const res = await fetch(endpoints.token, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token refresh failed (${res.status}): ${text}`);
  }

  return (await res.json()) as TokenResponse;
}

/**
 * Build TideCloak logout URL.
 */
export function buildLogoutUrl(
  endpoints: OidcEndpoints,
  clientId: string,
  postLogoutRedirectUri: string
): string {
  const params = new URLSearchParams({
    client_id: clientId,
    post_logout_redirect_uri: postLogoutRedirectUri,
  });

  return `${endpoints.logout}?${params}`;
}

/**
 * Parse the state parameter from the callback.
 */
export function parseState(state: string): { nonce: string; redirect: string } {
  try {
    return JSON.parse(Buffer.from(state, "base64url").toString("utf-8"));
  } catch {
    return { nonce: "", redirect: "/" };
  }
}
