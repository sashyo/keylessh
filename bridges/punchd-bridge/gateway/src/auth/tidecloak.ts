/**
 * TideCloak JWT verification using local JWKS with remote fallback.
 * Tries the local JWKS first (from config), and falls back to fetching
 * the JWKS from the TideCloak server if the local key doesn't match.
 */

import { jwtVerify, createLocalJWKSet, createRemoteJWKSet, JWTPayload } from "jose";
import type { TidecloakConfig } from "../config.js";

export interface TidecloakAuth {
  verifyToken(token: string): Promise<JWTPayload | null>;
}

export function createTidecloakAuth(
  config: TidecloakConfig,
  extraIssuers?: string[]
): TidecloakAuth {
  const localJWKS = createLocalJWKSet(config.jwk);

  const baseUrl = config["auth-server-url"].replace(/\/$/, "");
  const primaryIssuer = `${baseUrl}/realms/${config.realm}`;
  const jwksUrl = new URL(`${primaryIssuer}/protocol/openid-connect/certs`);
  const remoteJWKS = createRemoteJWKSet(jwksUrl);

  // Accept tokens from both the local and public TideCloak URLs
  const validIssuers = [primaryIssuer];
  if (extraIssuers) {
    for (const base of extraIssuers) {
      const url = base.replace(/\/$/, "");
      validIssuers.push(`${url}/realms/${config.realm}`);
    }
  }

  console.log("[Gateway] TideCloak JWKS loaded successfully");
  console.log(`[Gateway] Remote JWKS fallback: ${jwksUrl}`);
  console.log(`[Gateway] Valid issuers: ${validIssuers.join(", ")}`);

  return {
    async verifyToken(token: string): Promise<JWTPayload | null> {
      try {
        // Try local JWKS first, fall back to remote if key not found
        let payload: JWTPayload;
        try {
          ({ payload } = await jwtVerify(token, localJWKS, {
            issuer: validIssuers,
          }));
        } catch (localErr: any) {
          if (localErr?.code === "ERR_JWKS_NO_MATCHING_KEY") {
            ({ payload } = await jwtVerify(token, remoteJWKS, {
              issuer: validIssuers,
            }));
          } else {
            throw localErr;
          }
        }

        if (payload.azp !== config.resource) {
          console.log(
            `[Gateway] AZP mismatch: expected ${config.resource}, got ${payload.azp}`
          );
          return null;
        }

        return payload;
      } catch (err) {
        console.log("[Gateway] JWT verification failed:", err);
        return null;
      }
    },
  };
}
