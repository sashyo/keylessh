/**
 * TideCloak JWT verification using local JWKS.
 * Adapted from tcp-bridge pattern.
 */

import { jwtVerify, createLocalJWKSet, JWTPayload } from "jose";
import type { TidecloakConfig } from "../config.js";

export interface TidecloakAuth {
  verifyToken(token: string): Promise<JWTPayload | null>;
}

export function createTidecloakAuth(
  config: TidecloakConfig,
  extraIssuers?: string[]
): TidecloakAuth {
  const JWKS = createLocalJWKSet(config.jwk);

  const baseUrl = config["auth-server-url"].replace(/\/$/, "");
  const primaryIssuer = `${baseUrl}/realms/${config.realm}`;

  // Accept tokens from both the local and public TideCloak URLs
  const validIssuers = [primaryIssuer];
  if (extraIssuers) {
    for (const base of extraIssuers) {
      const url = base.replace(/\/$/, "");
      validIssuers.push(`${url}/realms/${config.realm}`);
    }
  }

  console.log("[Gateway] TideCloak JWKS loaded successfully");
  console.log(`[Gateway] Valid issuers: ${validIssuers.join(", ")}`);

  return {
    async verifyToken(token: string): Promise<JWTPayload | null> {
      try {
        const { payload } = await jwtVerify(token, JWKS, {
          issuer: validIssuers,
        });

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
