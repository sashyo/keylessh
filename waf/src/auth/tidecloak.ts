/**
 * TideCloak JWT verification using local JWKS.
 * Adapted from tcp-bridge pattern.
 */

import { jwtVerify, createLocalJWKSet, JWTPayload } from "jose";
import type { TidecloakConfig } from "../config.js";

export interface TidecloakAuth {
  verifyToken(token: string): Promise<JWTPayload | null>;
}

export function createTidecloakAuth(config: TidecloakConfig): TidecloakAuth {
  const JWKS = createLocalJWKSet(config.jwk);

  const issuer = config["auth-server-url"].endsWith("/")
    ? `${config["auth-server-url"]}realms/${config.realm}`
    : `${config["auth-server-url"]}/realms/${config.realm}`;

  console.log("[WAF] TideCloak JWKS loaded successfully");

  return {
    async verifyToken(token: string): Promise<JWTPayload | null> {
      try {
        const { payload } = await jwtVerify(token, JWKS, { issuer });

        if (payload.azp !== config.resource) {
          console.log(
            `[WAF] AZP mismatch: expected ${config.resource}, got ${payload.azp}`
          );
          return null;
        }

        return payload;
      } catch (err) {
        console.log("[WAF] JWT verification failed:", err);
        return null;
      }
    },
  };
}
