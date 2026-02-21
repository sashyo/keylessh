/**
 * JWT validation for admin dashboard access.
 * Validates TideCloak JWTs using local JWKS and checks for tide-realm-admin role.
 */

import { jwtVerify, createLocalJWKSet, type JWTPayload } from "jose";
import type { TidecloakConfig } from "../config.js";

export interface AdminAuth {
  /** Verify a JWT is valid (any authenticated user). Returns payload if valid, null otherwise. */
  verifyToken(token: string): Promise<JWTPayload | null>;
  /** Verify a JWT and check for admin role. Returns payload if valid, null otherwise. */
  verifyAdmin(token: string): Promise<JWTPayload | null>;
}

export function createAdminAuth(config: TidecloakConfig): AdminAuth {
  const JWKS = createLocalJWKSet(config.jwk);

  const issuer = config["auth-server-url"].endsWith("/")
    ? `${config["auth-server-url"]}realms/${config.realm}`
    : `${config["auth-server-url"]}/realms/${config.realm}`;

  return {
    async verifyToken(token: string): Promise<JWTPayload | null> {
      try {
        const { payload } = await jwtVerify(token, JWKS, { issuer });
        return payload;
      } catch (err) {
        console.log("[Auth] JWT verification failed:", err);
        return null;
      }
    },

    async verifyAdmin(token: string): Promise<JWTPayload | null> {
      try {
        const { payload } = await jwtVerify(token, JWKS, { issuer });

        if (!hasRealmAdminRole(payload)) {
          console.log("[Auth] JWT valid but missing tide-realm-admin role");
          return null;
        }

        return payload;
      } catch (err) {
        console.log("[Auth] JWT verification failed:", err);
        return null;
      }
    },
  };
}

function hasRealmAdminRole(payload: JWTPayload): boolean {
  const resourceAccess = payload.resource_access as
    | Record<string, { roles?: string[] }>
    | undefined;
  if (!resourceAccess) return false;

  const realmMgmt = resourceAccess["realm-management"];
  if (!realmMgmt?.roles) return false;

  return realmMgmt.roles.includes("tide-realm-admin");
}
