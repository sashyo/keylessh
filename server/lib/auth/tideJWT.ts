import { jwtVerify, createLocalJWKSet } from "jose";
import {
  initTcData,
  getAuthServerUrl,
  getJWK,
  getRealm,
  getResource,
} from "./tidecloakConfig";

export interface TokenPayload {
  sub?: string;
  email?: string;
  azp?: string;
  realm_access?: {
    roles: string[];
  };
  tideuserkey?: string;
  vuid?: string;
  given_name?: string;
  preferred_username?: string;
  name?: string;
  resource_access?: {
    [key: string]: {
      roles: string[];
    };
  };
  allowed_servers?: string[];
  exp?: number;
  iat?: number;
  // Multi-tenancy claims
  organization_id?: string;
  org_role?: string; // "global-admin" | "org-admin" | "user"
  [key: string]: any;
}

export async function verifyTideCloakToken(
  token: string,
  allowedRoles: string[]
): Promise<TokenPayload | null> {
  try {
    initTcData();
    const jwkData = getJWK();
    if (!jwkData) {
      console.error("[TideJWT] No JWK keys found in `tidecloak.json`.");
      console.error(
        "[TideJWT] Ensure that the correct client adapter config is downloaded from TideCloak."
      );
      throw new Error(
        "Missing JWK client adapter config. Update `tidecloak.json` with the correct JWK set."
      );
    }
    const JWKS = createLocalJWKSet(jwkData);
    const authServerUrl = getAuthServerUrl();
    const resource = getResource();
    const realm = getRealm();

    if (!JWKS) {
      throw new Error("No client adapter config found.");
    }
    if (!token) {
      throw new Error("No token found");
    }

    const issSlash = authServerUrl.endsWith("/") ? "" : "/";
    const thisIssuer = `${authServerUrl}${issSlash}realms/${realm}`;

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: thisIssuer,
    });

    if (!payload || typeof payload !== "object") {
      throw new Error("Invalid token payload");
    }

    const typedPayload = payload as TokenPayload;

    if (typedPayload.azp !== resource) {
      throw new Error(
        `AZP attribute failed: '${resource}' isn't '${typedPayload.azp}'`
      );
    }

    const realmAccess = typedPayload.realm_access?.roles || [];
    const clientAccess = Object.values(typedPayload.resource_access || {}).flatMap(
      (access) => access.roles
    );
    const allUserRoles = new Set([...realmAccess, ...clientAccess]);

    if (
      allowedRoles.length > 0 &&
      !allowedRoles.some((role) => Array.from(allUserRoles).includes(role))
    ) {
      throw new Error(
        `Role match failed: '${typedPayload.realm_access?.roles}' does not contain any of '${allowedRoles}'`
      );
    }

    return typedPayload;
  } catch (err) {
    console.error("[TideJWT] Token verification failed:", err);
    return null;
  }
}

export function hasRole(tokenPayload: TokenPayload, role: string): boolean {
  const realmAccess = tokenPayload.realm_access?.roles || [];
  const clientAccess = Object.values(tokenPayload.resource_access || {}).flatMap(
    (access) => access.roles
  );
  const allUserRoles = new Set([...realmAccess, ...clientAccess]);
  return allUserRoles.has(role);
}
