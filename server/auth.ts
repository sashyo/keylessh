import type { Request, Response, NextFunction } from "express";
import type { OIDCUser, UserRole } from "@shared/schema";
import { Roles } from "@shared/config/roles";
import { verifyTideCloakToken, TokenPayload } from "./lib/auth/tideJWT";
import crypto from "crypto";
import {
  GetUsers,
  AddUser,
  UpdateUser,
  DeleteUser,
  SetUserEnabled,
  GrantUserRole,
  RemoveUserRole,
  GetTideLinkUrl,
  GetAllRoles,
  getClientRoles,
  createRoleForClient,
  getClientByClientId,
  UpdateRole,
  DeleteRole,
  DeleteRoleResult,
  getClientById,
  invalidateCache,
} from "./lib/tidecloakApi";
import { UserRepresentation, RoleRepresentation, ClientRepresentation } from "./lib/auth/keycloakTypes";
import { getResource, getAuthOverrideUrl, getRealm } from "./lib/auth/tidecloakConfig";

// Extended Request interface with user information
export interface AuthenticatedRequest extends Request {
  user?: OIDCUser;
  accessToken?: string;
  tokenPayload?: TokenPayload;
}

// ============================================
// DPoP Proof Verification (RFC 9449)
// ============================================

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string): Buffer {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

/** Compute JWK Thumbprint (RFC 7638) — SHA-256 of the canonical JWK */
function computeJwkThumbprint(jwk: any): string {
  let canonical: string;
  if (jwk.kty === "EC") {
    canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  } else if (jwk.kty === "OKP") {
    canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  } else if (jwk.kty === "RSA") {
    canonical = `{"e":"${jwk.e}","kty":"${jwk.kty}","n":"${jwk.n}"}`;
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
  const hash = crypto.createHash("sha256").update(canonical).digest();
  return base64UrlEncode(hash);
}

// JTI replay protection — track seen JTIs with TTL
const seenJtis = new Map<string, number>();
const JTI_TTL_MS = 120_000; // 2 minutes

function checkAndStoreJti(jti: string): boolean {
  const now = Date.now();
  // Purge expired entries periodically
  if (seenJtis.size > 1000) {
    seenJtis.forEach((exp, k) => {
      if (exp < now) seenJtis.delete(k);
    });
  }
  if (seenJtis.has(jti)) return false;
  seenJtis.set(jti, now + JTI_TTL_MS);
  return true;
}

interface DPoPVerifyResult {
  valid: boolean;
  error?: string;
}

/**
 * Verify a DPoP proof JWT (RFC 9449).
 * Checks: typ, alg, signature, htm, htu, iat freshness, jti replay, cnf.jkt binding.
 */
function verifyDPoPProof(
  proofJwt: string,
  httpMethod: string,
  httpUrl: string,
  expectedJkt?: string,
): DPoPVerifyResult {
  try {
    const parts = proofJwt.split(".");
    if (parts.length !== 3) return { valid: false, error: "Invalid JWT structure" };

    const header = JSON.parse(base64UrlDecode(parts[0]).toString());
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString());

    // Check typ
    if (header.typ !== "dpop+jwt") return { valid: false, error: "Invalid typ" };

    // Check alg — support EdDSA and ES256/384/512
    const supportedAlgs = ["EdDSA", "ES256", "ES384", "ES512"];
    if (!supportedAlgs.includes(header.alg)) return { valid: false, error: `Unsupported alg: ${header.alg}` };

    // Must have jwk in header
    if (!header.jwk) return { valid: false, error: "Missing jwk in header" };

    // Import the public key and verify signature
    const publicKey = crypto.createPublicKey({ key: header.jwk, format: "jwk" });
    const signInput = `${parts[0]}.${parts[1]}`;
    const signature = base64UrlDecode(parts[2]);

    const alg = header.alg === "EdDSA" ? null : header.alg.toLowerCase().replace("es", "sha");
    const valid = crypto.verify(alg, Buffer.from(signInput), publicKey, signature);
    if (!valid) return { valid: false, error: "Invalid signature" };

    // Check htm (HTTP method)
    if (payload.htm !== httpMethod) return { valid: false, error: `htm mismatch: ${payload.htm} != ${httpMethod}` };

    // Check htu (HTTP URL, without query string)
    const expectedHtu = httpUrl.split("?")[0];
    if (payload.htu !== expectedHtu) return { valid: false, error: `htu mismatch: got=${payload.htu} expected=${expectedHtu}` };

    // Check iat freshness (allow 2 minute skew)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.iat) > 120) return { valid: false, error: "iat too far from current time" };

    // Check jti replay
    if (!payload.jti || !checkAndStoreJti(payload.jti)) return { valid: false, error: "jti missing or replayed" };

    // Check cnf.jkt binding if provided
    if (expectedJkt) {
      const thumbprint = computeJwkThumbprint(header.jwk);
      if (thumbprint !== expectedJkt) return { valid: false, error: "JWK thumbprint does not match cnf.jkt" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: `DPoP verification error: ${err}` };
  }
}

// TideCloak role names - tide-realm-admin is a client role under realm-management
const ADMIN_ROLE = Roles.Admin;
const REALM_MANAGEMENT_CLIENT = "realm-management";

// Extract user from JWT payload
function extractUserFromPayload(payload: TokenPayload): OIDCUser {
  // Check for admin role in realm-management client roles
  const clientRoles = payload.resource_access?.[REALM_MANAGEMENT_CLIENT]?.roles || [];
  const realmRoles = payload.realm_access?.roles || [];

  // Check both locations for backwards compatibility
  const isAdmin = clientRoles.includes(ADMIN_ROLE) || realmRoles.includes(ADMIN_ROLE);

  return {
    id: payload.sub || "",
    username: payload.preferred_username || payload.name || "",
    email: payload.email || "",
    role: isAdmin ? "admin" : ("user" as UserRole),
    allowedServers: payload.allowed_servers || [],
  };
}

// Middleware to authenticate requests using JWT with TideCloak verification
export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  // Check Authorization header first, then query param (for downloads via window.open)
  const authHeader = req.headers.authorization;
  let token: string | null = null;
  let isDPoP = false;

  if (authHeader?.startsWith("DPoP ")) {
    token = authHeader.substring(5);
    isDPoP = true;
  } else if (authHeader?.startsWith("Bearer ")) {
    token = authHeader.substring(7);
  } else if (typeof req.query.token === "string" && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  try {
    // Use TideCloak JWT verification with JWKS
    const payload = await verifyTideCloakToken(token, []);

    if (!payload) {
      res.status(401).json({ message: "Invalid or expired token" });
      return;
    }

    // DPoP proof verification (RFC 9449)
    const cnfJkt = (payload as any).cnf?.jkt as string | undefined;

    if (isDPoP) {
      const dpopProof = req.headers["dpop"] as string | undefined;
      if (!dpopProof) {
        res.status(401).json({ message: "DPoP proof required" });
        return;
      }

      const proto = req.headers["x-forwarded-proto"] || req.protocol;
      const requestUrl = `${proto}://${req.get("host")}${req.originalUrl.split("?")[0]}`;
      const result = verifyDPoPProof(dpopProof, req.method, requestUrl, cnfJkt);
      if (!result.valid) {
        console.warn("[Auth] DPoP proof verification failed:", result.error);
        res.status(401).json({ message: `DPoP proof invalid: ${result.error}` });
        return;
      }
    }
    // DPoP-bound tokens sent as Bearer are accepted but logged.
    // IAMService.secureFetch may not attach DPoP during fast page transitions.
    // TideCloak still enforces DPoP binding on its own endpoints.
    if (!isDPoP && cnfJkt) {
      console.warn("[Auth] DPoP-bound token sent as Bearer (cnf.jkt present but no DPoP proof)");
    }

    req.user = extractUserFromPayload(payload);
    req.accessToken = token;
    req.tokenPayload = payload;
    next();
  } catch (error) {
    console.error("[Auth] Token verification failed:", error);
    res.status(401).json({ message: "Token verification failed" });
  }
}

// Middleware to require admin role
export function requireAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  if (!req.user) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  if (req.user.role !== "admin") {
    res.status(403).json({ message: "Admin access required" });
    return;
  }

  next();
}

// Middleware to require policy creator permissions
// Allows: tide-realm-admin, realm-admin (realm-management), or policy-creator role
export function requirePolicyCreator(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  if (!req.user) {
    res.status(401).json({ message: "Authentication required" });
    return;
  }

  const payload = req.tokenPayload;
  if (!payload) {
    res.status(401).json({ message: "Token payload not available" });
    return;
  }

  // Check for policy creator permissions in various role locations
  const realmManagementRoles = payload.resource_access?.[REALM_MANAGEMENT_CLIENT]?.roles || [];
  const realmRoles = payload.realm_access?.roles || [];

  // Get the resource client roles (e.g., keylessh client)
  const resourceClient = Object.keys(payload.resource_access || {}).find(
    (key) => key !== REALM_MANAGEMENT_CLIENT && key !== "account"
  );
  const resourceRoles = resourceClient
    ? payload.resource_access?.[resourceClient]?.roles || []
    : [];

  const hasPermission =
    realmManagementRoles.includes(ADMIN_ROLE) ||
    realmManagementRoles.includes("realm-admin") ||
    realmRoles.includes(ADMIN_ROLE) ||
    realmRoles.includes("realm-admin") ||
    resourceRoles.includes("policy-creator");

  if (!hasPermission) {
    res.status(403).json({ message: "Policy creator access required" });
    return;
  }

  next();
}

// Admin User type (TideCloak Admin API shape)
export interface AdminUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  username?: string;
  role: string[];
  linked: boolean;
  enabled: boolean;
  isAdmin: boolean;
}

// Admin Role type (TideCloak Admin API shape)
export interface AdminRole {
  id: string;
  name: string;
  description?: string;
  clientRole?: boolean;
  clientId?: string;
}

// Simple TTL cache for expensive aggregated queries
interface CacheEntry<T> { data: T; expiry: number; }
const usersCache: { entry?: CacheEntry<AdminUser[]> } = {};
const USERS_CACHE_TTL = 30_000; // 30 seconds

// TideCloak Admin API wrapper class
export class TidecloakAdmin {
  // Get all users with their roles (role-centric approach: R+3 calls instead of N+1)
  async getUsers(token: string): Promise<AdminUser[]> {
    // Return cached if fresh
    if (usersCache.entry && Date.now() < usersCache.entry.expiry) {
      return usersCache.entry.data;
    }

    const allUsers = await GetUsers(token);

    // Build userId → role names map using role-centric fetching
    const userRolesMap = new Map<string, string[]>();

    // Get app client roles and their members
    const appClient = await getClientByClientId(getResource(), token);
    if (appClient?.id) {
      const tcUrl = `${getAuthOverrideUrl()}/admin/realms/${getRealm()}`;
      // Fetch role list for the app client
      const rolesRes = await fetch(`${tcUrl}/clients/${appClient.id}/roles`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (rolesRes.ok) {
        const roles: RoleRepresentation[] = await rolesRes.json();

        // For each role, fetch its users
        // Skip VPN firewall roles (colons/slashes break URL path)
        await Promise.all(
          roles
            .filter((role) => {
              const name = role.name || "";
              return !(name.includes(":allow:") || name.includes(":deny:"));
            })
            .map(async (role) => {
              try {
                const usersRes = await fetch(
                  `${tcUrl}/clients/${appClient.id}/roles/${encodeURIComponent(role.name!)}/users`,
                  { headers: { Authorization: `Bearer ${token}` } }
                );
                if (usersRes.ok) {
                  const roleUsers: UserRepresentation[] = await usersRes.json();
                  for (const u of roleUsers) {
                    const existing = userRolesMap.get(u.id!) || [];
                    existing.push(role.name!);
                    userRolesMap.set(u.id!, existing);
                  }
                }
              } catch { /* skip failed role lookup */ }
            })
        );

        // For VPN firewall roles, get assignments via user role-mappings instead
        const fwRoles = roles.filter((r) => {
          const name = r.name || "";
          return name.includes(":allow:") || name.includes(":deny:");
        });
        if (fwRoles.length > 0) {
          // Get all users and check their role-mappings
          const usersRes = await fetch(`${tcUrl}/users?briefRepresentation=true`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (usersRes.ok) {
            const allUsers: UserRepresentation[] = await usersRes.json();
            await Promise.all(
              allUsers.map(async (user) => {
                try {
                  const mappingsRes = await fetch(
                    `${tcUrl}/users/${user.id}/role-mappings/clients/${appClient.id}`,
                    { headers: { Authorization: `Bearer ${token}` } }
                  );
                  if (mappingsRes.ok) {
                    const mappedRoles: RoleRepresentation[] = await mappingsRes.json();
                    for (const mr of mappedRoles) {
                      if (fwRoles.some((fw) => fw.id === mr.id)) {
                        const existing = userRolesMap.get(user.id!) || [];
                        existing.push(mr.name!);
                        userRolesMap.set(user.id!, existing);
                      }
                    }
                  }
                } catch { /* skip */ }
              })
            );
          }
        }
      }
    }

    // Also check admin role members
    try {
      const rmClient = await getClientByClientId(REALM_MANAGEMENT_CLIENT, token);
      if (rmClient?.id) {
        const tcUrl = `${getAuthOverrideUrl()}/admin/realms/${getRealm()}`;
        const adminRes = await fetch(
          `${tcUrl}/clients/${rmClient.id}/roles/${encodeURIComponent(ADMIN_ROLE)}/users`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if (adminRes.ok) {
          const adminUsers: UserRepresentation[] = await adminRes.json();
          for (const u of adminUsers) {
            const existing = userRolesMap.get(u.id!) || [];
            existing.push(ADMIN_ROLE);
            userRolesMap.set(u.id!, existing);
          }
        }
      }
    } catch { /* admin role fetch failed */ }

    const users: AdminUser[] = allUsers.map((u: UserRepresentation) => {
      const userClientRoles = userRolesMap.get(u.id!) || [];
      const isAdmin = userClientRoles.includes(ADMIN_ROLE);
      return {
        id: u.id ?? "",
        firstName: u.firstName ?? "",
        lastName: u.lastName ?? "",
        email: u.email ?? "",
        username: u.username,
        role: userClientRoles,
        linked: !!u.attributes?.vuid?.[0],
        enabled: u.enabled !== false,
        isAdmin,
      };
    });

    usersCache.entry = { data: users, expiry: Date.now() + USERS_CACHE_TTL };
    return users;
  }

  // Add a new user
  async addUser(
    token: string,
    userData: { username: string; firstName: string; lastName: string; email: string }
  ): Promise<void> {
    const userRep: UserRepresentation = {
      email: userData.email,
      firstName: userData.firstName,
      lastName: userData.lastName,
      username: userData.username,
      enabled: true,
    };
    await AddUser(userRep, token);
    usersCache.entry = undefined;
  }

  // Update user profile
  async updateUser(
    token: string,
    userId: string,
    data: { firstName: string; lastName: string; email: string }
  ): Promise<void> {
    await UpdateUser(userId, data.firstName, data.lastName, data.email, token);
    usersCache.entry = undefined;
  }

  // Update user roles
  async updateUserRoles(
    token: string,
    userId: string,
    rolesToAdd: string[],
    rolesToRemove: string[]
  ): Promise<void> {
    for (const role of rolesToAdd) {
      await GrantUserRole(userId, role, token);
    }
    for (const role of rolesToRemove) {
      await RemoveUserRole(userId, role, token);
    }
    usersCache.entry = undefined;
  }

  // Delete user
  async deleteUser(token: string, userId: string): Promise<void> {
    await DeleteUser(userId, token);
    usersCache.entry = undefined;
  }

  // Enable or disable a user
  async setUserEnabled(token: string, userId: string, enabled: boolean): Promise<void> {
    await SetUserEnabled(userId, enabled, token);
    usersCache.entry = undefined;
  }

  // Get Tide link URL for account linking
  async getTideLinkUrl(
    token: string,
    userId: string,
    redirectUri: string
  ): Promise<string> {
    return await GetTideLinkUrl(userId, token, redirectUri);
  }

  // Get all roles (client roles + admin role)
  async getAllRoles(token: string): Promise<AdminRole[]> {
    const roles = await GetAllRoles(token);

    const formattedRoles = await Promise.all(
      roles.map(async (r: RoleRepresentation) => {
        const role: AdminRole = {
          id: r.id!,
          name: r.name!,
          description: r.description ?? "",
          clientRole: false,
        };

        if (r.clientRole) {
          const client: ClientRepresentation | null = await getClientById(
            r.containerId!,
            token
          );
          role.clientRole = true;
          role.clientId = client?.clientId!;
        }

        return role;
      })
    );

    return formattedRoles;
  }

  // Get client roles only (without admin role)
  async getClientRoles(token: string): Promise<AdminRole[]> {
    const roles = await getClientRoles(token);

    const formattedRoles = await Promise.all(
      roles.map(async (r: RoleRepresentation) => {
        const role: AdminRole = {
          id: r.id!,
          name: r.name!,
          description: r.description ?? "",
          clientRole: false,
        };

        if (r.clientRole) {
          const client: ClientRepresentation | null = await getClientById(
            r.containerId!,
            token
          );
          role.clientRole = true;
          role.clientId = client?.clientId!;
        }

        return role;
      })
    );

    return formattedRoles;
  }

  // Create a new role
  async createRole(
    token: string,
    roleData: { name: string; description?: string }
  ): Promise<void> {
    const client = await getClientByClientId(getResource(), token);
    if (!client) {
      throw new Error("Client not found");
    }

    const roleRep: RoleRepresentation = {
      name: roleData.name,
      description: roleData.description,
    };
    await createRoleForClient(client.id!, roleRep, token);
    invalidateCache("clientRoles");
  }

  // Update a role
  async updateRole(
    token: string,
    roleData: { name: string; description?: string }
  ): Promise<void> {
    const roleRep: RoleRepresentation = {
      name: roleData.name,
      description: roleData.description,
    };
    await UpdateRole(roleRep, token);
    invalidateCache("clientRoles");
  }

  // Delete a role
  async deleteRole(token: string, roleName: string): Promise<DeleteRoleResult> {
    const result = await DeleteRole(roleName, token);
    invalidateCache("clientRoles");
    return result;
  }
}

export const tidecloakAdmin = new TidecloakAdmin();

// Legacy KeycloakAdmin class for backward compatibility
// This can be removed once all routes are updated to use tidecloakAdmin
export const keycloakAdmin = tidecloakAdmin;
