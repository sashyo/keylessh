import type { Request, Response, NextFunction } from "express";
import type { OIDCUser, UserRole } from "@shared/schema";
import { Roles } from "@shared/config/roles";
import { verifyTideCloakToken, TokenPayload } from "./lib/auth/tideJWT";
import {
  GetUsers,
  GetUserRoleMappings,
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
  getClientById,
} from "./lib/tidecloakApi";
import { UserRepresentation, RoleRepresentation, ClientRepresentation } from "./lib/auth/keycloakTypes";
import { getResource } from "./lib/auth/tidecloakConfig";

// Extended Request interface with user information
export interface AuthenticatedRequest extends Request {
  user?: OIDCUser;
  accessToken?: string;
  tokenPayload?: TokenPayload;
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

  if (authHeader?.startsWith("Bearer ")) {
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

// TideCloak Admin API wrapper class
export class TidecloakAdmin {
  // Get all users with their roles
  async getUsers(token: string): Promise<AdminUser[]> {
    const allUsers = await GetUsers(token);

    const users: AdminUser[] = await Promise.all(
      allUsers.map(async (u: UserRepresentation) => {
        const userRoles = await GetUserRoleMappings(u.id!, token);
        const userClientRoles = userRoles.clientMappings
          ? Object.values(userRoles.clientMappings).flatMap(
              (m) => m.mappings?.map((role) => role.name!) || []
            )
          : [];

        // Check if user has admin role (tide-realm-admin)
        const isAdmin = userClientRoles.includes(ADMIN_ROLE);

        return {
          id: u.id ?? "",
          firstName: u.firstName ?? "",
          lastName: u.lastName ?? "",
          email: u.email ?? "",
          username: u.username,
          role: userClientRoles,
          linked: !!u.attributes?.vuid?.[0],
          enabled: u.enabled !== false, // Default to true if not set
          isAdmin,
        };
      })
    );

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
  }

  // Update user profile
  async updateUser(
    token: string,
    userId: string,
    data: { firstName: string; lastName: string; email: string }
  ): Promise<void> {
    await UpdateUser(userId, data.firstName, data.lastName, data.email, token);
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
  }

  // Delete user
  async deleteUser(token: string, userId: string): Promise<void> {
    await DeleteUser(userId, token);
  }

  // Enable or disable a user
  async setUserEnabled(token: string, userId: string, enabled: boolean): Promise<void> {
    await SetUserEnabled(userId, enabled, token);
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
  }

  // Delete a role
  async deleteRole(token: string, roleName: string): Promise<void> {
    await DeleteRole(roleName, token);
  }
}

export const tidecloakAdmin = new TidecloakAdmin();

// Legacy KeycloakAdmin class for backward compatibility
// This can be removed once all routes are updated to use tidecloakAdmin
export const keycloakAdmin = tidecloakAdmin;
