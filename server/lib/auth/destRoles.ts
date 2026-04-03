import type { TokenPayload } from "./tideJWT";

/**
 * Parse destination/endpoint roles from JWT token payload.
 * Pattern: dest:<gatewayId>:<backendName>
 * Split on first two colons (gateway IDs may contain dashes).
 *
 * Mirrors the SSH role pattern in sshUsers.ts.
 */

export interface DestPermission {
  gatewayId: string;
  backendName: string;
  /** Windows username for RDP/EdDSA passwordless logon (from dest:gw:ep:user roles) */
  username?: string;
  /** Role prefix: "dest" or "ssh" */
  prefix: string;
}

function getAllRoleNames(payload: TokenPayload): string[] {
  const realmRoles = payload.realm_access?.roles || [];
  const clientRoles = Object.values(payload.resource_access || {}).flatMap(
    (access) => access.roles || []
  );
  return [...realmRoles, ...clientRoles];
}

function parseDestRole(role: string): DestPermission | null {
  // Match dest: or ssh: prefix
  const match = /^(dest|ssh):/i.exec(role);
  if (!match) return null;
  const prefix = match[1].toLowerCase();
  const parts = role.slice(prefix.length + 1).split(":");
  if (parts.length < 2) return null;
  const gatewayId = parts[0].trim();
  const backendName = parts[1].trim();
  if (!gatewayId || !backendName) return null;
  const username = parts.length >= 3 ? parts.slice(2).join(":").trim() : undefined;
  return { gatewayId, backendName, prefix, ...(username ? { username } : {}) };
}

export function parseDestRolesFromToken(
  payload: TokenPayload | undefined | null
): DestPermission[] {
  if (!payload) return [];

  const roles = getAllRoleNames(payload);
  const permissions: DestPermission[] = [];

  for (const role of roles) {
    if (typeof role !== "string") continue;
    const perm = parseDestRole(role);
    if (perm) permissions.push(perm);
  }

  return permissions;
}

export function hasDestAccess(
  permissions: DestPermission[],
  gatewayId: string,
  backendName: string
): boolean {
  const gwLower = gatewayId.toLowerCase();
  const bkLower = backendName.toLowerCase();
  return permissions.some(
    (p) => p.gatewayId.toLowerCase() === gwLower && p.backendName.toLowerCase() === bkLower
  );
}
