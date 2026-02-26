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
}

function getAllRoleNames(payload: TokenPayload): string[] {
  const realmRoles = payload.realm_access?.roles || [];
  const clientRoles = Object.values(payload.resource_access || {}).flatMap(
    (access) => access.roles || []
  );
  return [...realmRoles, ...clientRoles];
}

function parseDestRole(role: string): DestPermission | null {
  if (!/^dest:/i.test(role)) return null;
  // "dest:<gatewayId>:<backendName>" — split on first two colons
  const firstColon = role.indexOf(":");
  const secondColon = role.indexOf(":", firstColon + 1);
  if (secondColon < 0) return null;
  const gatewayId = role.slice(firstColon + 1, secondColon).trim();
  const backendName = role.slice(secondColon + 1).trim();
  if (!gatewayId || !backendName) return null;
  return { gatewayId, backendName };
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
