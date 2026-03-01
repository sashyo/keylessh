import type { TokenPayload } from "./tideJWT";

/**
 * Parse destination/endpoint roles from JWT token payload.
 *
 * Supported role prefixes:
 *   dest:<gatewayId>:<backendName>      — catch-all (grants access for any protocol)
 *   endpoint:<gatewayId>:<backendName>  — HTTP/web proxy only
 *   rdp:<gatewayId>:<backendName>       — RDP only
 *   vnc:<gatewayId>:<backendName>       — VNC only
 *
 * Split on first two colons (gateway IDs may contain dashes).
 * Mirrors the SSH role pattern in sshUsers.ts.
 */

/** Known role prefixes and the protocol they grant access to (null = all) */
export type RoleProtocol = "http" | "rdp" | "vnc" | null;

const ROLE_PREFIX_MAP: Record<string, RoleProtocol> = {
  dest: null,       // catch-all
  endpoint: "http", // HTTP/web proxy
  rdp: "rdp",
  vnc: "vnc",
};

/** All recognised role prefixes (for regex matching) */
const ROLE_PREFIXES = Object.keys(ROLE_PREFIX_MAP);
const ROLE_PREFIX_RE = new RegExp(`^(${ROLE_PREFIXES.join("|")}):`, "i");

export interface DestPermission {
  gatewayId: string;
  backendName: string;
  /** null = catch-all (dest:), otherwise protocol-specific */
  protocol: RoleProtocol;
}

function getAllRoleNames(payload: TokenPayload): string[] {
  const realmRoles = payload.realm_access?.roles || [];
  const clientRoles = Object.values(payload.resource_access || {}).flatMap(
    (access) => access.roles || []
  );
  return [...realmRoles, ...clientRoles];
}

function parseDestRole(role: string): DestPermission | null {
  const match = ROLE_PREFIX_RE.exec(role);
  if (!match) return null;
  const prefix = match[1].toLowerCase();
  const protocol = ROLE_PREFIX_MAP[prefix];
  // "<prefix>:<gatewayId>:<backendName>" — split on first two colons
  const firstColon = role.indexOf(":");
  const secondColon = role.indexOf(":", firstColon + 1);
  if (secondColon < 0) return null;
  const gatewayId = role.slice(firstColon + 1, secondColon).trim();
  const backendName = role.slice(secondColon + 1).trim();
  if (!gatewayId || !backendName) return null;
  return { gatewayId, backendName, protocol };
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

/**
 * Check if the user has access to a specific backend.
 *
 * @param permissions - Parsed dest permissions from the user's token
 * @param gatewayId  - Gateway ID to check
 * @param backendName - Backend name to check
 * @param protocol   - Protocol to check against (e.g. "rdp", "vnc", "http").
 *                     If omitted, only catch-all `dest:` roles are matched.
 */
export function hasDestAccess(
  permissions: DestPermission[],
  gatewayId: string,
  backendName: string,
  protocol?: string
): boolean {
  const gwLower = gatewayId.toLowerCase();
  const bkLower = backendName.toLowerCase();
  return permissions.some((p) => {
    if (p.gatewayId.toLowerCase() !== gwLower) return false;
    if (p.backendName.toLowerCase() !== bkLower) return false;
    // dest: (protocol === null) matches everything
    if (p.protocol === null) return true;
    // Protocol-specific role must match the requested protocol
    if (protocol && p.protocol === protocol) return true;
    return false;
  });
}
