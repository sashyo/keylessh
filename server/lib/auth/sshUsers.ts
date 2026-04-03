import type { TokenPayload } from "./tideJWT";
import { SSH_USERS_CLAIM_NAMES } from "@shared/config/claims";

function getAllRoleNames(payload: TokenPayload): string[] {
  const realmRoles = payload.realm_access?.roles || [];
  const clientRoles = Object.values(payload.resource_access || {}).flatMap((access) => access.roles || []);
  return [...realmRoles, ...clientRoles];
}

function parseStringArrayClaim(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.trim())
      .filter(Boolean);
  }

  if (typeof value === "string") {
    return value
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  }

  return [];
}

function parseSshUsersFromRoles(payload: TokenPayload): string[] {
  const roles = getAllRoleNames(payload);
  const extracted: string[] = [];

  for (const role of roles) {
    if (typeof role !== "string") continue;

    // Supported patterns:
    // - ssh:root                              (legacy: simple username)
    // - ssh-root                              (legacy: simple username)
    // - ssh:Gateway:Backend:username          (new: gateway-scoped with username)
    const match = role.match(/^ssh[:\-](.+)$/i);
    if (!match) continue;

    const rest = match[1].trim();
    if (!rest) continue;

    // Check if it's the new gateway format (has colons = gateway:backend:user)
    const parts = rest.split(":");
    if (parts.length >= 3) {
      // ssh:Gateway:Backend:Username — extract username
      extracted.push(parts.slice(2).join(":").trim());
    } else if (parts.length === 1) {
      // ssh:username (legacy)
      extracted.push(rest);
    }
    // ssh:Gateway:Backend (no username) — skip, no user to extract
  }

  return extracted;
}

/**
 * Get allowed SSH users for a specific gateway backend from token roles.
 * Looks for ssh:<gatewayId>:<backendName>:<username> roles.
 */
export function getSshUsersForBackend(
  payload: TokenPayload | undefined | null,
  gatewayId: string,
  backendName: string
): string[] {
  if (!payload) return [];
  const roles = getAllRoleNames(payload);
  const users: string[] = [];

  for (const role of roles) {
    if (typeof role !== "string") continue;
    if (!/^ssh:/i.test(role)) continue;
    const parts = role.slice(4).split(":");
    if (parts.length >= 3
      && parts[0].toLowerCase() === gatewayId.toLowerCase()
      && parts[1].toLowerCase() === backendName.toLowerCase()) {
      users.push(parts.slice(2).join(":").trim());
    }
  }

  return users;
}

export function getAllowedSshUsersFromToken(payload: TokenPayload | undefined | null): string[] {
  if (!payload) return [];

  const fromClaims: string[] = [];
  for (const claimName of SSH_USERS_CLAIM_NAMES) {
    fromClaims.push(...parseStringArrayClaim(payload[claimName]));
  }

  const fromRoles = parseSshUsersFromRoles(payload);
  return Array.from(new Set([...fromClaims, ...fromRoles]));
}
