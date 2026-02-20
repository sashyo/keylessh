/**
 * TURN permission management.
 *
 * Permissions are installed per peer IP address (port is ignored).
 * They expire after 300 seconds (5 minutes) per RFC 5766.
 */

import type { Allocation, Permission } from "./types.js";

const PERMISSION_LIFETIME = 300; // seconds

/**
 * Install or refresh a permission for a peer IP on an allocation.
 */
export function installPermission(
  allocation: Allocation,
  peerAddress: string
): void {
  const existing = allocation.permissions.get(peerAddress);
  if (existing) {
    clearTimeout(existing.refreshTimer);
  }

  const perm: Permission = {
    peerAddress,
    expiresAt: Date.now() + PERMISSION_LIFETIME * 1000,
    refreshTimer: setTimeout(() => {
      allocation.permissions.delete(peerAddress);
    }, PERMISSION_LIFETIME * 1000),
  };

  allocation.permissions.set(peerAddress, perm);
}

/**
 * Check if an allocation has a valid permission for a peer IP.
 */
export function hasPermission(
  allocation: Allocation,
  peerAddress: string
): boolean {
  const perm = allocation.permissions.get(peerAddress);
  if (!perm) return false;
  if (Date.now() > perm.expiresAt) {
    allocation.permissions.delete(peerAddress);
    return false;
  }
  return true;
}
