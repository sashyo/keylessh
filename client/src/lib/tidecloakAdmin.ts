/**
 * Client-side TideCloak Admin API — calls TideCloak directly from the browser
 * using IAMService.secureFetch (DPoP-secured).
 *
 * Requires TideCloak CORS to allow the app origin.
 */
import { IAMService } from "@tidecloak/js";

// Lazy-loaded config from /api/auth/config
let _config: { realm: string; "auth-server-url": string; resource: string } | null = null;

async function getConfig() {
  if (!_config) {
    const res = await fetch("/api/auth/config");
    _config = await res.json();
  }
  return _config!;
}

async function getTcUrl() {
  const cfg = await getConfig();
  return `${cfg["auth-server-url"]}/admin/realms/${cfg.realm}`;
}

async function getClientId() {
  const cfg = await getConfig();
  return cfg.resource;
}

/**
 * Fetch wrapper for TideCloak admin API calls from the browser.
 * Uses IAMService.secureFetch which handles DPoP proof generation.
 */
async function tcFetch<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const base = await getTcUrl();
  const url = `${base}${path}`;

  // secureFetch only adds DPoP when it sees Authorization: Bearer <our token>
  const token = await IAMService.getToken();
  const response = await IAMService.secureFetch(url, {
    ...options,
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${token}`,
      ...((options.headers as Record<string, string>) || {}),
    },
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => response.statusText);
    console.error(`[tcFetch] ${options.method || "GET"} ${url} → ${response.status}:`, errorBody);
    throw new Error(`TideCloak API error: ${response.status} ${errorBody}`);
  }

  // Some endpoints return no body (204, or empty 200)
  const text = await response.text();
  if (!text) return undefined as T;

  try {
    return JSON.parse(text) as T;
  } catch {
    return text as T;
  }
}

// ============================================
// Types (match Keycloak representations)
// ============================================

interface UserRepresentation {
  id?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  enabled?: boolean;
  attributes?: Record<string, string[]>;
  [key: string]: any;
}

interface RoleRepresentation {
  id?: string;
  name?: string;
  description?: string;
  composite?: boolean;
  composites?: { client?: Record<string, string[]> };
  attributes?: Record<string, string[]>;
  [key: string]: any;
}

interface ClientRepresentation {
  id?: string;
  clientId?: string;
  [key: string]: any;
}

interface MappingsRepresentation {
  clientMappings?: Record<string, { mappings: RoleRepresentation[] }>;
  realmMappings?: RoleRepresentation[];
  [key: string]: any;
}

interface ChangeSetRequest {
  changeSetId: string;
  changeSetType: string;
  actionType: string;
}

interface KeycloakEvent {
  id: string;
  time: number;
  type: string;
  clientId?: string;
  userId?: string;
  ipAddress?: string;
  details?: Record<string, any>;
}

// ============================================
// Client lookup helpers
// ============================================

let _clientCache = new Map<string, ClientRepresentation>();

async function getClientByClientId(clientId: string): Promise<ClientRepresentation | null> {
  const cached = _clientCache.get(clientId);
  if (cached) return cached;

  const clients = await tcFetch<ClientRepresentation[]>(`/clients?clientId=${clientId}`);
  if (clients.length > 0) {
    _clientCache.set(clientId, clients[0]);
    return clients[0];
  }
  return null;
}

const REALM_MGMT = "realm-management";
const ADMIN_ROLE = "tide-realm-admin";

// ============================================
// Caching + concurrency helpers
// ============================================

interface CacheEntry<T> { data: T; expiry: number; }

const _usersWithRolesCache: { entry?: CacheEntry<any[]> } = {};
const _rolesCache: { entry?: CacheEntry<RoleRepresentation[]> } = {};
const CACHE_TTL = 30_000; // 30 seconds

/** Run async tasks with a concurrency limit */
async function limitedAll<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;
  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, () => worker()));
  return results;
}

/** Invalidate user/role caches (call after mutations) */
export function invalidateUsersCache(): void { _usersWithRolesCache.entry = undefined; }
export function invalidateRolesCache(): void { _rolesCache.entry = undefined; }

// ============================================
// User Management
// ============================================

export async function getUsers(): Promise<UserRepresentation[]> {
  return tcFetch<UserRepresentation[]>("/users?briefRepresentation=false");
}

/**
 * Fetch all users with their roles using a role-centric approach.
 * Instead of N calls (one per user for role-mappings), this makes R calls
 * (one per role to get its members) — typically far fewer since roles << users.
 *
 * 1. Fetch all users (1 call)
 * 2. Fetch client roles (1 call, cached)
 * 3. For each role, fetch users in that role (R calls)
 * 4. Also fetch admin role members (1 call)
 * 5. Build userId → roles map and merge
 *
 * Total: ~R+3 calls instead of N+1
 */
export async function getUsersWithRoles(
  users?: UserRepresentation[]
): Promise<(UserRepresentation & { clientRoles: string[] })[]> {
  // Return cached if fresh
  if (_usersWithRolesCache.entry && Date.now() < _usersWithRolesCache.entry.expiry) {
    return _usersWithRolesCache.entry.data;
  }

  const allUsers = users ?? await getUsers();

  // Build a map of userId → role names
  const userRolesMap = new Map<string, string[]>();

  // Get the app client
  const appClientId = await getClientId();
  const appClient = await getClientByClientId(appClientId);

  if (appClient?.id) {
    // Fetch client role list (cached)
    const roles = await tcFetch<RoleRepresentation[]>(`/clients/${appClient.id}/roles`).catch(() => []);

    // For each role, fetch which users have it — all in parallel (R is small)
    const roleUserPairs = await Promise.all(
      roles.map(async (role) => {
        const usersInRole = await tcFetch<UserRepresentation[]>(
          `/clients/${appClient.id}/roles/${encodeURIComponent(role.name!)}/users`
        ).catch(() => []);
        return { roleName: role.name!, userIds: usersInRole.map(u => u.id!) };
      })
    );

    // Populate the map
    for (const { roleName, userIds } of roleUserPairs) {
      for (const uid of userIds) {
        const existing = userRolesMap.get(uid) || [];
        existing.push(roleName);
        userRolesMap.set(uid, existing);
      }
    }
  }

  // Also check admin role (tide-realm-admin under realm-management client)
  try {
    const rmClient = await getClientByClientId(REALM_MGMT);
    if (rmClient?.id) {
      const adminUsers = await tcFetch<UserRepresentation[]>(
        `/clients/${rmClient.id}/roles/${encodeURIComponent(ADMIN_ROLE)}/users`
      ).catch(() => []);
      for (const u of adminUsers) {
        const existing = userRolesMap.get(u.id!) || [];
        existing.push(ADMIN_ROLE);
        userRolesMap.set(u.id!, existing);
      }
    }
  } catch { /* admin role fetch failed, skip */ }

  // Merge users with their roles
  const result = allUsers.map(u => ({
    ...u,
    clientRoles: userRolesMap.get(u.id!) || [],
  }));

  _usersWithRolesCache.entry = { data: result, expiry: Date.now() + CACHE_TTL };
  return result;
}

export async function getUserByVuid(vuid: string): Promise<UserRepresentation[]> {
  return tcFetch<UserRepresentation[]>(`/users?q=vuid:${vuid}`);
}

export async function addUser(userRep: { username: string; firstName: string; lastName: string; email: string }): Promise<void> {
  await tcFetch("/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(userRep),
  });
  invalidateUsersCache();
}

export async function updateUser(userId: string, data: { firstName: string; lastName: string; email: string }): Promise<void> {
  const user = await tcFetch<UserRepresentation>(`/users/${userId}`);
  const updated = { ...user, ...data };
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
  invalidateUsersCache();
}

export async function deleteUser(userId: string): Promise<void> {
  await tcFetch(`/users/${userId}`, { method: "DELETE" });
  invalidateUsersCache();
}

export async function setUserEnabled(userId: string, enabled: boolean): Promise<void> {
  const user = await tcFetch<UserRepresentation>(`/users/${userId}`);
  const updated = { ...user, enabled };
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
  invalidateUsersCache();
}

export async function getUserRoleMappings(userId: string): Promise<MappingsRepresentation> {
  return tcFetch<MappingsRepresentation>(`/users/${userId}/role-mappings`);
}

export async function getTideLinkUrl(userId: string, redirectUri: string): Promise<string> {
  const clientId = await getClientId();
  return tcFetch<string>(
    `/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=43200&redirect_uri=${redirectUri}&client_id=${clientId}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(["link-tide-account-action"]),
    }
  );
}

// ============================================
// Role Management
// ============================================

export async function getClientRoles(): Promise<RoleRepresentation[]> {
  // Return cached if fresh
  if (_rolesCache.entry && Date.now() < _rolesCache.entry.expiry) {
    return _rolesCache.entry.data;
  }

  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) return [];

  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles`);
  // Fetch full role details with concurrency limit
  const fullRoles = await limitedAll(
    roles.map(r => () => tcFetch<RoleRepresentation>(`/roles-by-id/${r.id}`)),
    5
  );

  _rolesCache.entry = { data: fullRoles, expiry: Date.now() + CACHE_TTL };
  return fullRoles;
}

export async function getTideRealmAdminRole(): Promise<RoleRepresentation> {
  const client = await getClientByClientId(REALM_MGMT);
  if (!client) throw new Error("No client found: " + REALM_MGMT);

  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles?search=${ADMIN_ROLE}`);
  return roles[0];
}

export async function getAllRoles(): Promise<RoleRepresentation[]> {
  const clientRoles = await getClientRoles();
  try {
    const adminRole = await getTideRealmAdminRole();
    return [...clientRoles, adminRole];
  } catch {
    return clientRoles;
  }
}

export async function createRole(data: { name: string; description?: string }): Promise<void> {
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  invalidateRolesCache();
}

export async function updateRole(roleRep: { name: string; description?: string }): Promise<void> {
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles/${roleRep.name}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(roleRep),
  });
  invalidateRolesCache();
}

export async function deleteRole(roleName: string): Promise<{ approvalCreated: boolean; message?: string }> {
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles/${roleName}`, { method: "DELETE" });
  invalidateRolesCache();

  // Check if role still exists (approval created instead of immediate delete)
  try {
    await tcFetch(`/clients/${client.id}/roles/${roleName}`);
    return { approvalCreated: true, message: "Approval request created" };
  } catch {
    return { approvalCreated: false };
  }
}

export async function grantUserRole(userId: string, roleName: string): Promise<void> {
  const isAdmin = roleName === ADMIN_ROLE;
  const client = isAdmin
    ? await getClientByClientId(REALM_MGMT)
    : await getClientByClientId(await getClientId());

  if (!client?.id) throw new Error("Client not found");

  const role = isAdmin
    ? await getTideRealmAdminRole()
    : await tcFetch<RoleRepresentation>(`/clients/${client.id}/roles/${roleName}`);

  await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([role]),
  });
  invalidateUsersCache();
}

export async function removeUserRole(userId: string, roleName: string): Promise<void> {
  const isAdmin = roleName === ADMIN_ROLE;
  const client = isAdmin
    ? await getClientByClientId(REALM_MGMT)
    : await getClientByClientId(await getClientId());

  if (!client?.id) throw new Error("Client not found");

  const role = isAdmin
    ? await getTideRealmAdminRole()
    : await tcFetch<RoleRepresentation>(`/clients/${client.id}/roles/${roleName}`);

  await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([{ id: role.id, name: role.name }]),
  });
  invalidateUsersCache();
}

// ============================================
// Events / Logs
// ============================================

export async function getClientEvents(first: number = 0, max: number = 100): Promise<KeycloakEvent[]> {
  const clientId = await getClientId();
  const params = new URLSearchParams({ first: String(first), max: String(max), client: clientId });
  return tcFetch<KeycloakEvent[]>(`/events?${params.toString()}`);
}

// ============================================
// Change Set / Approval Operations
// ============================================

export async function getUserChangeRequests(): Promise<any[]> {
  const data = await tcFetch<any[]>("/tide-admin/change-set/users/requests");
  return data.map(d => ({
    data: d,
    retrievalInfo: {
      changeSetId: d.draftRecordId,
      changeSetType: d.changeSetType,
      actionType: d.actionType,
    } as ChangeSetRequest,
  }));
}

export async function getRoleChangeRequests(): Promise<any[]> {
  const data = await tcFetch<any[]>("/tide-admin/change-set/roles/requests");
  return data.map(d => ({
    data: d,
    retrievalInfo: {
      changeSetId: d.draftRecordId,
      changeSetType: d.changeSetType,
      actionType: d.actionType,
    } as ChangeSetRequest,
  }));
}

export async function addApprovalToChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  const formData = new FormData();
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetType", changeSet.changeSetType);

  const token = await IAMService.getToken();
  const base = await getTcUrl();
  const url = `${base}/tideAdminResources/add-review`;
  const response = await IAMService.secureFetch(url, { method: "POST", body: formData, headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`Error adding approval: ${await response.text()}`);
}

export async function addRejectionToChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  const formData = new FormData();
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("changeSetType", changeSet.changeSetType);

  const token = await IAMService.getToken();
  const base = await getTcUrl();
  const url = `${base}/tideAdminResources/add-rejection`;
  const response = await IAMService.secureFetch(url, { method: "POST", body: formData, headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`Error adding rejection: ${await response.text()}`);
}

export async function commitChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch("/tide-admin/change-set/commit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet),
  });
}

export async function cancelChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch("/tide-admin/change-set/cancel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet),
  });
}

export async function getRawChangeSetRequest(changeSet: ChangeSetRequest): Promise<any[]> {
  return tcFetch("/tide-admin/change-set/sign/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ changeSets: [changeSet] }),
  });
}

export async function addApprovalWithSignedRequest(
  changeSet: ChangeSetRequest,
  signedRequest: string
): Promise<void> {
  const formData = new FormData();
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetType", changeSet.changeSetType);
  formData.append("requests", signedRequest);

  const token = await IAMService.getToken();
  const base = await getTcUrl();
  const url = `${base}/tideAdminResources/add-review`;
  const response = await IAMService.secureFetch(url, { method: "POST", body: formData, headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`Error adding approval with signed request: ${await response.text()}`);
}

// ============================================
// SSH Policy Sync (still goes through server)
// ============================================

export async function syncPolicyToTideCloak(policy: {
  roleId: string;
  contractCode?: string;
  approvalType: string;
  executionType: string;
  threshold: number;
  policyData: string;
}): Promise<void> {
  await tcFetch("/tide-admin/ssh-policies", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(policy),
  });
}
