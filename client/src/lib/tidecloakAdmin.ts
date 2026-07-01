/**
 * Client-side TideCloak Admin API — calls TideCloak directly from the browser
 * using IAMService.fetch() (handles DPoP + delegation automatically).
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
  return `${cfg["auth-server-url"].replace(/\/+$/, "")}/admin/realms/${cfg.realm}`;
}

async function getClientId() {
  const cfg = await getConfig();
  return cfg.resource;
}

/**
 * Fetch wrapper for TideCloak admin API calls from the browser.
 * Uses IAMService.fetch() which handles auth automatically.
 */
async function tcFetch<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const base = await getTcUrl();
  const url = `${base}${path}`;

  const response = await IAMService.fetch(url, {
    ...options,
    headers: {
      accept: "application/json",
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

const _usersCache: { entry?: CacheEntry<UserRepresentation[]> } = {};
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
export function invalidateUsersCache(): void { _usersCache.entry = undefined; _usersWithRolesCache.entry = undefined; }
export function invalidateRolesCache(): void { _rolesCache.entry = undefined; }

/** Fire-and-forget prefetch of users+roles right after login so caches are warm */
export function prefetchAdminData(): void {
  // These run in parallel, populate caches, errors are silently ignored
  getUsers().catch(() => {});
  getClientRoles().catch(() => {});
}

// ============================================
// User Management
// ============================================

export async function getUsers(): Promise<UserRepresentation[]> {
  if (_usersCache.entry && Date.now() < _usersCache.entry.expiry) {
    return _usersCache.entry.data;
  }
  const users = await tcFetch<UserRepresentation[]>("/users?briefRepresentation=false");
  _usersCache.entry = { data: users, expiry: Date.now() + CACHE_TTL };
  return users;
}

/**
 * Fetch all users with their roles using a role-centric approach.
 * Maximizes parallelism: fires users, client lookups, role list, and admin
 * members all concurrently. Only 2 sequential rounds:
 *   Round 1: users + both client lookups + role list (all parallel)
 *   Round 2: role-member fetches (all parallel)
 */
export async function getUsersWithRoles(
  users?: UserRepresentation[]
): Promise<(UserRepresentation & { clientRoles: string[] })[]> {
  // Return cached if fresh
  if (_usersWithRolesCache.entry && Date.now() < _usersWithRolesCache.entry.expiry) {
    return _usersWithRolesCache.entry.data;
  }

  // --- Round 1: fetch users + realm-management client in parallel ---
  const usersP = users ? Promise.resolve(users) : getUsers();
  const rmClientP = getClientByClientId(REALM_MGMT);
  const [allUsers, rmClient] = await Promise.all([usersP, rmClientP]);

  // --- Round 2: fetch admin members only (no per-role member listing needed) ---
  const adminUsers = rmClient?.id
    ? await tcFetch<UserRepresentation[]>(
        `/clients/${rmClient.id}/roles/${encodeURIComponent(ADMIN_ROLE)}/users`
      ).catch(() => [] as UserRepresentation[])
    : [] as UserRepresentation[];

  const adminSet = new Set(adminUsers.map(u => u.id!));

  const result = allUsers.map(u => ({
    ...u,
    clientRoles: adminSet.has(u.id!) ? [ADMIN_ROLE] : [],
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

export async function getUserClientRoleMappings(userId: string): Promise<RoleRepresentation[]> {
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client?.id) return [];
  return tcFetch<RoleRepresentation[]>(`/users/${userId}/role-mappings/clients/${client.id}`);
}

export async function getUserRealmManagementRoleMappings(userId: string): Promise<RoleRepresentation[]> {
  const client = await getClientByClientId(REALM_MGMT);
  if (!client?.id) return [];
  return tcFetch<RoleRepresentation[]>(`/users/${userId}/role-mappings/clients/${client.id}`).catch(() => []);
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

  // The list endpoint already returns id, name, description, clientRole, containerId
  // No need to re-fetch each role by ID
  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles`);

  _rolesCache.entry = { data: roles, expiry: Date.now() + CACHE_TTL };
  return roles;
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
  const clientIdStr = await getClientId();
  const client = await getClientByClientId(clientIdStr);
  if (!client) throw new Error(`Client '${clientIdStr}' not found`);

  await tcFetch(`/clients/${client.id}/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  invalidateRolesCache();
}

export async function updateRole(roleRep: { name: string; description?: string }): Promise<void> {
  const clientIdStr = await getClientId();
  const client = await getClientByClientId(clientIdStr);
  if (!client) throw new Error(`Client '${clientIdStr}' not found`);

  await tcFetch(`/clients/${client.id}/roles/${roleRep.name}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(roleRep),
  });
  invalidateRolesCache();
}

export async function deleteRole(roleName: string): Promise<{ approvalCreated: boolean; message?: string }> {
  const clientIdStr = await getClientId();
  const client = await getClientByClientId(clientIdStr);
  if (!client) throw new Error(`Client '${clientIdStr}' not found`);

  // Use role ID for deletion (role name with colons/slashes breaks URL path)
  const role = await findRoleByName(client.id, roleName);
  await tcFetch(`/roles-by-id/${role.id}`, { method: "DELETE" });
  invalidateRolesCache();

  // Check if role still exists (approval created instead of immediate delete)
  try {
    await findRoleByName(client.id, roleName);
    return { approvalCreated: true, message: "Approval request created" };
  } catch {
    return { approvalCreated: false };
  }
}

/** Determine which TideCloak client a role belongs to. */
async function getClientIdForRole(roleName: string): Promise<string> {
  if (roleName === ADMIN_ROLE) return REALM_MGMT;
  return await getClientId();
}

/// Look up a role by name without putting the name in the URL path.
/// Keycloak's GET /roles/{name} breaks on colons/slashes in role names.
/// Uses the cached roles list from getClientRoles().
async function findRoleByName(_clientUuid: string, roleName: string): Promise<RoleRepresentation> {
  let roles = await getClientRoles();
  let role = roles.find((r) => r.name === roleName);
  if (!role) {
    // Cache miss — invalidate and retry
    invalidateRolesCache();
    roles = await getClientRoles();
    role = roles.find((r) => r.name === roleName);
    if (!role) throw new Error(`Role '${roleName}' not found`);
  }
  return role;
}

export async function grantUserRole(userId: string, roleName: string): Promise<void> {
  const isAdmin = roleName === ADMIN_ROLE;
  const targetClientId = await getClientIdForRole(roleName);
  const client = await getClientByClientId(targetClientId);

  if (!client?.id) throw new Error(`Client '${targetClientId}' not found`);

  const role = isAdmin
    ? await getTideRealmAdminRole()
    : await findRoleByName(client.id, roleName);

  await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([role]),
  });
  invalidateUsersCache();
}

export async function removeUserRole(userId: string, roleName: string): Promise<void> {
  const isAdmin = roleName === ADMIN_ROLE;
  const targetClientId = await getClientIdForRole(roleName);
  const client = await getClientByClientId(targetClientId);

  if (!client?.id) throw new Error(`Client '${targetClientId}' not found`);

  const role = isAdmin
    ? await getTideRealmAdminRole()
    : await findRoleByName(client.id, roleName);

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

// NEW iga-core: one GET /iga/change-requests?status=PENDING for all entity
// types; filter client-side by entityType. Renames: draftRecordId -> id ;
// changeSetType -> entityType ; actionType UNCHANGED.
async function listPendingChangeRequests(): Promise<any[]> {
  return tcFetch<any[]>("/iga/change-requests?status=PENDING");
}

export async function getUserChangeRequests(): Promise<any[]> {
  const all = await listPendingChangeRequests();
  return all.filter(d => d.entityType === "USER").map(d => ({
    data: d,
    retrievalInfo: {
      changeSetId: d.id,
      changeSetType: d.entityType,
      actionType: d.actionType,
    } as ChangeSetRequest,
  }));
}

export async function getRoleChangeRequests(): Promise<any[]> {
  const all = await listPendingChangeRequests();
  return all.filter(d => d.entityType === "ROLE").map(d => ({
    data: d,
    retrievalInfo: {
      changeSetId: d.id,
      changeSetType: d.entityType,
      actionType: d.actionType,
    } as ChangeSetRequest,
  }));
}

// /approve = Authorize: records + auto-commits at quorum (collapses the old
// add-review + commit). firstAdmin/simple sends {}.
export async function addApprovalToChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}

// /deny replaces add-rejection (id in path, no body, 204).
export async function addRejectionToChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/deny`, {
    method: "POST",
  });
}

// Explicit apply-only commit (id in path, empty body). Usually unnecessary
// since /approve auto-commits at quorum; 412 QUORUM_NOT_MET if sub-quorum.
export async function commitChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/commit`, {
    method: "POST",
  });
}

// Cancel maps to /deny (id in path, no body, 204).
export async function cancelChangeRequest(changeSet: ChangeSetRequest): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/deny`, {
    method: "POST",
  });
}

// Phase-1 /approve (empty body): requestModel == old changeSetDraftRequests;
// mode === "needs-approval" == old requiresApprovalPopup. Mapped into the
// legacy rawRequests shape so the enclave-signing UI flow holds.
export async function getRawChangeSetRequest(changeSet: ChangeSetRequest): Promise<any[]> {
  const resp = await tcFetch<any>(`/iga/change-requests/${changeSet.changeSetId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const needsApproval = resp?.mode === "needs-approval";
  return needsApproval
    ? [{
        changesetId: resp.changeRequestId || changeSet.changeSetId,
        changeSetDraftRequests: resp.requestModel,
        requiresApprovalPopup: true,
      }]
    : [{
        changesetId: changeSet.changeSetId,
        changeSetDraftRequests: "",
        requiresApprovalPopup: false,
      }];
}

// multiAdmin phase-2: signed doken in requestModel; /approve records it toward
// threshold and auto-commits at quorum (the old multipart `requests` field).
export async function addApprovalWithSignedRequest(
  changeSet: ChangeSetRequest,
  signedRequest: string
): Promise<void> {
  await tcFetch(`/iga/change-requests/${changeSet.changeSetId}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ requestModel: signedRequest }),
  });
}

// ============================================
// SSH Policy Sync (consolidated iga-core role-policies / forseti-contracts)
// ============================================

// Repointed to the new surface (USER DIRECTION: repoint keylessh, not a shim).
// Policy is keyed by NAME == the role name (policy.roleId). The new POST
// requires `name`, `policy`, AND `policySig` as non-blank fields. iga-core's
// POLICY_SIG column is VARCHAR(512) and rejects policySig.length > 512, so the
// combined blob CANNOT go there. Correct split (mirrors the server):
//   policy    = combined signed blob (uncapped TEXT).
//   policySig = Base64 of the detached 64-byte Ed25519 sig (~88 chars, < 512).
//   policyData= combined blob (iga-core ignores it).
export async function syncPolicyToTideCloak(policy: {
  roleId: string;
  contractCode?: string;
  approvalType: string;
  executionType: string;
  threshold: number;
  policyData: string;
  // Base64 of the detached 64-byte Ed25519 signature (the bare sig from the
  // commit step, NOT the combined blob).
  policySig: string;
}): Promise<void> {
  // Step 1: upsert the Forseti contract (if supplied) to obtain a contractId.
  let contractId: string | undefined;
  if (policy.contractCode) {
    const contract = await tcFetch<any>("/iga/forseti-contracts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contractCode: policy.contractCode, name: policy.roleId }),
    });
    contractId = contract?.id;
  }

  // Step 2: upsert the role policy keyed by the role NAME.
  await tcFetch("/iga/role-policies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: policy.roleId,
      contractId,
      approvalType: policy.approvalType,
      executionType: policy.executionType,
      threshold: policy.threshold,
      // policy = combined signed blob (uncapped TEXT). policySig = detached
      // 64-byte Ed25519 sig Base64 (~88 chars, under the VARCHAR(512) cap).
      policy: policy.policyData,
      policySig: policy.policySig,
      policyData: policy.policyData,
    }),
  });
}
