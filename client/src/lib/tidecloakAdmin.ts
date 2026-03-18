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
// User Management
// ============================================

export async function getUsers(): Promise<UserRepresentation[]> {
  return tcFetch<UserRepresentation[]>("/users?briefRepresentation=false");
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
}

export async function updateUser(userId: string, data: { firstName: string; lastName: string; email: string }): Promise<void> {
  const user = await tcFetch<UserRepresentation>(`/users/${userId}`);
  const updated = { ...user, ...data };
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
}

export async function deleteUser(userId: string): Promise<void> {
  await tcFetch(`/users/${userId}`, { method: "DELETE" });
}

export async function setUserEnabled(userId: string, enabled: boolean): Promise<void> {
  const user = await tcFetch<UserRepresentation>(`/users/${userId}`);
  const updated = { ...user, enabled };
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
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
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) return [];

  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles`);
  // Fetch full role details
  const fullRoles = await Promise.all(
    roles.map(r => tcFetch<RoleRepresentation>(`/roles-by-id/${r.id}`))
  );
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
}

export async function deleteRole(roleName: string): Promise<{ approvalCreated: boolean; message?: string }> {
  const clientId = await getClientId();
  const client = await getClientByClientId(clientId);
  if (!client) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles/${roleName}`, { method: "DELETE" });

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
