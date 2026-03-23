/**
 * Client-side TideCloak API calls using DPoP secureFetch.
 * These call TideCloak directly instead of proxying through the server,
 * so the DPoP proof htu matches the TideCloak URL.
 */
import { appFetch } from "./appFetch";
import type { AdminUser, AdminRole } from "@shared/schema";
import type { ChangeSetRequest, AccessApproval, RoleApproval, TidecloakEvent } from "./api";

const ADMIN_ROLE = "tide-realm-admin";
const REALM_MGMT = "realm-management";

function getTokenPayload(): any {
  const token = localStorage.getItem("access_token");
  if (!token) throw new Error("Not authenticated");
  return JSON.parse(atob(token.split(".")[1]));
}

/** Get the TideCloak admin base URL from the JWT issuer */
function getTcAdminUrl(): string {
  const payload = getTokenPayload();
  const issuer = payload.iss as string; // e.g. "http://localhost:8080/realms/keylessh"
  return issuer.replace("/realms/", "/admin/realms/");
}

/** Get the client ID (resource) from the JWT azp claim */
function getClientIdFromToken(): string {
  return getTokenPayload().azp as string;
}

async function tcFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const baseUrl = getTcAdminUrl();
  const url = `${baseUrl}${path}`;
  const token = localStorage.getItem("access_token");

  const headers: HeadersInit = {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await appFetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => response.statusText);
    throw new Error(`TideCloak API error: ${response.status} ${errorBody}`);
  }

  // Some endpoints return no body
  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

// --- Access Approvals (User Change Requests) ---

export async function listAccessApprovals(): Promise<AccessApproval[]> {
  const data = await tcFetch<any[]>("/tide-admin/change-set/users/requests");

  return data.map((item) => {
    const firstUserRecord =
      item.userRecord && item.userRecord.length > 0 ? item.userRecord[0] : null;

    return {
      id: item.draftRecordId,
      timestamp: new Date().toISOString(),
      username: firstUserRecord?.username || "Unknown",
      role: item.role || "Unknown",
      clientId: item.clientId || "Unknown",
      commitReady:
        item.status === "APPROVED" || item.deleteStatus === "APPROVED" || false,
      decisionMade: false,
      rejectionFound: false,
      retrievalInfo: {
        changeSetId: item.draftRecordId,
        changeSetType: item.changeSetType,
        actionType: item.actionType,
      },
      data: item,
    } as AccessApproval;
  });
}

// --- Role Approvals (Role Change Requests) ---

export async function listRoleApprovals(): Promise<RoleApproval[]> {
  const data = await tcFetch<any[]>("/tide-admin/change-set/roles/requests");

  return data.map((item) => ({
    id: item.draftRecordId,
    requestType: item.actionType || item.action,
    status: item.status,
    requestedBy: item.userRecord?.[0]?.username || "Unknown",
    requestedAt: item.createdAt || new Date().toISOString(),
    role: item.role,
    compositeRole: item.compositeRole,
    clientId: item.clientId,
    changeSetType: item.changeSetType,
    userRecords: item.userRecord || [],
    retrievalInfo: {
      changeSetId: item.draftRecordId,
      changeSetType: item.changeSetType,
      actionType: item.actionType,
    },
  })) as RoleApproval[];
}

// --- Shared approval operations ---

export async function getRawChangeSet(
  changeSet: ChangeSetRequest
): Promise<
  Array<{
    changesetId: string;
    changeSetDraftRequests: string;
    requiresApprovalPopup: boolean | string;
  }>
> {
  return tcFetch("/tide-admin/change-set/sign/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ changeSets: [changeSet] }),
  });
}

export async function approveChangeRequest(
  changeSet: ChangeSetRequest,
  signedRequest?: string
): Promise<void> {
  const formData = new FormData();
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetType", changeSet.changeSetType);
  if (signedRequest) {
    formData.append("requests", signedRequest);
  }

  await tcFetch("/tideAdminResources/add-review", {
    method: "POST",
    body: formData,
  });
}

export async function rejectChangeRequest(
  changeSet: ChangeSetRequest
): Promise<void> {
  const formData = new FormData();
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("changeSetType", changeSet.changeSetType);

  await tcFetch("/tideAdminResources/add-rejection", {
    method: "POST",
    body: formData,
  });
}

export async function commitChangeRequest(
  changeSet: ChangeSetRequest
): Promise<void> {
  await tcFetch("/tide-admin/change-set/commit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet),
  });
}

export async function cancelChangeRequest(
  changeSet: ChangeSetRequest
): Promise<void> {
  await tcFetch("/tide-admin/change-set/cancel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(changeSet),
  });
}

// --- Helper: resolve client internal UUID from clientId string ---

interface ClientRepresentation {
  id?: string;
  clientId?: string;
  [key: string]: any;
}

interface RoleRepresentation {
  id?: string;
  name?: string;
  description?: string;
  clientRole?: boolean;
  containerId?: string;
  [key: string]: any;
}

async function getClientByClientId(clientId: string): Promise<ClientRepresentation | null> {
  try {
    const clients = await tcFetch<ClientRepresentation[]>(`/clients?clientId=${clientId}`);
    return clients.length > 0 ? clients[0] : null;
  } catch {
    return null;
  }
}

async function getClientById(id: string): Promise<ClientRepresentation | null> {
  try {
    return await tcFetch<ClientRepresentation>(`/clients/${id}`);
  } catch {
    return null;
  }
}

async function getClientRoleByName(roleName: string, clientUuid: string): Promise<RoleRepresentation> {
  return tcFetch<RoleRepresentation>(`/clients/${clientUuid}/roles/${roleName}`);
}

async function getTideRealmAdminRole(): Promise<RoleRepresentation> {
  const client = await getClientByClientId(REALM_MGMT);
  if (!client) throw new Error("No client found with clientId: " + REALM_MGMT);
  const roles = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles?search=${ADMIN_ROLE}`);
  return roles[0];
}

async function getRoleById(roleId: string): Promise<RoleRepresentation> {
  return tcFetch<RoleRepresentation>(`/roles-by-id/${roleId}`);
}

// --- User Management ---

export async function listUsers(): Promise<AdminUser[]> {
  const allUsers = await tcFetch<any[]>("/users?briefRepresentation=false");

  return await Promise.all(
    allUsers.map(async (u: any) => {
      const userRoles = await tcFetch<any>(`/users/${u.id}/role-mappings`).catch(() => ({}));
      const userClientRoles = userRoles.clientMappings
        ? Object.values(userRoles.clientMappings).flatMap(
            (m: any) => m.mappings?.map((role: any) => role.name!) || []
          )
        : [];

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
      } as AdminUser;
    })
  );
}

export async function addUser(data: {
  username: string;
  firstName: string;
  lastName: string;
  email: string;
}): Promise<void> {
  await tcFetch("/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: data.email,
      firstName: data.firstName,
      lastName: data.lastName,
      username: data.username,
      enabled: true,
    }),
  });
}

export async function updateUserProfile(
  userId: string,
  data: { firstName: string; lastName: string; email: string }
): Promise<void> {
  const user = await tcFetch<any>(`/users/${userId}`);
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...user, ...data }),
  });
}

export async function updateUserRoles(
  userId: string,
  rolesToAdd: string[],
  rolesToRemove: string[]
): Promise<void> {
  const appClientId = getClientIdFromToken();

  for (const roleName of rolesToAdd) {
    const client =
      roleName === ADMIN_ROLE
        ? await getClientByClientId(REALM_MGMT)
        : await getClientByClientId(appClientId);
    if (!client?.id) throw new Error(`Client not found for role grant`);

    const role =
      roleName === ADMIN_ROLE
        ? await getTideRealmAdminRole()
        : await getClientRoleByName(roleName, client.id);

    await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([role]),
    });
  }

  for (const roleName of rolesToRemove) {
    const client =
      roleName === ADMIN_ROLE
        ? await getClientByClientId(REALM_MGMT)
        : await getClientByClientId(appClientId);
    if (!client?.id) throw new Error(`Client not found for role removal`);

    const role =
      roleName === ADMIN_ROLE
        ? await getTideRealmAdminRole()
        : await getClientRoleByName(roleName, client.id);

    await tcFetch(`/users/${userId}/role-mappings/clients/${client.id}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([{ id: role.id, name: role.name }]),
    });
  }
}

export async function deleteUser(userId: string): Promise<void> {
  await tcFetch(`/users/${userId}`, { method: "DELETE" });
}

export async function setUserEnabled(userId: string, enabled: boolean): Promise<void> {
  const user = await tcFetch<any>(`/users/${userId}`);
  await tcFetch(`/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...user, enabled }),
  });
}

export async function getTideLinkUrl(userId: string, redirectUri?: string): Promise<string> {
  const clientId = getClientIdFromToken();
  const redirect = redirectUri || `${window.location.origin}/`;
  const url = `/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=43200&redirect_uri=${redirect}&client_id=${clientId}`;

  const baseUrl = getTcAdminUrl();
  const fullUrl = `${baseUrl}${url}`;
  const token = localStorage.getItem("access_token");

  const response = await appFetch(fullUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(["link-tide-account-action"]),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => response.statusText);
    throw new Error(`TideCloak API error: ${response.status} ${errorBody}`);
  }

  return await response.text();
}

// --- Role Management ---

export async function listClientRoles(): Promise<AdminRole[]> {
  const appClientId = getClientIdFromToken();
  const client = await getClientByClientId(appClientId);
  if (!client?.id) return [];

  const roleRes = await tcFetch<RoleRepresentation[]>(`/clients/${client.id}/roles`).catch(() => []);

  const roles = await Promise.all(
    roleRes.map(async (r) => {
      const full = await getRoleById(r.id!).catch(() => r);
      const role: AdminRole = {
        id: full.id!,
        name: full.name!,
        description: full.description ?? "",
        clientRole: true,
        clientId: appClientId,
      };
      return role;
    })
  );

  return roles;
}

export async function listAllRoles(): Promise<AdminRole[]> {
  const clientRoles = await listClientRoles();

  try {
    const adminRole = await getTideRealmAdminRole();
    const adminClient = await getClientByClientId(REALM_MGMT);
    const formatted: AdminRole = {
      id: adminRole.id!,
      name: adminRole.name!,
      description: adminRole.description ?? "",
      clientRole: true,
      clientId: adminClient?.clientId,
    };
    return [...clientRoles, formatted];
  } catch {
    return clientRoles;
  }
}

export async function createRole(data: { name: string; description?: string }): Promise<void> {
  const appClientId = getClientIdFromToken();
  const client = await getClientByClientId(appClientId);
  if (!client?.id) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: data.name, description: data.description }),
  });
}

export async function updateRole(data: { name: string; description?: string }): Promise<void> {
  const appClientId = getClientIdFromToken();
  const client = await getClientByClientId(appClientId);
  if (!client?.id) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles/${data.name}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: data.name, description: data.description }),
  });
}

export async function deleteRole(roleName: string): Promise<{ approvalCreated: boolean }> {
  const appClientId = getClientIdFromToken();
  const client = await getClientByClientId(appClientId);
  if (!client?.id) throw new Error("Client not found");

  await tcFetch(`/clients/${client.id}/roles/${roleName}`, { method: "DELETE" });

  // Check if the role still exists (approval created instead of immediate delete)
  try {
    await getClientRoleByName(roleName, client.id);
    return { approvalCreated: true };
  } catch {
    return { approvalCreated: false };
  }
}

// --- Access Logs ---

export async function listAccessLogs(limit: number = 100, offset: number = 0): Promise<TidecloakEvent[]> {
  const clientId = getClientIdFromToken();
  const params = new URLSearchParams({
    first: String(offset),
    max: String(limit),
    client: clientId,
  });
  return tcFetch<TidecloakEvent[]>(`/events?${params.toString()}`);
}
