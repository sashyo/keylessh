import { AsyncLocalStorage } from "node:async_hooks";
import {
  ChangeSetRequest,
  ClientRepresentation,
  MappingsRepresentation,
  RoleRepresentation,
  UserRepresentation,
} from "./auth/keycloakTypes";
import { Roles } from "@shared/config/roles";
import { getAuthOverrideUrl, getRealm, getResource } from "./auth/tidecloakConfig";
import { requestDPoPProof } from "./dpopSigner";

// ============================================
// Request-scoped context — stores the authenticated user's ID
// so TideCloak API calls can request DPoP proofs via WebSocket.
// ============================================

interface TcRequestContext {
  token: string;
  userId: string;
}

const tcRequestStorage = new AsyncLocalStorage<TcRequestContext>();

/** Middleware: store token and userId in async context for TideCloak calls */
export function withTcDPoP(req: any, _res: any, next: any) {
  const token = req.accessToken as string | undefined;
  const userId = req.tokenPayload?.sub as string | undefined;
  if (token && userId) {
    tcRequestStorage.run({ token, userId }, next);
  } else {
    next();
  }
}

/**
 * Build Authorization headers for a TideCloak API call.
 * If a DPoP signer is connected, requests a fresh proof for the specific URL.
 * Falls back to Bearer token if no signer is available.
 */
export async function tcAuthHeaders(token: string, url?: string, method?: string): Promise<Record<string, string>> {
  const ctx = tcRequestStorage.getStore();
  if (ctx && url && method) {
    const proof = await requestDPoPProof(ctx.userId, url, method);
    if (proof) {
      return {
        Authorization: `DPoP ${ctx.token}`,
        DPoP: proof,
      };
    }
  }
  return { Authorization: `Bearer ${token}` };
}

/** Sync version for backwards compatibility — Bearer only */
export function tcAuthHeadersSync(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/** Fetch wrapper that handles async DPoP auth headers */
async function tcFetch(url: string, token: string, options: RequestInit = {}): Promise<Response> {
  const method = (options.method || "GET").toUpperCase();
  const authHeaders = await tcAuthHeaders(token, url, method);
  return fetch(url, {
    ...options,
    headers: {
      ...authHeaders,
      ...((options.headers as Record<string, string>) || {}),
    },
  });
}

// Lazy-evaluated getters to avoid calling config functions at module load time
const getKeycloakAuthServer = () => getAuthOverrideUrl();
const getRealm_ = () => getRealm();
const getClient = () => getResource();

/// Determine which TideCloak client a role belongs to.
function getClientForRole(roleName: string): string {
  if (roleName === Roles.Admin) return REALM_MGMT;
  return getClient();
}

const getTcUrl = () => `${getKeycloakAuthServer()}/admin/realms/${getRealm_()}`;
const getNonAdminTcUrl = () => `${getKeycloakAuthServer()}/realms/${getRealm_()}`;

const REALM_MGMT = "realm-management";

// ============================================
// Caching layer — avoids repeated slow calls to TideCloak
// ============================================

interface CacheEntry<T> {
  data: T;
  expiry: number;
}

const cache = new Map<string, CacheEntry<any>>();
const CACHE_TTL_MS = 30_000; // 30 seconds

function getCached<T>(key: string): T | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiry) {
    cache.delete(key);
    return undefined;
  }
  return entry.data as T;
}

function setCache<T>(key: string, data: T, ttl = CACHE_TTL_MS): void {
  cache.set(key, { data, expiry: Date.now() + ttl });
}

export function invalidateCache(prefix?: string): void {
  if (!prefix) {
    cache.clear();
    return;
  }
  cache.forEach((_, key) => {
    if (key.startsWith(prefix)) cache.delete(key);
  });
}

// Concurrency-limited Promise.all — runs at most `limit` tasks in parallel
async function promiseAllLimited<T>(
  tasks: (() => Promise<T>)[],
  limit: number
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;

  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

// Server-side client lookup cache (equivalent to client-side _clientCache)
const clientCache = new Map<string, { data: ClientRepresentation; expiry: number }>();
const CLIENT_CACHE_TTL = 300_000; // 5 minutes — clients rarely change


// Sync a committed policy to TideCloak's SSH policies table
export const syncPolicyToTideCloak = async (
  token: string,
  policy: {
    roleId: string;
    contractCode?: string;
    approvalType: string;
    executionType: string;
    threshold: number;
    policyData: string;
  }
): Promise<void> => {
  const url = `${getTcUrl()}/tide-admin/ssh-policies`;
  console.log(`[PolicySync] PUT ${url}`, JSON.stringify(policy).substring(0, 200));
  const response = await tcFetch(url, token, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(policy),
  });

  const responseBody = await response.text();
  console.log(`[PolicySync] Response: ${response.status} ${responseBody}`);

  if (!response.ok) {
    throw new Error(`Error syncing policy to TideCloak: ${response.status} ${responseBody}`);
  }
};

// Fetch the admin policy from TideCloak (used to authorize policy commits)
export const getAdminPolicy = async (): Promise<string> => {
  const response = await fetch(`${getNonAdminTcUrl()}/tide-policy-resources/admin-policy`);
  if (!response.ok) {
    throw new Error(`Error fetching admin policy: ${await response.text()}`);
  }
  // Returns base64-encoded policy bytes
  return await response.text();
};

export interface KeycloakEvent {
  id: string;
  time: number;
  type: string;
  clientId?: string;
  userId?: string;
  ipAddress?: string;
  details?: Record<string, any>;
}

export const GetClientEvents = async (
  token: string,
  first: number = 0,
  max: number = 100
): Promise<KeycloakEvent[]> => {
  const clientId = getClient();
  const params = new URLSearchParams({
    first: String(first),
    max: String(max),
    client: clientId,
  });

  const response = await tcFetch(`${getTcUrl()}/events?${params.toString()}`, token, { method: "GET", headers: { accept: "application/json" } });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Error fetching events: ${response.status} ${errorBody}`);
  }

  return response.json();
};

export const getUserByVuid = async (
  vuid: string,
  token: string
): Promise<UserRepresentation[]> => {
  const response = await tcFetch(`${getTcUrl()}/users?q=vuid:${vuid}`, token, { method: "GET", headers: { accept: "application/json" } });

  if (!response.ok) {
    throw new Error(`Error fetching user: ${response.statusText}`);
  }
  return response.json();
};

export const getRoleById = async (
  roleId: string,
  token: string
): Promise<RoleRepresentation> => {
  const client: ClientRepresentation | null = await getClientByClientId(
    getClient(),
    token
  );
  if (client === null) {
    return {};
  }
  const response = await tcFetch(`${getTcUrl()}/roles-by-id/${roleId}`, token, { method: "GET", headers: { accept: "application/json" } });
  if (!response.ok) {
    console.error(`Error fetching role by id: ${response.statusText}`);
    return {};
  }
  return await response.json();
};

export const getClientRoles = async (
  token: string
): Promise<RoleRepresentation[]> => {
  // Check cache
  const cacheKey = "clientRoles";
  const cached = getCached<RoleRepresentation[]>(cacheKey);
  if (cached) return cached;

  const client: ClientRepresentation | null = await getClientByClientId(
    getClient(),
    token
  );
  if (client === null) {
    return [];
  }
  const response = await tcFetch(`${getTcUrl()}/clients/${client.id}/roles`, token, { method: "GET", headers: { accept: "application/json" } });
  if (!response.ok) {
    console.error(`Error fetching client roles: ${response.statusText}`);
    return [];
  }
  // The list endpoint already returns id, name, description, clientRole, containerId
  // No need to re-fetch each role by ID
  const roles: RoleRepresentation[] = await response.json();

  setCache(cacheKey, roles);
  return roles;
};

export const getTideRealmAdminRole = async (
  token: string
): Promise<RoleRepresentation> => {
  const client: ClientRepresentation | null = await getClientByClientId(
    REALM_MGMT,
    token
  );
  if (client === null) throw new Error("No client found with clientId: " + REALM_MGMT);

  const response = await tcFetch(
    `${getTcUrl()}/clients/${client.id}/roles?search=${Roles.Admin}`, token, { method: "GET", headers: { accept: "application/json" } });
  if (!response.ok) {
    console.error(`Error fetching tide realm admin role: ${response.statusText}`);
    throw new Error("Error fetching tide realm admin role");
  }

  const roles = await response.json();
  return roles[0];
};

export const getClientByClientId = async (
  clientId: string,
  token: string
): Promise<ClientRepresentation | null> => {
  // Check cache first — client representations rarely change
  const cacheKey = `client:${clientId}`;
  const cached = clientCache.get(cacheKey);
  if (cached && Date.now() < cached.expiry) return cached.data;

  try {
    const response = await tcFetch(`${getTcUrl()}/clients?clientId=${clientId}`, token);
    if (!response.ok) {
      console.error(`Error fetching client by clientId: ${response.statusText}`);
      return null;
    }
    const clients: ClientRepresentation[] = await response.json();
    const result = clients.length > 0 ? clients[0] : null;
    if (result) clientCache.set(cacheKey, { data: result, expiry: Date.now() + CLIENT_CACHE_TTL });
    return result;
  } catch (error) {
    console.error("Error fetching client by clientId:", error);
    return null;
  }
};

export const getClientById = async (
  id: string,
  token: string
): Promise<ClientRepresentation | null> => {
  const cacheKey = `clientById:${id}`;
  const cached = clientCache.get(cacheKey);
  if (cached && Date.now() < cached.expiry) return cached.data;

  try {
    const response = await tcFetch(`${getTcUrl()}/clients/${id}`, token);
    if (!response.ok) {
      console.error(`Error fetching client by id: ${response.statusText}`);
      return null;
    }
    const result = await response.json();
    if (result) clientCache.set(cacheKey, { data: result, expiry: Date.now() + CLIENT_CACHE_TTL });
    return result;
  } catch (error) {
    console.error("Error fetching client by id:", error);
    return null;
  }
};

export const createRoleForClient = async (
  clientuuid: string,
  roleRep: RoleRepresentation,
  token: string
): Promise<void> => {
  const response = await tcFetch(`${getTcUrl()}/clients/${clientuuid}/roles`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(roleRep),
  });
  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error creating role for client: ${response.statusText}`);
    throw new Error(`Error creating role for client: ${errorBody}`);
  }
  return;
};

/// Look up a role by name without putting the name in the URL path.
/// Keycloak's GET /roles/{name} breaks on colons/slashes in role names.
/// Lists all roles for the client and finds by name.
export const getClientRoleByName = async (
  roleName: string,
  clientuuid: string,
  token: string
): Promise<RoleRepresentation> => {
  const response = await tcFetch(
    `${getTcUrl()}/clients/${clientuuid}/roles`, token);
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Error fetching client roles: ${errorBody}`);
  }
  const roles: RoleRepresentation[] = await response.json();
  const role = roles.find(r => r.name === roleName);
  if (!role) throw new Error(`Role '${roleName}' not found`);
  return role;
};

export const GetUsers = async (token: string): Promise<UserRepresentation[]> => {
  const response = await tcFetch(`${getTcUrl()}/users?briefRepresentation=false`, token);

  if (!response.ok) {
    console.error(`Error getting users: ${response.statusText}`);
    return [];
  }
  return await response.json();
};

export const GrantUserRole = async (
  userId: string,
  roleName: string,
  token: string
): Promise<void> => {
  const targetClientId = getClientForRole(roleName);
  const client = await getClientByClientId(targetClientId, token);

  if (client === null || client?.id === undefined) {
    throw new Error(`Could not grant user role, client ${targetClientId} does not exist`);
  }

  const role =
    roleName === Roles.Admin
      ? await getTideRealmAdminRole(token)
      : await getClientRoleByName(roleName, client.id, token);
  const response = await tcFetch(
    `${getTcUrl()}/users/${userId}/role-mappings/clients/${client.id}`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify([role]),
    }
  );
  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error granting user role: ${response.statusText}`);
    throw new Error(`Error granting user role: ${errorBody}`);
  }
  return;
};

export const UpdateUser = async (
  userId: string,
  firstName: string,
  lastName: string,
  email: string,
  token: string
): Promise<void> => {
  // Fetch the current user to preserve other fields
  const userResponse = await tcFetch(`${getTcUrl()}/users/${userId}`, token);

  if (!userResponse.ok) {
    throw new Error(`Error fetching user: ${userResponse.statusText}`);
  }

  const user = await userResponse.json();
  const updatedUserRep = { ...user, firstName, lastName, email };

  const response = await tcFetch(`${getTcUrl()}/users/${userId}`, token, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(updatedUserRep),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error updating user: ${response.statusText}`);
    throw new Error(`Error updating user: ${errorBody}`);
  }

  return;
};

export const DeleteUser = async (userId: string, token: string): Promise<void> => {
  const response = await tcFetch(`${getTcUrl()}/users/${userId}`, token, { method: "DELETE" });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error deleting user: ${response.statusText}`);
    throw new Error(`Error deleting user: ${errorBody}`);
  }

  return;
};

export const SetUserEnabled = async (
  userId: string,
  enabled: boolean,
  token: string
): Promise<void> => {
  // Fetch the current user to preserve other fields
  const userResponse = await tcFetch(`${getTcUrl()}/users/${userId}`, token);

  if (!userResponse.ok) {
    throw new Error(`Error fetching user: ${userResponse.statusText}`);
  }

  const user = await userResponse.json();
  const updatedUserRep = { ...user, enabled };

  const response = await tcFetch(`${getTcUrl()}/users/${userId}`, token, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(updatedUserRep),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error setting user enabled status: ${response.statusText}`);
    throw new Error(`Error setting user enabled status: ${errorBody}`);
  }

  return;
};

export interface DeleteRoleResult {
  approvalCreated: boolean;
  message?: string;
}

export const DeleteRole = async (roleName: string, token: string): Promise<DeleteRoleResult> => {
  const client: ClientRepresentation | null = await getClientByClientId(
    getClient(),
    token
  );

  // Look up role by name to get UUID (name in URL path breaks on colons/slashes)
  const role = await getClientRoleByName(roleName, client!.id!, token);

  const response = await tcFetch(
    `${getTcUrl()}/roles-by-id/${role.id}`, token, { method: "DELETE" });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error deleting role: ${response.statusText}`);
    throw new Error(`Error deleting role: ${errorBody}`);
  }

  // Invalidate roles cache
  invalidateCache("clientRoles");

  // Check if the role still exists after deletion (approval created instead of immediate delete)
  try {
    await getClientRoleByName(roleName, client!.id!, token);
    return { approvalCreated: true, message: "Approval request created" };
  } catch {
    return { approvalCreated: false };
  }
};

export const UpdateRole = async (
  roleRep: RoleRepresentation,
  token: string
): Promise<void> => {
  const client: ClientRepresentation | null = await getClientByClientId(
    getClient(),
    token
  );
  const role = await getClientRoleByName(roleRep.name!, client!.id!, token);
  if (roleRep === role) {
    return;
  }

  // Use roles-by-id to avoid colons/slashes in URL path
  const response = await tcFetch(
    `${getTcUrl()}/roles-by-id/${role.id}`, token, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(roleRep),
    }
  );

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error updating role: ${response.statusText}`);
    throw new Error(`Error updating role: ${errorBody}`);
  }

  return;
};

export const RemoveUserRole = async (
  userId: string,
  roleName: string,
  token: string
): Promise<void> => {
  const targetClientId = getClientForRole(roleName);
  const client = await getClientByClientId(targetClientId, token);

  if (client === null || client?.id === undefined) {
    throw new Error(`Could not remove user role, client ${targetClientId} does not exist`);
  }

  const role =
    roleName === Roles.Admin
      ? await getTideRealmAdminRole(token)
      : await getClientRoleByName(roleName, client.id, token);

  const response = await tcFetch(
    `${getTcUrl()}/users/${userId}/role-mappings/clients/${client.id}`, token, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify([{ id: role.id, name: role.name }]),
    }
  );
  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error removing role from user: ${response.statusText}`);
    throw new Error(`Error removing role from user: ${errorBody}`);
  }
  return;
};

export const AddUser = async (
  userRep: UserRepresentation,
  token: string
): Promise<void> => {
  const response = await tcFetch(`${getTcUrl()}/users`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(userRep),
  });
  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error adding user: ${response.statusText}`);
    throw new Error(`Error adding user: ${errorBody}`);
  }
  return;
};

export const GetUserRoleMappings = async (
  userId: string,
  token: string
): Promise<MappingsRepresentation> => {
  const response = await tcFetch(`${getTcUrl()}/users/${userId}/role-mappings`, token);

  if (!response.ok) {
    console.error(`Error getting user role mappings: ${response.statusText}`);
    return {};
  }
  return await response.json();
};

export const GetTideLinkUrl = async (
  userId: string,
  token: string,
  redirect_uri: string
) => {
  if (!userId || !token) {
    throw new Error("UserId and token must be provided.");
  }
  const response = await tcFetch(
    `${getTcUrl()}/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=43200&redirect_uri=${redirect_uri}&client_id=${getClient()}`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(["link-tide-account-action"]),
    }
  );

  if (!response.ok) {
    const errorDetails = await response.text();
    throw new Error(`Failed to fetch tide link URL: ${errorDetails}`);
  }

  return await response.text();
};

export const GetAllRoles = async (
  token: string
): Promise<RoleRepresentation[]> => {
  const clientRoles = await getClientRoles(token);

  try {
    const adminRole = await getTideRealmAdminRole(token);
    return [...clientRoles, adminRole];
  } catch {
    return clientRoles;
  }
};

// ============================================
// TideCloak Change Set API Functions
// ============================================

export const GetUserChangeRequests = async (
  token: string
): Promise<{ data: any; retrievalInfo: ChangeSetRequest }[]> => {
  const response = await tcFetch(
    `${getTcUrl()}/tide-admin/change-set/users/requests`, token);

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error getting user change requests: ${response.statusText}`);
    throw new Error(`Error getting user change requests: ${errorBody}`);
  }

  const json = await response.json();
  const result = json.map((d: any) => {
    return {
      data: d,
      retrievalInfo: {
        changeSetId: d.draftRecordId,
        changeSetType: d.changeSetType,
        actionType: d.actionType,
      } as ChangeSetRequest,
    };
  });

  return result;
};

export const GetRoleChangeRequests = async (
  token: string
): Promise<{ data: any; retrievalInfo: ChangeSetRequest }[]> => {
  const response = await tcFetch(
    `${getTcUrl()}/tide-admin/change-set/roles/requests`, token);

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error getting role change requests: ${response.statusText}`);
    throw new Error(`Error getting role change requests: ${errorBody}`);
  }

  const json = await response.json();
  const result = json.map((d: any) => {
    return {
      data: d,
      retrievalInfo: {
        changeSetId: d.draftRecordId,
        changeSetType: d.changeSetType,
        actionType: d.actionType,
      } as ChangeSetRequest,
    };
  });

  return result;
};

export const AddApprovalToChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  const formData = new FormData();
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetType", changeSet.changeSetType);

  const reviewUrl = `${getTcUrl()}/tideAdminResources/add-review`;
  const authHeaders = await tcAuthHeaders(token, reviewUrl, "POST");
  const response = await fetch(reviewUrl, {
    method: "POST",
    headers: authHeaders,
    body: formData,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(
      `Error adding approval to change set request: ${response.statusText}`
    );
    throw new Error(`Error adding approval to change set request: ${errorBody}`);
  }
  return;
};

export const AddRejectionToChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  const formData = new FormData();
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("changeSetType", changeSet.changeSetType);

  const rejectionUrl = `${getTcUrl()}/tideAdminResources/add-rejection`;
  const authHeaders = await tcAuthHeaders(token, rejectionUrl, "POST");
  const response = await fetch(rejectionUrl, {
    method: "POST",
    headers: authHeaders,
    body: formData,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(
      `Error adding rejection to change set request: ${response.statusText}`
    );
    throw new Error(
      `Error adding rejection to change set request: ${errorBody}`
    );
  }
  return;
};

export const CommitChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  const response = await tcFetch(`${getTcUrl()}/tide-admin/change-set/commit`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(changeSet),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error committing change set request: ${response.statusText}`);
    throw new Error(`Error committing change set request: ${errorBody}`);
  }
  return;
};

export const CancelChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  const response = await tcFetch(`${getTcUrl()}/tide-admin/change-set/cancel`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(changeSet),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error cancelling change set request: ${response.statusText}`);
    throw new Error(`Error cancelling change set request: ${errorBody}`);
  }
  return;
};

export interface RawChangeSetResponse {
  changesetId: string;
  changeSetDraftRequests: string;
  requiresApprovalPopup: boolean | string;
}

export const GetRawChangeSetRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<RawChangeSetResponse[]> => {
  const response = await tcFetch(`${getTcUrl()}/tide-admin/change-set/sign/batch`, token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ changeSets: [changeSet] }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error getting raw change set request: ${response.statusText}`);
    throw new Error(`Error getting raw change set request: ${errorBody}`);
  }

  const json = await response.json();
  // Returns array of all sign requests (may include user + policy requests)
  return json as RawChangeSetResponse[];
};

export const AddApprovalWithSignedRequest = async (
  changeSet: ChangeSetRequest,
  signedRequest: string,
  token: string
): Promise<void> => {
  const formData = new FormData();
  formData.append("changeSetId", changeSet.changeSetId);
  formData.append("actionType", changeSet.actionType);
  formData.append("changeSetType", changeSet.changeSetType);
  formData.append("requests", signedRequest);

  const signedReviewUrl = `${getTcUrl()}/tideAdminResources/add-review`;
  const signedAuthHeaders = await tcAuthHeaders(token, signedReviewUrl, "POST");
  const response = await fetch(signedReviewUrl, {
    method: "POST",
    headers: signedAuthHeaders,
    body: formData,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(
      `Error adding approval with signed request: ${response.statusText}`
    );
    throw new Error(`Error adding approval with signed request: ${errorBody}`);
  }
  return;
};

