import {
  ChangeSetRequest,
  ClientRepresentation,
  MappingsRepresentation,
  RoleRepresentation,
  UserRepresentation,
} from "./auth/keycloakTypes";
import { Roles } from "@shared/config/roles";
import fs from "fs";
import path from "path";
import { getAuthOverrideUrl, getRealm, getResource } from "./auth/tidecloakConfig";
import { TideDelegation } from "asgard-tide/node";

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


// Sync a committed policy to TideCloak via the consolidated iga-core
// role-policies / forseti-contracts surface (replaces the removed
// PUT /tide-admin/ssh-policies). Two writes, both requireManageRealm (admin
// bearer token; NO mTLS/delegation):
//   1. If contractCode is present, upsert the Forseti contract
//      (POST /iga/forseti-contracts {contractCode, name}) -> {id}, and bind the
//      returned contractId to the role policy.
//   2. Upsert the role policy (POST /iga/role-policies). iga-core keys policies
//      by NAME; keylessh keys SSH policies by ROLE NAME (roleId), so name ==
//      policy.roleId. `policySig` is REQUIRED, non-blank, and hard-capped at
//      512 chars: it is the detached 64-byte Ed25519 signature (Base64, ~88
//      chars) that keylessh already produced via the enclave/ORK sign — NOT the
//      combined blob. The combined signed blob rides in `policy` (uncapped TEXT).
// Since the server-side delegation refactor (asgard server-identity), the two
// iga-core writes (/iga/forseti-contracts, /iga/role-policies) go through the
// cert-bound delegation helper attached to the request by
// getDelegation().requireDelegation() — req.delegation. Its `.fetch` carries the
// delegated admin token over the mTLS channel, parses JSON, and throws on
// non-2xx, so the mirror authenticates the same way every server-side admin op
// does.
export interface DelegationFetch {
  token: string;
  fetch: (url: string, opts?: { method?: string; body?: any; formData?: any }) => Promise<any>;
}

export const syncPolicyToTideCloak = async (
  delegation: DelegationFetch,
  policy: {
    roleId: string;
    contractCode?: string;
    approvalType: string;
    executionType: string;
    threshold: number;
    policyData: string;
    // Base64 of the detached 64-byte Ed25519 signature (the bare sig, under the
    // VARCHAR(512) cap). Plumbed from the commit step where the raw signature
    // bytes exist before they are collapsed into policyData.
    policySig: string;
  }
): Promise<void> => {
  // Step 1: upsert the Forseti contract (if supplied) to obtain a contractId.
  let contractId: string | undefined;
  if (policy.contractCode) {
    const contractUrl = `${getTcUrl()}/iga/forseti-contracts`;
    // delegation.fetch returns the parsed JSON body and throws on non-2xx.
    const contractBody = await delegation.fetch(contractUrl, {
      method: "POST",
      body: { contractCode: policy.contractCode, name: policy.roleId },
    });
    contractId = contractBody?.id;
  }

  // Step 2: upsert the role policy keyed by the role NAME.
  const url = `${getTcUrl()}/iga/role-policies`;
  const body = {
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
  };
  console.log(`[PolicySync] POST ${url}`, JSON.stringify({ ...body, policy: "<redacted>", policySig: "<redacted>", policyData: "<redacted>" }));
  await delegation.fetch(url, { method: "POST", body });
  console.log(`[PolicySync] role-policy mirror upserted for ${policy.roleId}`);
};

// NOTE: the tide-realm-admin admin policy that the ORK PreSign requires is now
// fetched CLIENT-SIDE via the DPoP-authenticated path (client/src/lib/
// tidecloakAdmin.ts `getAdminPolicy` -> tcFetch), not server-side. The old
// server-side getAdminPolicy fetched GET /iga/role-policies/name/tide-realm-admin
// with the forwarded plain Bearer token, which iga-core's admin surface rejects
// with 401 (no DPoP proof), so it never worked. It was removed to leave a single
// working path.

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

  const response = await fetch(`${getTcUrl()}/events?${params.toString()}`, {
    method: "GET",
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

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
  const response = await fetch(`${getTcUrl()}/users?q=vuid:${vuid}`, {
    method: "GET",
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

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
  const response = await fetch(`${getTcUrl()}/roles-by-id/${roleId}`, {
    method: "GET",
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });
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
  const response = await fetch(`${getTcUrl()}/clients/${client.id}/roles`, {
    method: "GET",
    headers: {
      accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });
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

  const response = await fetch(
    `${getTcUrl()}/clients/${client.id}/roles?search=${Roles.Admin}`,
    {
      method: "GET",
      headers: {
        accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    }
  );
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
    const response = await fetch(`${getTcUrl()}/clients?clientId=${clientId}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
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
    const response = await fetch(`${getTcUrl()}/clients/${id}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
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
  const response = await fetch(`${getTcUrl()}/clients/${clientuuid}/roles`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(roleRep),
  });
  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error creating role for client: ${response.statusText}`);
    throw new Error(`Error creating role for client: ${errorBody}`);
  }
  return;
};

export const getClientRoleByName = async (
  roleName: string,
  clientuuid: string,
  token: string
): Promise<RoleRepresentation> => {
  const response = await fetch(
    `${getTcUrl()}/clients/${clientuuid}/roles/${roleName}`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );
  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error fetching client role by name: ${response.statusText}`);
    throw new Error(`Error fetching client role by name: ${errorBody}`);
  }
  return response.json();
};

export const GetUsers = async (token: string): Promise<UserRepresentation[]> => {
  const response = await fetch(`${getTcUrl()}/users?briefRepresentation=false`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

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
  const response = await fetch(
    `${getTcUrl()}/users/${userId}/role-mappings/clients/${client.id}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify([role]),
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
  const userResponse = await fetch(`${getTcUrl()}/users/${userId}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!userResponse.ok) {
    throw new Error(`Error fetching user: ${userResponse.statusText}`);
  }

  const user = await userResponse.json();
  const updatedUserRep = { ...user, firstName, lastName, email };

  const response = await fetch(`${getTcUrl()}/users/${userId}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(updatedUserRep),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error updating user: ${response.statusText}`);
    throw new Error(`Error updating user: ${errorBody}`);
  }

  return;
};

export const DeleteUser = async (userId: string, token: string): Promise<void> => {
  const response = await fetch(`${getTcUrl()}/users/${userId}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

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
  const userResponse = await fetch(`${getTcUrl()}/users/${userId}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!userResponse.ok) {
    throw new Error(`Error fetching user: ${userResponse.statusText}`);
  }

  const user = await userResponse.json();
  const updatedUserRep = { ...user, enabled };

  const response = await fetch(`${getTcUrl()}/users/${userId}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(updatedUserRep),
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
  const response = await fetch(
    `${getTcUrl()}/clients/${client!.id!}/roles/${roleName}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error deleting role: ${response.statusText}`);
    throw new Error(`Error deleting role: ${errorBody}`);
  }

  // Check if the role still exists after deletion
  // If it does, an approval was created instead of immediate deletion
  try {
    await getClientRoleByName(roleName, client!.id!, token);
    // Role still exists - approval was created
    return { approvalCreated: true, message: "Approval request created" };
  } catch {
    // Role doesn't exist - it was deleted immediately
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

  const response = await fetch(
    `${getTcUrl()}/clients/${client!.id!}/roles/${roleRep.name!}`,
    {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(roleRep),
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

  const response = await fetch(
    `${getTcUrl()}/users/${userId}/role-mappings/clients/${client.id}`,
    {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify([{ id: role.id, name: role.name }]),
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
  const response = await fetch(`${getTcUrl()}/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(userRep),
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
  const response = await fetch(`${getTcUrl()}/users/${userId}/role-mappings`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

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
  const response = await fetch(
    `${getTcUrl()}/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=43200&redirect_uri=${redirect_uri}&client_id=${getClient()}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(["link-tide-account-action"]),
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

// NEW iga-core: a single GET /iga/change-requests?status=PENDING returns a flat
// list of IgaChangeRequestRepresentation for ALL entity types; callers filter
// client-side by entityType. Field renames vs the old surface:
//   draftRecordId -> id ; changeSetType -> entityType ; payload -> rows[] ;
//   state -> status (PENDING/APPROVED/DENIED/CANCELLED). actionType UNCHANGED.
// requireManageRealm (admin bearer token).
const getPendingChangeRequests = async (delegation: DelegationFetch): Promise<any[]> => {
  // delegation.fetch returns the parsed JSON body and throws on non-2xx.
  return (await delegation.fetch(`${getTcUrl()}/iga/change-requests?status=PENDING`)) || [];
};

// ── Server-side CR display name resolution (port of client commit 13d501d) ──
// The new iga-core CRs carry the target user/role/client under `rows` (DB-row
// shaped, UPPERCASE columns that vary by actionType) — GRANT_ROLES rows hold
// only USER_ID/ROLE_ID UUIDs. Because the admin UI is now SERVER-routed, the
// name resolution that used to run client-side must run here, or the CR list
// shows "Unknown". We resolve UUIDs against server-fetched user/role/client
// lists and inject userRecord/role/compositeRole/clientId onto `data`.
interface CrLookups {
  usersById: Map<string, UserRepresentation>;
  rolesById: Map<string, RoleRepresentation>;
  clientIdByUuid: Map<string, string>;
}

const buildCrLookups = async (delegation: DelegationFetch): Promise<CrLookups> => {
  const tcBase = getTcUrl();
  const [users, appClients, rmClients] = await Promise.all([
    delegation.fetch(`${tcBase}/users?briefRepresentation=false`).catch(() => [] as any[]),
    delegation.fetch(`${tcBase}/clients?clientId=${getResource()}`).catch(() => [] as any[]),
    delegation.fetch(`${tcBase}/clients?clientId=${REALM_MGMT}`).catch(() => [] as any[]),
  ]);
  const appClient = Array.isArray(appClients) && appClients.length ? appClients[0] : null;
  const rmClient = Array.isArray(rmClients) && rmClients.length ? rmClients[0] : null;

  // Resolve roles from both the app client and realm-management so GRANT_ROLES
  // ROLE_IDs (app roles AND tide-realm-admin) map to names.
  const roleFetches: Promise<any[]>[] = [];
  if (appClient?.id) roleFetches.push(delegation.fetch(`${tcBase}/clients/${appClient.id}/roles`).catch(() => []));
  if (rmClient?.id) roleFetches.push(delegation.fetch(`${tcBase}/clients/${rmClient.id}/roles`).catch(() => []));
  const roleLists = await Promise.all(roleFetches);
  const roles: any[] = ([] as any[]).concat(...roleLists);

  const usersById = new Map<string, UserRepresentation>();
  for (const u of (Array.isArray(users) ? users : [])) if (u.id) usersById.set(u.id, u);
  const rolesById = new Map<string, RoleRepresentation>();
  for (const r of roles) if (r.id) rolesById.set(r.id, r);
  const clientIdByUuid = new Map<string, string>();
  if (appClient?.id) clientIdByUuid.set(appClient.id, appClient.clientId || getResource());
  if (rmClient?.id) clientIdByUuid.set(rmClient.id, rmClient.clientId || REALM_MGMT);
  return { usersById, rolesById, clientIdByUuid };
};

// Pull display User / Role / Client out of a CR's `rows`.
//   GRANT_ROLES : [{ USER_ID, ROLE_ID }]              (UUIDs only, resolve)
//   CREATE_USER : [{ ID, USERNAME, REP_JSON, ... }]   (USERNAME present)
//   CREATE_ROLE : [{ ID, NAME, CLIENT_ID, ... }]      (NAME + CLIENT_ID present)
const extractCrDisplay = (
  d: any,
  lk: CrLookups
): { userRecord: { username: string }[]; role: string; compositeRole: string | undefined; clientId: string } => {
  const rows: any[] = Array.isArray(d.rows) ? d.rows : [];
  const row = rows[0] || {};

  const userId = row.USER_ID || row.ID || d.entityId;
  const username: string | undefined = row.USERNAME || (userId ? lk.usersById.get(userId)?.username : undefined);

  const roleId = row.ROLE_ID || (d.entityType === "ROLE" ? row.ID || d.entityId : undefined);
  const resolvedRole = roleId ? lk.rolesById.get(roleId) : undefined;
  const role: string | undefined = row.NAME || resolvedRole?.name;
  const compositeRole: string | undefined = resolvedRole?.composite ? resolvedRole?.name : undefined;

  const containerUuid = row.CLIENT_UUID || (resolvedRole as any)?.containerId;
  const clientId: string | undefined = row.CLIENT_ID || (containerUuid ? lk.clientIdByUuid.get(containerUuid) : undefined);

  return {
    userRecord: username ? [{ username }] : [],
    role: role || "Unknown",
    compositeRole,
    clientId: clientId || "Unknown",
  };
};

// Map an IgaChangeRequestRepresentation to keylessh's {data, retrievalInfo}
// shape, injecting resolved display fields (userRecord/role/compositeRole/
// clientId) onto `data` so the route/UI can render names instead of "Unknown".
const toRetrieval = (
  d: any,
  lk: CrLookups
): { data: any; retrievalInfo: ChangeSetRequest } => {
  const display = extractCrDisplay(d, lk);
  return {
    // Alias the legacy field names the route/UI mappers read (draftRecordId /
    // changeSetType) from the new rep, and inject the resolved display fields.
    data: {
      ...d,
      draftRecordId: d.id,
      changeSetType: d.entityType,
      userRecord: display.userRecord,
      role: display.role,
      compositeRole: display.compositeRole,
      clientId: display.clientId,
    },
    retrievalInfo: {
      changeSetId: d.id,
      changeSetType: d.entityType,
      actionType: d.actionType,
    } as ChangeSetRequest,
  };
};

export const GetUserChangeRequests = async (
  delegation: DelegationFetch
): Promise<{ data: any; retrievalInfo: ChangeSetRequest }[]> => {
  const all = await getPendingChangeRequests(delegation);
  const userCrs = all.filter((d: any) => d.entityType === "USER");
  if (userCrs.length === 0) return [];
  const lk = await buildCrLookups(delegation);
  return userCrs.map((d) => toRetrieval(d, lk));
};

export const GetRoleChangeRequests = async (
  delegation: DelegationFetch
): Promise<{ data: any; retrievalInfo: ChangeSetRequest }[]> => {
  const all = await getPendingChangeRequests(delegation);
  const roleCrs = all.filter((d: any) => d.entityType === "ROLE");
  if (roleCrs.length === 0) return [];
  const lk = await buildCrLookups(delegation);
  return roleCrs.map((d) => toRetrieval(d, lk));
};

// Response of the multiAdmin phase-1 /approve call.
//   mode === "needs-approval" (multiAdmin) == the old requiresApprovalPopup;
//   requestModel == the old changeSetDraftRequests (the bytes the enclave signs).
//   mode === "recorded" (firstAdmin/simple) records AND auto-commits.
export interface ApprovePhase1Response {
  mode: string;
  changeRequestId?: string;
  actionType?: string;
  requestModel?: string; // base64 bytes for the enclave to sign
  authCount?: number;
  threshold?: number;
  committed?: boolean;
  readyToCommit?: boolean;
  status?: string;
}

// POST /iga/change-requests/{id}/approve.
//   - Empty body  => PHASE 1. multiAdmin returns {mode:"needs-approval",
//     requestModel,...}; firstAdmin/simple returns {mode:"recorded"} (records AND
//     auto-commits at quorum in one call).
//   - {requestModel:<signed-doken-base64>} => PHASE 2 (multiAdmin): records the
//     signed doken toward threshold and auto-commits at quorum.
// This single endpoint replaces the old sign/batch + add-review two-step.
export const ApproveChangeRequest = async (
  changeSetId: string,
  token: string,
  signedRequest?: string
): Promise<ApprovePhase1Response> => {
  const response = await fetch(
    `${getTcUrl()}/iga/change-requests/${changeSetId}/approve`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(signedRequest ? { requestModel: signedRequest } : {}),
    }
  );

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error approving change request: ${response.statusText}`);
    throw new Error(`Error approving change request: ${errorBody}`);
  }

  const text = await response.text();
  return text ? (JSON.parse(text) as ApprovePhase1Response) : ({} as ApprovePhase1Response);
};

// POST /iga/change-requests/{id}/deny - id in path, no body, returns 204.
// Used for both REJECT and CANCEL (the old add-rejection and change-set/cancel).
export const DenyChangeRequest = async (
  changeSetId: string,
  token: string
): Promise<void> => {
  const response = await fetch(
    `${getTcUrl()}/iga/change-requests/${changeSetId}/deny`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error denying change request: ${response.statusText}`);
    throw new Error(`Error denying change request: ${errorBody}`);
  }
  return;
};

// POST /iga/change-requests/{id}/commit - id in path, EMPTY body. Apply-only.
// Usually unnecessary (/approve auto-commits at quorum); kept for an explicit
// apply step. 412 QUORUM_NOT_MET if sub-quorum, 409 if not PENDING.
export const CommitChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  const response = await fetch(
    `${getTcUrl()}/iga/change-requests/${changeSet.changeSetId}/commit`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Error committing change request: ${response.statusText}`);
    throw new Error(`Error committing change request: ${errorBody}`);
  }
  return;
};

// CANCEL maps to /deny on the new surface (the old change-set/cancel is gone).
export const CancelChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  await DenyChangeRequest(changeSet.changeSetId, token);
  return;
};

// REJECT maps to /deny on the new surface (the old add-rejection is gone).
export const AddRejectionToChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  await DenyChangeRequest(changeSet.changeSetId, token);
  return;
};

// Legacy no-signature approve. On the new surface an empty-body phase-1
// /approve records the admin's approval (firstAdmin/simple auto-commits at
// quorum); for multiAdmin realms it only builds the model and the enclave-signed
// phase-2 (AddApprovalWithSignedRequest) is required to actually record a vote.
export const AddApprovalToChangeRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<void> => {
  await ApproveChangeRequest(changeSet.changeSetId, token);
  return;
};

// Preserved response shape the client (AdminApprovals.tsx) already consumes:
//   changesetId            -> the CR id
//   changeSetDraftRequests -> base64 bytes the enclave signs (== requestModel)
//   requiresApprovalPopup  -> true when multiAdmin needs the enclave ceremony
export interface RawChangeSetResponse {
  changesetId: string;
  changeSetDraftRequests: string;
  requiresApprovalPopup: boolean | string;
}

// "Get raw request to sign" is now PHASE 1 of /approve: the empty-body call
// returns the requestModel (multiAdmin) that the enclave signs. We adapt it into
// the legacy RawChangeSetResponse[] shape so the existing client enclave-signing
// flow keeps working unchanged. If mode !== "needs-approval" (firstAdmin/simple
// realms), the CR was already recorded/committed and there is nothing to sign;
// we return an empty array so the caller treats it as "no popup required".
export const GetRawChangeSetRequest = async (
  changeSet: ChangeSetRequest,
  token: string
): Promise<RawChangeSetResponse[]> => {
  const phase1 = await ApproveChangeRequest(changeSet.changeSetId, token);
  const needsApproval = phase1.mode === "needs-approval" && !!phase1.requestModel;
  if (!needsApproval) {
    // firstAdmin/simple: recorded (and auto-committed) already; nothing to sign.
    return [];
  }
  return [
    {
      changesetId: phase1.changeRequestId ?? changeSet.changeSetId,
      changeSetDraftRequests: phase1.requestModel as string,
      requiresApprovalPopup: true,
    },
  ];
};

// PHASE 2: submit the enclave-signed doken toward the CR's threshold via
// /approve {requestModel:<signed>}. Auto-commits at quorum. Replaces the old
// multipart add-review with a `requests` form field.
export const AddApprovalWithSignedRequest = async (
  changeSet: ChangeSetRequest,
  signedRequest: string,
  token: string
): Promise<void> => {
  await ApproveChangeRequest(changeSet.changeSetId, token, signedRequest);
  return;
};


// ============================================
// Server-side delegation (mTLS server identity)
// ============================================
// Admin writes to TideCloak's /iga/* and /admin/* surface authenticate via a
// cert-bound delegation token exchanged over mTLS, NOT a forwarded browser
// Bearer/DPoP token. The keylessh server holds a server-identity certificate
// (SPIFFE SVID) issued by the realm; getDelegation() lazily builds the
// TideDelegation instance from the adapter config (data/tidecloak.json).

// Lazy TideDelegation instance (vault-backed mTLS)
let _delegation: TideDelegation | null = null;
export function getDelegation(): TideDelegation {
  if (!_delegation) {
    const adapterPath = path.join(process.cwd(), "data", "tidecloak.json");
    // Read the server client ID from the adapter JSON if available.
    let serverClientId: string | undefined;
    try {
      const adapter = JSON.parse(fs.readFileSync(adapterPath, "utf-8"));
      serverClientId = adapter.serverResource;
      console.log(`[delegation] adapterPath=${adapterPath} serverClientId=${serverClientId}`);
    } catch (e: any) {
      console.warn(`[delegation] Could not read adapter: ${adapterPath} - ${e.message}`);
    }

    _delegation = new TideDelegation({
      tidecloakUrl: getAuthOverrideUrl(),
      realm: getRealm(),
      clientId: getResource(),
      serverClientId,
      adapterJsonPath: adapterPath,
    });
  }
  return _delegation;
}

// Initialize vault-backed key management on startup (loads/creates the server
// key, requests the server-identity cert if absent, wires the mTLS agent).
export async function initServerIdentity() {
  const delegation = getDelegation();
  await delegation.init();
  console.log(`[delegation] mTLS enabled: ${delegation.isMtlsEnabled()}`);
}

/**
 * Get the server's cert thumbprint for clients to include in delegation
 * requests. Returns null if mTLS is not configured.
 */
export function getDelegationCertThumbprint(): string | null {
  return getDelegation().getCertThumbprint();
}
