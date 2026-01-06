import {
  ChangeSetRequest,
  ClientRepresentation,
  MappingsRepresentation,
  RoleRepresentation,
  UserRepresentation,
} from "./auth/keycloakTypes";
import { Roles } from "@shared/config/roles";
import { getAuthOverrideUrl, getRealm, getResource } from "./auth/tidecloakConfig";

// Lazy-evaluated getters to avoid calling config functions at module load time
const getKeycloakAuthServer = () => getAuthOverrideUrl();
const getRealm_ = () => getRealm();
const getClient = () => getResource();

const getTcUrl = () => `${getKeycloakAuthServer()}/admin/realms/${getRealm_()}`;
const getNonAdminTcUrl = () => `${getKeycloakAuthServer()}/realms/${getRealm_()}`;

const REALM_MGMT = "realm-management";

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
  const roleRes: RoleRepresentation[] = await response.json();
  const roles: RoleRepresentation[] = await Promise.all(
    roleRes.map(async (r) => {
      return await getRoleById(r!.id!, token);
    })
  );
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
    return clients.length > 0 ? clients[0] : null;
  } catch (error) {
    console.error("Error fetching client by clientId:", error);
    return null;
  }
};

export const getClientById = async (
  id: string,
  token: string
): Promise<ClientRepresentation | null> => {
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
    return await response.json();
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
  const client =
    roleName === Roles.Admin
      ? await getClientByClientId(REALM_MGMT, token)
      : await getClientByClientId(getClient(), token);

  if (client === null || client?.id === undefined) {
    throw new Error(`Could not grant user role, client ${getClient()} does not exist`);
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
  const client =
    roleName === Roles.Admin
      ? await getClientByClientId(REALM_MGMT, token)
      : await getClientByClientId(getClient(), token);

  if (client === null || client?.id === undefined) {
    throw new Error(`Could not remove user role, client ${getClient()} does not exist`);
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
  // Get client roles
  const clientRoles = await getClientRoles(token);

  // Get admin role
  try {
    const adminRole = await getTideRealmAdminRole(token);
    return [...clientRoles, adminRole];
  } catch {
    // If admin role fetch fails, just return client roles
    return clientRoles;
  }
};

// ============================================
// TideCloak Change Set API Functions
// ============================================

export const GetUserChangeRequests = async (
  token: string
): Promise<{ data: any; retrievalInfo: ChangeSetRequest }[]> => {
  const response = await fetch(
    `${getTcUrl()}/tide-admin/change-set/users/requests`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

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
  const response = await fetch(
    `${getTcUrl()}/tide-admin/change-set/roles/requests`,
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

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

  const response = await fetch(`${getTcUrl()}/tideAdminResources/add-review`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
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

  const response = await fetch(
    `${getTcUrl()}/tideAdminResources/add-rejection`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: formData,
    }
  );

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
  const response = await fetch(`${getTcUrl()}/tide-admin/change-set/commit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(changeSet),
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
  const response = await fetch(`${getTcUrl()}/tide-admin/change-set/cancel`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(changeSet),
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
  const response = await fetch(`${getTcUrl()}/tide-admin/change-set/sign/batch`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ changeSets: [changeSet] }),
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

  const response = await fetch(`${getTcUrl()}/tideAdminResources/add-review`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
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

