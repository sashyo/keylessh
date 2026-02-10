/**
 * Organization-Scoped User Management
 *
 * Provides user management for freemium organizations in the shared TideCloak realm.
 * Uses master admin credentials to manage users, with organization scoping via user attributes.
 *
 * This is used when org-admins (who don't have TideCloak realm-level permissions)
 * need to manage users within their organization.
 */

import { log } from "../logger";
import { getAuthOverrideUrl, getRealm } from "./auth/tidecloakConfig";

interface OrgUser {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  enabled: boolean;
  organizationId: string;
  orgRole: string;
  linked: boolean;
}

interface CreateOrgUserParams {
  email: string;
  firstName: string;
  lastName: string;
  organizationId: string;
  orgRole?: string; // defaults to "user"
}

interface UpdateOrgUserParams {
  firstName?: string;
  lastName?: string;
  email?: string;
  orgRole?: string;
}

/**
 * Get admin token from TideCloak master realm using password grant.
 * This is used for org-scoped operations where the org-admin doesn't have
 * TideCloak realm-level permissions.
 */
async function getMasterAdminToken(): Promise<string> {
  const authServerUrl = getAuthOverrideUrl();
  const kcUser = process.env.KC_USER;
  const kcPassword = process.env.KC_PASSWORD;

  if (!kcUser || !kcPassword) {
    throw new Error("KC_USER and KC_PASSWORD must be set for org user management");
  }

  const response = await fetch(`${authServerUrl}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      username: kcUser,
      password: kcPassword,
      grant_type: "password",
      client_id: "admin-cli",
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to get master admin token: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  return data.access_token;
}

/**
 * Get all users in an organization (filtered by organization_id attribute)
 */
export async function getOrgUsers(organizationId: string): Promise<OrgUser[]> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();

  // Query users with organization_id attribute
  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users?q=organization_id:${encodeURIComponent(organizationId)}&max=1000`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to get org users: ${response.status} ${text}`);
  }

  const users = await response.json();

  return users.map((u: any) => ({
    id: u.id,
    username: u.username || "",
    email: u.email || "",
    firstName: u.firstName || "",
    lastName: u.lastName || "",
    enabled: u.enabled !== false,
    organizationId: u.attributes?.organization_id?.[0] || "",
    orgRole: u.attributes?.org_role?.[0] || "user",
    linked: !!u.attributes?.vuid?.[0],
  }));
}

/**
 * Create a new user in the organization
 */
export async function createOrgUser(params: CreateOrgUserParams): Promise<OrgUser> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();

  const username = params.email.split("@")[0].toLowerCase().replace(/[^a-z0-9]/g, "");

  const createResponse = await fetch(`${authServerUrl}/admin/realms/${realmName}/users`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username,
      email: params.email,
      firstName: params.firstName,
      lastName: params.lastName,
      enabled: true,
      emailVerified: false,
      requiredActions: [],
      attributes: {
        organization_id: params.organizationId,
        org_role: params.orgRole || "user",
      },
      groups: [],
    }),
  });

  if (!createResponse.ok) {
    const text = await createResponse.text();
    throw new Error(`Failed to create org user: ${createResponse.status} ${text}`);
  }

  // Get the created user by email
  const usersResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users?email=${encodeURIComponent(params.email)}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  const users = await usersResponse.json();
  if (!users || users.length === 0) {
    throw new Error("Failed to find created user");
  }

  const u = users[0];
  return {
    id: u.id,
    username: u.username || "",
    email: u.email || "",
    firstName: u.firstName || "",
    lastName: u.lastName || "",
    enabled: u.enabled !== false,
    organizationId: u.attributes?.organization_id?.[0] || params.organizationId,
    orgRole: u.attributes?.org_role?.[0] || params.orgRole || "user",
    linked: false,
  };
}

/**
 * Update a user in the organization
 */
export async function updateOrgUser(
  userId: string,
  organizationId: string,
  updates: UpdateOrgUserParams
): Promise<void> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();

  // First, get the current user to verify they belong to this org
  const userResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!userResponse.ok) {
    throw new Error(`User not found: ${userId}`);
  }

  const user = await userResponse.json();
  const userOrgId = user.attributes?.organization_id?.[0];

  if (userOrgId !== organizationId) {
    throw new Error("User does not belong to this organization");
  }

  // Build update payload
  const updatePayload: any = { ...user };
  if (updates.firstName !== undefined) updatePayload.firstName = updates.firstName;
  if (updates.lastName !== undefined) updatePayload.lastName = updates.lastName;
  if (updates.email !== undefined) updatePayload.email = updates.email;
  if (updates.orgRole !== undefined) {
    updatePayload.attributes = {
      ...updatePayload.attributes,
      org_role: [updates.orgRole],
    };
  }

  const updateResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(updatePayload),
    }
  );

  if (!updateResponse.ok) {
    const text = await updateResponse.text();
    throw new Error(`Failed to update org user: ${updateResponse.status} ${text}`);
  }
}

/**
 * Enable or disable a user in the organization
 */
export async function setOrgUserEnabled(
  userId: string,
  organizationId: string,
  enabled: boolean
): Promise<void> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();

  // First, get the current user to verify they belong to this org
  const userResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!userResponse.ok) {
    throw new Error(`User not found: ${userId}`);
  }

  const user = await userResponse.json();
  const userOrgId = user.attributes?.organization_id?.[0];

  if (userOrgId !== organizationId) {
    throw new Error("User does not belong to this organization");
  }

  // Update enabled status
  const updateResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      method: "PUT",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ...user, enabled }),
    }
  );

  if (!updateResponse.ok) {
    const text = await updateResponse.text();
    throw new Error(`Failed to update user enabled status: ${updateResponse.status} ${text}`);
  }
}

/**
 * Delete a user from the organization
 */
export async function deleteOrgUser(userId: string, organizationId: string): Promise<void> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();

  // First, get the current user to verify they belong to this org
  const userResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!userResponse.ok) {
    throw new Error(`User not found: ${userId}`);
  }

  const user = await userResponse.json();
  const userOrgId = user.attributes?.organization_id?.[0];

  if (userOrgId !== organizationId) {
    throw new Error("User does not belong to this organization");
  }

  // Delete the user
  const deleteResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      method: "DELETE",
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!deleteResponse.ok) {
    const text = await deleteResponse.text();
    throw new Error(`Failed to delete org user: ${deleteResponse.status} ${text}`);
  }
}

/**
 * Get Tide account linking URL for a user
 */
export async function getOrgUserTideLinkUrl(
  userId: string,
  organizationId: string,
  redirectUri: string
): Promise<string> {
  const authServerUrl = getAuthOverrideUrl();
  const realmName = getRealm();
  const token = await getMasterAdminToken();

  // First, verify user belongs to this org
  const userResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users/${userId}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!userResponse.ok) {
    throw new Error(`User not found: ${userId}`);
  }

  const user = await userResponse.json();
  const userOrgId = user.attributes?.organization_id?.[0];

  if (userOrgId !== organizationId) {
    throw new Error("User does not belong to this organization");
  }

  // Get the Tide link URL
  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/tideAdminResources/get-required-action-link?userId=${userId}&lifespan=43200`,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(["link-tide-account-action"]),
    }
  );

  if (!response.ok) {
    throw new Error(`Failed to generate Tide link URL: ${response.status}`);
  }

  return response.text();
}
