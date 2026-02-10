/**
 * Organization Provisioning Service
 *
 * Provisions a new organization in TideCloak, creating:
 * - A new realm for the organization
 * - Initial admin user with tide-realm-admin role
 * - Client configuration for KeyleSSH
 * - Protocol mappers for organization_id and org_role claims
 */

import { log } from "../logger";
import { getAuthOverrideUrl, getResource, getRealm } from "./auth/tidecloakConfig";

interface ProvisionOrgParams {
  organizationId: string;
  organizationSlug: string;
  organizationName: string;
  adminEmail: string;
  adminFirstName: string;
  adminLastName: string;
  clientAppUrl: string;
}

interface ProvisionOrgResult {
  success: boolean;
  realmName: string;
  inviteLink?: string;
  error?: string;
}

// Get admin token from TideCloak master realm (for creating new realms - paid tier)
async function getMasterAdminToken(authServerUrl: string): Promise<string> {
  const clientId = process.env.KC_MASTER_CLIENT_ID;
  const clientSecret = process.env.KC_MASTER_CLIENT_SECRET;

  // Prefer client credentials if configured
  if (clientId && clientSecret) {
    const tokenUrl = `${authServerUrl}/realms/master/protocol/openid-connect/token`;
    log(`Requesting master token from: ${tokenUrl} with client_id: ${clientId}`);

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      log(`Master token request failed (client credentials): ${response.status} - ${errorText}`);
      log(`Falling back to password grant...`);
      // Fall through to password grant below
    } else {
      const data = await response.json();
      return data.access_token;
    }
  }

  // Fallback to password grant (for backwards compatibility / dev / when service accounts don't work)
  const kcUser = process.env.KC_USER;
  const kcPassword = process.env.KC_PASSWORD;

  if (!kcUser || !kcPassword) {
    throw new Error("Neither client credentials nor KC_USER/KC_PASSWORD are configured for master realm authentication");
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
    throw new Error(`Failed to get master admin token: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return data.access_token;
}

// Get admin token for shared realm (for creating users - freemium tier)
async function getSharedRealmAdminToken(authServerUrl: string, realmName: string): Promise<string> {
  const clientId = process.env.KC_CLIENT_ID;
  const clientSecret = process.env.KC_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error("KC_CLIENT_ID and KC_CLIENT_SECRET must be set for freemium provisioning");
  }

  const tokenUrl = `${authServerUrl}/realms/${realmName}/protocol/openid-connect/token`;
  log(`Requesting token from: ${tokenUrl} with client_id: ${clientId}`);

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    log(`Token request failed: ${response.status} - ${errorText}`);
    throw new Error(`Failed to get shared realm admin token: ${response.status} ${response.statusText} - ${errorText}`);
  }

  const data = await response.json();
  return data.access_token;
}

// Create a new realm based on template
async function createRealm(
  authServerUrl: string,
  token: string,
  realmName: string,
  clientAppUrl: string
): Promise<void> {
  // Generate realm JSON from template
  const realmConfig = generateRealmConfig(realmName, clientAppUrl);

  const response = await fetch(`${authServerUrl}/admin/realms`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(realmConfig),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to create realm: ${response.status} ${text}`);
  }
}

// Initialize Tide realm with IGA
async function initializeTideRealm(
  authServerUrl: string,
  token: string,
  realmName: string,
  licenseEmail: string
): Promise<void> {
  // Set up Tide realm
  const setupResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/vendorResources/setUpTideRealm`,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        email: licenseEmail,
        isRagnarokEnabled: "true",
      }),
    }
  );

  if (!setupResponse.ok) {
    log(`Warning: Tide realm setup returned ${setupResponse.status}`);
  }

  // Enable IGA
  const igaResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/tide-admin/toggle-iga`,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        isIGAEnabled: "true",
      }),
    }
  );

  if (!igaResponse.ok) {
    log(`Warning: IGA toggle returned ${igaResponse.status}`);
  }
}

// Approve and commit change-sets
async function approveAndCommitChangeSets(
  authServerUrl: string,
  token: string,
  realmName: string,
  type: "users" | "clients"
): Promise<void> {
  // Get pending change-sets
  const response = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/tide-admin/change-set/${type}/requests`,
    {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!response.ok) {
    log(`Warning: Failed to get ${type} change-sets: ${response.status}`);
    return;
  }

  const requests = await response.json();
  if (!Array.isArray(requests) || requests.length === 0) {
    return;
  }

  for (const req of requests) {
    const payload = {
      changeSetId: req.draftRecordId,
      changeSetType: req.changeSetType,
      actionType: req.actionType,
    };

    // Sign
    await fetch(`${authServerUrl}/admin/realms/${realmName}/tide-admin/change-set/sign`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    // Commit
    await fetch(`${authServerUrl}/admin/realms/${realmName}/tide-admin/change-set/commit`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  }
}

// Create admin user
async function createAdminUser(
  authServerUrl: string,
  token: string,
  realmName: string,
  email: string,
  firstName: string,
  lastName: string
): Promise<string> {
  const username = email.split("@")[0].toLowerCase().replace(/[^a-z0-9]/g, "");

  // Create user
  const createResponse = await fetch(`${authServerUrl}/admin/realms/${realmName}/users`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username,
      email,
      firstName,
      lastName,
      enabled: true,
      emailVerified: false,
      requiredActions: [],
      attributes: {
        locale: "",
      },
      groups: [],
    }),
  });

  if (!createResponse.ok) {
    const text = await createResponse.text();
    throw new Error(`Failed to create admin user: ${createResponse.status} ${text}`);
  }

  // Get user ID
  const usersResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users?username=${username}`,
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

  const userId = users[0].id;

  // Get realm-management client ID
  const clientsResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients?clientId=realm-management`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );
  const clients = await clientsResponse.json();
  const clientUuid = clients[0]?.id;

  if (clientUuid) {
    // Get tide-realm-admin role
    const roleResponse = await fetch(
      `${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/roles/tide-realm-admin`,
      {
        headers: {
          "Authorization": `Bearer ${token}`,
        },
      }
    );

    if (roleResponse.ok) {
      const role = await roleResponse.json();

      // Assign role to user
      await fetch(
        `${authServerUrl}/admin/realms/${realmName}/users/${userId}/role-mappings/clients/${clientUuid}`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify([role]),
        }
      );
    }
  }

  return userId;
}

// Generate invite link for admin
async function generateInviteLink(
  authServerUrl: string,
  token: string,
  realmName: string,
  userId: string
): Promise<string> {
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
    throw new Error(`Failed to generate invite link: ${response.status}`);
  }

  return response.text();
}

// Update CustomAdminUIDomain in Tide identity provider
async function updateCustomAdminUIDomain(
  authServerUrl: string,
  token: string,
  realmName: string,
  clientAppUrl: string
): Promise<void> {
  // Get current IDP config
  const getResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/identity-provider/instances/tide`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  if (!getResponse.ok) {
    log(`Warning: Failed to get Tide IDP config: ${getResponse.status}`);
    return;
  }

  const idpConfig = await getResponse.json();
  idpConfig.config.CustomAdminUIDomain = clientAppUrl;

  // Update IDP config
  await fetch(`${authServerUrl}/admin/realms/${realmName}/identity-provider/instances/tide`, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(idpConfig),
  });

  // Sign IDP settings
  await fetch(`${authServerUrl}/admin/realms/${realmName}/vendorResources/sign-idp-settings`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
    },
  });
}

// Add protocol mappers for organization_id and org_role
async function addOrganizationMappers(
  authServerUrl: string,
  token: string,
  realmName: string,
  clientName: string,
  organizationId: string
): Promise<void> {
  // Get client UUID
  const clientsResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/clients?clientId=${clientName}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  const clients = await clientsResponse.json();
  const clientUuid = clients[0]?.id;
  if (!clientUuid) {
    log(`Warning: Could not find client ${clientName} to add mappers`);
    return;
  }

  // Add organization_id hardcoded mapper
  await fetch(`${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/protocol-mappers/models`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: "organization_id",
      protocol: "openid-connect",
      protocolMapper: "oidc-hardcoded-claim-mapper",
      config: {
        "claim.name": "organization_id",
        "claim.value": organizationId,
        "jsonType.label": "String",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "true",
      },
    }),
  });

  // Add org_role mapper from user attribute
  await fetch(`${authServerUrl}/admin/realms/${realmName}/clients/${clientUuid}/protocol-mappers/models`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: "org_role",
      protocol: "openid-connect",
      protocolMapper: "oidc-usermodel-attribute-mapper",
      config: {
        "user.attribute": "org_role",
        "claim.name": "org_role",
        "jsonType.label": "String",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "true",
      },
    }),
  });
}

// Generate realm configuration from template
function generateRealmConfig(realmName: string, clientAppUrl: string): object {
  return {
    realm: realmName,
    enabled: true,
    sslRequired: "external",
    registrationAllowed: false,
    loginWithEmailAllowed: true,
    duplicateEmailsAllowed: false,
    resetPasswordAllowed: true,
    editUsernameAllowed: false,
    bruteForceProtected: true,
    accessTokenLifespan: 300,
    accessTokenLifespanForImplicitFlow: 900,
    ssoSessionIdleTimeout: 1800,
    ssoSessionMaxLifespan: 36000,
    clients: [
      {
        clientId: "myclient",
        name: "KeyleSSH Client",
        enabled: true,
        publicClient: true,
        directAccessGrantsEnabled: true,
        standardFlowEnabled: true,
        implicitFlowEnabled: false,
        serviceAccountsEnabled: false,
        protocol: "openid-connect",
        redirectUris: [
          `${clientAppUrl}/*`,
          "http://localhost:3000/*",
        ],
        webOrigins: [
          clientAppUrl,
          "http://localhost:3000",
        ],
        attributes: {
          "pkce.code.challenge.method": "S256",
        },
        defaultClientScopes: [
          "web-origins",
          "acr",
          "profile",
          "roles",
          "email",
        ],
      },
    ],
    roles: {
      realm: [
        { name: "appUser", description: "Application user role" },
        { name: "_tide_enabled", description: "Tide enabled role" },
      ],
    },
    defaultRoles: ["appUser", "_tide_enabled"],
  };
}

/**
 * Main provisioning function
 */
export async function provisionOrganization(params: ProvisionOrgParams): Promise<ProvisionOrgResult> {
  const authServerUrl = getAuthOverrideUrl();
  const clientName = getResource();
  const realmName = params.organizationSlug;

  log(`Starting provisioning for organization: ${params.organizationName} (${realmName})`);

  try {
    // Step 1: Get master admin token (for creating realms)
    log("Getting master admin token...");
    let token = await getMasterAdminToken(authServerUrl);

    // Step 2: Create realm
    log("Creating realm...");
    await createRealm(authServerUrl, token, realmName, params.clientAppUrl);

    // Step 3: Initialize Tide realm + IGA
    log("Initializing Tide realm + IGA...");
    token = await getMasterAdminToken(authServerUrl);
    await initializeTideRealm(authServerUrl, token, realmName, params.adminEmail);

    // Step 4: Approve client change-sets
    log("Approving client change-sets...");
    token = await getMasterAdminToken(authServerUrl);
    await approveAndCommitChangeSets(authServerUrl, token, realmName, "clients");

    // Step 5: Add organization mappers
    log("Adding organization protocol mappers...");
    token = await getMasterAdminToken(authServerUrl);
    await addOrganizationMappers(authServerUrl, token, realmName, clientName, params.organizationId);

    // Step 6: Create admin user
    log("Creating admin user...");
    token = await getMasterAdminToken(authServerUrl);
    const userId = await createAdminUser(
      authServerUrl,
      token,
      realmName,
      params.adminEmail,
      params.adminFirstName,
      params.adminLastName
    );

    // Step 7: Approve user change-sets (may need to wait for Tide)
    // Note: The full flow requires the admin to link their Tide account first
    // For now, we generate the invite link

    // Step 8: Update CustomAdminUIDomain
    log("Updating CustomAdminUIDomain...");
    token = await getMasterAdminToken(authServerUrl);
    await updateCustomAdminUIDomain(authServerUrl, token, realmName, params.clientAppUrl);

    // Step 9: Generate invite link
    log("Generating invite link...");
    token = await getMasterAdminToken(authServerUrl);
    const inviteLink = await generateInviteLink(authServerUrl, token, realmName, userId);

    log(`Provisioning complete for ${params.organizationName}`);

    return {
      success: true,
      realmName,
      inviteLink,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log(`Provisioning failed: ${errorMessage}`);
    return {
      success: false,
      realmName,
      error: errorMessage,
    };
  }
}

/**
 * Freemium provisioning function
 * Creates a user in the existing shared realm with organization_id attribute
 * No new realm is created - all freemium orgs share the same TideCloak realm
 */
export async function provisionFreemiumOrganization(params: ProvisionOrgParams): Promise<ProvisionOrgResult> {
  const authServerUrl = getAuthOverrideUrl();
  const sharedRealmName = getRealm();

  log(`Starting freemium provisioning for organization: ${params.organizationName} (using shared realm: ${sharedRealmName})`);

  try {
    // Step 1: Get admin token
    // Note: Using master admin token as TideCloak has issues with service accounts in Tide-enabled realms
    log("Getting admin token...");
    let token = await getMasterAdminToken(authServerUrl);

    // Step 2: Create admin user in shared realm with organization_id attribute
    log("Creating admin user in shared realm...");
    const userId = await createFreemiumAdminUser(
      authServerUrl,
      token,
      sharedRealmName,
      params.organizationId,
      params.adminEmail,
      params.adminFirstName,
      params.adminLastName
    );

    // Step 3: Generate invite link for the user
    log("Generating invite link...");
    token = await getMasterAdminToken(authServerUrl);
    const inviteLink = await generateInviteLink(authServerUrl, token, sharedRealmName, userId);

    log(`Freemium provisioning complete for ${params.organizationName}`);

    return {
      success: true,
      realmName: sharedRealmName,
      inviteLink,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log(`Freemium provisioning failed: ${errorMessage}`);
    return {
      success: false,
      realmName: sharedRealmName,
      error: errorMessage,
    };
  }
}

// Create admin user in shared realm with organization_id attribute
// Note: No tide-realm-admin role is assigned - that role is reserved for
// the actual realm administrators. Freemium users only get attributes.
async function createFreemiumAdminUser(
  authServerUrl: string,
  token: string,
  realmName: string,
  organizationId: string,
  email: string,
  firstName: string,
  lastName: string
): Promise<string> {
  const username = email.split("@")[0].toLowerCase().replace(/[^a-z0-9]/g, "");

  // Create user with organization_id and org_role attributes
  // The org_role attribute marks them as org-admin for their organization
  // This is checked by the app, not by TideCloak realm roles
  // Note: username and lastName are user fields, NOT attributes - TideCloak validates attributes
  const createResponse = await fetch(`${authServerUrl}/admin/realms/${realmName}/users`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username,
      email,
      firstName,
      lastName,
      enabled: true,
      emailVerified: false,
      requiredActions: [],
      attributes: {
        organization_id: organizationId,
        org_role: "org-admin",
      },
      groups: [],
    }),
  });

  if (!createResponse.ok) {
    const text = await createResponse.text();
    throw new Error(`Failed to create freemium admin user: ${createResponse.status} ${text}`);
  }

  // Get user ID
  const usersResponse = await fetch(
    `${authServerUrl}/admin/realms/${realmName}/users?username=${username}`,
    {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    }
  );

  const users = await usersResponse.json();
  if (!users || users.length === 0) {
    throw new Error("Failed to find created freemium user");
  }

  return users[0].id;
}
