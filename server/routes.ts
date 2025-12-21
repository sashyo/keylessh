import type { Express } from "express";
import type { Server } from "http";
import { storage, approvalStorage, policyStorage, pendingPolicyStorage, templateStorage, type ApprovalType } from "./storage";
import { log } from "./logger";
// spawn import removed - now calling Ork's compile endpoint directly
import { terminateSession } from "./wsBridge";
import type { ServerWithAccess, ActiveSession, ServerStatus, Server as ServerType } from "@shared/schema";
import { createRequire } from "module";
import { fileURLToPath } from "url";

// Ork URL for Forseti compilation - guarantees hash matches Ork's runtime
const ORK_URL = process.env.ORK_URL || "http://localhost:1001";

/**
 * Compiles Forseti contract source code by calling Ork's compile endpoint.
 * This guarantees the contractId matches exactly what Ork will compute at runtime,
 * since both use the same runtime environment and SDK version.
 */
async function compileForsetiContract(
  source: string,
  options: { validate?: boolean; entryType?: string } = {}
): Promise<{ success: boolean; contractId?: string; sdkVersion?: string; error?: string; validated?: boolean }> {
  try {
    const response = await fetch(`${ORK_URL}/Forseti/Compile/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: `HTTP ${response.status}` }));
      return { success: false, error: error.message || error.error || `Ork returned ${response.status}` };
    }

    const result = await response.json();
    return {
      success: true,
      contractId: result.contractId,
      sdkVersion: result.sdkVersion,
      validated: options.validate ?? false, // Ork's preview doesn't validate, but mark based on request
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return { success: false, error: `Failed to call Ork compile endpoint: ${message}` };
  }
}

// Use createRequire for heimdall-tide (CJS module with broken ESM exports)
const require = createRequire(import.meta.url || fileURLToPath(new URL(".", import.meta.url)));
const { PolicySignRequest } = require("heimdall-tide");

// Base64 conversion helpers for Tide request handling
function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// Check server health by calling its health check URL
async function checkServerHealth(server: ServerType): Promise<ServerStatus> {
  if (!server.healthCheckUrl) {
    return "unknown";
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    const response = await fetch(server.healthCheckUrl, {
      method: "GET",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    return response.ok ? "online" : "offline";
  } catch (error) {
    return "offline";
  }
}

// Check health for multiple servers in parallel
async function checkServersHealth(servers: ServerType[]): Promise<Map<string, ServerStatus>> {
  const healthChecks = servers.map(async (server) => {
    const status = await checkServerHealth(server);
    return { id: server.id, status };
  });

  const results = await Promise.all(healthChecks);
  const statusMap = new Map<string, ServerStatus>();
  results.forEach(({ id, status }) => statusMap.set(id, status));
  return statusMap;
}
import {
  authenticate,
  requireAdmin,
  requirePolicyCreator,
  tidecloakAdmin,
  type AuthenticatedRequest,
} from "./auth";
import {
  GetUserChangeRequests,
  AddApprovalToChangeRequest,
  AddRejectionToChangeRequest,
  CommitChangeRequest,
  CancelChangeRequest,
  GetRawChangeSetRequest,
  AddApprovalWithSignedRequest,
  GetClientEvents,
} from "./lib/tidecloakApi";
import type { ChangeSetRequest, AccessApproval } from "./lib/auth/keycloakTypes";
import { getAllowedSshUsersFromToken } from "./lib/auth/sshUsers";

// SSH connections are handled via WebSocket TCP bridge
// The browser runs SSH client (using @microsoft/dev-tunnels-ssh)
// and connects through /ws/tcp to reach SSH servers

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // ============================================
  // User Routes (authenticated users)
  // ============================================

  app.get("/api/servers", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const allowedSshUsersFromToken = getAllowedSshUsersFromToken(req.tokenPayload);

      let servers;
      if (user.role === "admin") {
        servers = await storage.getServers();
      } else {
        // Non-admin users can view all configured servers (connect access is still gated
        // by server existence/enabled and WS/session validation).
        servers = (await storage.getServers()).filter((s) => s.enabled);
      }

      // Check health status for all servers in parallel
      const healthStatusMap = await checkServersHealth(servers);

      const serversWithAccess: ServerWithAccess[] = servers.map((server) => ({
        ...server,
        allowedSshUsers: (server.sshUsers || []).filter((u) => allowedSshUsersFromToken.includes(u)),
        status: healthStatusMap.get(server.id) || "unknown",
      }));

      res.json(serversWithAccess);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch servers" });
    }
  });

  app.get("/api/servers/:id", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const allowedSshUsersFromToken = getAllowedSshUsersFromToken(req.tokenPayload);
      const server = await storage.getServer(req.params.id);

      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      if (user.role !== "admin" && !server.enabled) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      // Check health status
      const status = await checkServerHealth(server);

      const serverWithAccess: ServerWithAccess = {
        ...server,
        allowedSshUsers: (server.sshUsers || []).filter((u) => allowedSshUsersFromToken.includes(u)),
        status,
      };

      res.json(serverWithAccess);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch server" });
    }
  });

  app.get("/api/sessions", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const sessions = await storage.getSessionsByUserId(user.id);
      const servers = await storage.getServers();

      const activeSessions: ActiveSession[] = sessions.map((session) => {
        const server = servers.find((s) => s.id === session.serverId);
        return {
          ...session,
          serverName: server?.name || "Unknown",
          serverHost: server?.host || "Unknown",
        };
      });

      res.json(activeSessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch sessions" });
    }
  });

  app.post("/api/sessions", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const { serverId, sshUser } = req.body;
      const allowedSshUsersFromToken = getAllowedSshUsersFromToken(req.tokenPayload);

      const server = await storage.getServer(serverId);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      if (user.role !== "admin" && !server.enabled) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      const serverSshUsers = server.sshUsers || [];
      if (!serverSshUsers.includes(sshUser)) {
        res.status(400).json({ message: `SSH user '${sshUser}' is not allowed for this server` });
        return;
      }

      if (!allowedSshUsersFromToken.includes(sshUser)) {
        res.status(403).json({
          message: `Not allowed to SSH as '${sshUser}'`,
          allowedSshUsers: serverSshUsers.filter((u) => allowedSshUsersFromToken.includes(u)),
        });
        return;
      }

      const session = await storage.createSession({
        userId: user.id,
        userUsername: user.username,
        userEmail: user.email,
        serverId,
        sshUser,
        status: "active",
      });

      res.json(session);
    } catch (error) {
      res.status(500).json({ message: "Failed to create session" });
    }
  });

  app.delete(
    "/api/sessions/:id",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        const user = req.user!;
        const session = await storage.getSession(req.params.id);

        // Only allow ending own sessions (unless admin)
        if (session && user.role !== "admin" && session.userId !== user.id) {
          res.status(403).json({ message: "Access denied" });
          return;
        }

        await storage.endSession(req.params.id);
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to end session" });
      }
    }
  );

  // SSH connection authorization endpoint
  // Validates user has access to server and returns connection details
  app.post(
    "/api/ssh/authorize",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        const user = req.user!;
        const allowedSshUsersFromToken = getAllowedSshUsersFromToken(req.tokenPayload);
        const { serverId } = req.body;

        if (!serverId) {
          res.status(400).json({ message: "serverId is required" });
          return;
        }

        const server = await storage.getServer(serverId);
        if (!server) {
          res.status(404).json({ message: "Server not found" });
          return;
        }

        if (user.role !== "admin" && !server.enabled) {
          res.status(404).json({ message: "Server not found" });
          return;
        }

        // Return server connection details
        // The JWT token from the Authorization header will be used for WebSocket auth
        res.json({
          host: server.host,
          port: server.port,
          serverId: server.id,
          serverName: server.name,
          allowedSshUsers: (server.sshUsers || []).filter((u) => allowedSshUsersFromToken.includes(u)),
        });
      } catch (error) {
        log(`SSH authorize error: ${error}`);
        res.status(500).json({ message: "Failed to authorize SSH connection" });
      }
    }
  );

  // ============================================
  // Admin Server Routes
  // ============================================

  app.get(
    "/api/admin/servers",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const servers = await storage.getServers();
        res.json(servers);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch servers" });
      }
    }
  );

  app.post(
    "/api/admin/servers",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const server = await storage.createServer(req.body);
        res.json(server);
      } catch (error) {
        res.status(500).json({ message: "Failed to create server" });
      }
    }
  );

  app.patch(
    "/api/admin/servers/:id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const server = await storage.updateServer(req.params.id, req.body);
        if (!server) {
          res.status(404).json({ message: "Server not found" });
          return;
        }
        res.json(server);
      } catch (error) {
        res.status(500).json({ message: "Failed to update server" });
      }
    }
  );

  app.delete(
    "/api/admin/servers/:id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const success = await storage.deleteServer(req.params.id);
        if (!success) {
          res.status(404).json({ message: "Server not found" });
          return;
        }
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: "Failed to delete server" });
      }
    }
  );

  // ============================================
  // Admin User Routes
  // ============================================

  // GET /api/admin/users - List all users with roles
  app.get(
    "/api/admin/users",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const users = await tidecloakAdmin.getUsers(token);
        res.json(users);
      } catch (error) {
        log(`Failed to fetch users: ${error}`);
        res.status(500).json({ message: "Failed to fetch users" });
      }
    }
  );

  // POST /api/admin/users - Update user roles
  app.post(
    "/api/admin/users",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { id, rolesToAdd, rolesToRemove } = req.body;

        if (!id) {
          res.status(400).json({ error: "User ID is required" });
          return;
        }

        await tidecloakAdmin.updateUserRoles(
          token,
          id,
          rolesToAdd || [],
          rolesToRemove || []
        );

        res.json({ message: "User roles updated successfully" });
      } catch (error) {
        log(`Failed to update user roles: ${error}`);
        res.status(400).json({ error: "Failed to update user roles" });
      }
    }
  );

  // PUT /api/admin/users - Update user profile
  app.put(
    "/api/admin/users",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { id, firstName, lastName, email } = req.body;

        if (!id) {
          res.status(400).json({ error: "User ID is required" });
          return;
        }

        await tidecloakAdmin.updateUser(token, id, { firstName, lastName, email });

        res.json({ message: "User profile updated successfully" });
      } catch (error) {
        log(`Failed to update user: ${error}`);
        res.status(400).json({ error: "Failed to update user" });
      }
    }
  );

  // DELETE /api/admin/users - Delete user
  app.delete(
    "/api/admin/users",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const userId = req.query.userId as string;

        if (!userId) {
          res.status(400).json({ error: "UserId was not provided" });
          return;
        }

        await tidecloakAdmin.deleteUser(token, userId);

        res.json({ success: true });
      } catch (error) {
        log(`Failed to delete user: ${error}`);
        res.status(400).json({ error: "Failed to delete user" });
      }
    }
  );

  // POST /api/admin/users/add - Create new user
  app.post(
    "/api/admin/users/add",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { username, firstName, lastName, email } = req.body;

        if (!username || !firstName || !lastName || !email) {
          res.status(400).json({ error: "Missing required fields" });
          return;
        }

        await tidecloakAdmin.addUser(token, { username, firstName, lastName, email });

        res.json({ message: "User has been added" });
      } catch (error) {
        log(`Failed to add user: ${error}`);
        res.status(400).json({ error: "Failed to add user" });
      }
    }
  );

  // GET /api/admin/users/tide - Get Tide account linking URL
  app.get(
    "/api/admin/users/tide",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const userId = req.query.userId as string;
        const redirectUri = req.query.redirect_uri as string;

        if (!userId) {
          res.status(400).json({ error: "UserId was not provided" });
          return;
        }

        const linkUrl = await tidecloakAdmin.getTideLinkUrl(
          token,
          userId,
          redirectUri || `${req.protocol}://${req.get("host")}/`
        );

        res.json({ linkUrl });
      } catch (error) {
        log(`Failed to get Tide link URL: ${error}`);
        res.status(400).json({ error: "Failed to get Tide link URL" });
      }
    }
  );

  // ============================================
  // Admin Role Routes
  // ============================================

  // GET /api/admin/roles - List client roles
  app.get(
    "/api/admin/roles",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const roles = await tidecloakAdmin.getClientRoles(token);
        res.json({ roles });
      } catch (error) {
        log(`Failed to fetch roles: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // POST /api/admin/roles - Create new role
  app.post(
    "/api/admin/roles",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { name, description, policy } = req.body;

        if (!name) {
          res.status(400).json({ error: "Role name is required" });
          return;
        }

        // Create the role in TideCloak
        await tidecloakAdmin.createRole(token, { name, description });

        // If policy config is provided and enabled, store the SSH policy
        if (policy && policy.enabled) {
          try {
            await policyStorage.upsertPolicy({
              roleId: name,
              contractType: policy.contractType,
              approvalType: policy.approvalType,
              executionType: policy.executionType,
              threshold: policy.threshold,
            });
            log(`Created SSH policy for role: ${name}`);
          } catch (policyError) {
            log(`Warning: Role created but failed to save policy: ${policyError}`);
            // Continue - role was created successfully
          }
        }

        res.json({ success: "Role has been added!" });
      } catch (error) {
        log(`Failed to create role: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // PUT /api/admin/roles - Update role
  app.put(
    "/api/admin/roles",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { name, description } = req.body;

        if (!name) {
          res.status(400).json({ error: "Role name is required" });
          return;
        }

        await tidecloakAdmin.updateRole(token, { name, description });

        res.json({ success: "Role has been updated!" });
      } catch (error) {
        log(`Failed to update role: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // DELETE /api/admin/roles - Delete role
  app.delete(
    "/api/admin/roles",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const roleName = req.query.roleName as string;

        if (!roleName) {
          res.status(400).json({ error: "RoleName was not provided" });
          return;
        }

        // Delete the role in TideCloak
        await tidecloakAdmin.deleteRole(token, roleName);

        // Also delete any associated SSH policy
        try {
          await policyStorage.deletePolicy(roleName);
        } catch (policyError) {
          log(`Warning: Role deleted but failed to delete policy: ${policyError}`);
        }

        res.json({ success: "Role has been deleted!" });
      } catch (error) {
        log(`Failed to delete role: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/roles/policies - Get all SSH policies
  app.get(
    "/api/admin/roles/policies",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const policies = await policyStorage.getAllPolicies();
        res.json({ policies });
      } catch (error) {
        log(`Failed to fetch policies: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/roles/:roleName/policy - Get SSH policy for a specific role
  app.get(
    "/api/admin/roles/:roleName/policy",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { roleName } = req.params;
        const policy = await policyStorage.getPolicy(roleName);

        if (!policy) {
          res.status(404).json({ error: "Policy not found for this role" });
          return;
        }

        res.json({ policy });
      } catch (error) {
        log(`Failed to fetch policy: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/roles/all - List all roles including admin role
  app.get(
    "/api/admin/roles/all",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const roles = await tidecloakAdmin.getAllRoles(token);
        res.json({ roles });
      } catch (error) {
        log(`Failed to fetch all roles: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // ============================================
  // SSH Policy Approval Routes
  // ============================================

  // POST /api/admin/ssh-policies/pending - Create pending policy request
  app.post(
    "/api/admin/ssh-policies/pending",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { policyRequest, roleName, threshold } = req.body;

        if (!policyRequest || !roleName) {
          res.status(400).json({ error: "policyRequest and roleName are required" });
          return;
        }

        // Decode the request to get its unique ID (like Swarm does)
        const request = PolicySignRequest.decode(base64ToBytes(policyRequest));
        if (!request.isInitialized()) {
          res.status(400).json({ error: "Policy request has not been initialized" });
          return;
        }
        const id = request.getUniqueId();

        const policy = await pendingPolicyStorage.createPendingPolicy({
          id,
          roleId: roleName,
          requestedBy: req.tokenPayload?.vuid || req.user?.id || "unknown",
          requestedByEmail: req.user?.email,
          policyRequestData: policyRequest,
          threshold: threshold || 1,
        });

        log(`Created pending SSH policy for role: ${roleName} by ${req.user?.email} (id: ${id})`);
        res.json({ success: true, policy });
      } catch (error) {
        log(`Failed to create pending policy: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/ssh-policies/pending - List all pending policies
  app.get(
    "/api/admin/ssh-policies/pending",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const policies = await pendingPolicyStorage.getAllPendingPolicies();
        res.json({ policies });
      } catch (error) {
        log(`Failed to fetch pending policies: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/ssh-policies/pending/:id - Get a specific pending policy
  app.get(
    "/api/admin/ssh-policies/pending/:id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const policy = await pendingPolicyStorage.getPendingPolicy(id);

        if (!policy) {
          res.status(404).json({ error: "Policy not found" });
          return;
        }

        const decisions = await pendingPolicyStorage.getDecisions(id);
        res.json({ policy, decisions });
      } catch (error) {
        log(`Failed to fetch pending policy: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // POST /api/admin/ssh-policies/pending/approve - Approve a pending policy (Swarm-style)
  // Accepts full signed policyRequest and extracts ID from request
  app.post(
    "/api/admin/ssh-policies/pending/approve",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { policyRequest, decision } = req.body;

        if (!policyRequest) {
          res.status(400).json({ error: "policyRequest is required" });
          return;
        }

        // Decode the signed request to get its unique ID (like Swarm does)
        const request = PolicySignRequest.decode(base64ToBytes(policyRequest));
        if (!request.isInitialized()) {
          res.status(400).json({ error: "Policy request has not been initialized" });
          return;
        }
        const id = request.getUniqueId();

        const policy = await pendingPolicyStorage.getPendingPolicy(id);
        if (!policy) {
          res.status(404).json({ error: "Policy not found" });
          return;
        }

        if (policy.status !== "pending") {
          res.status(400).json({ error: "Policy is not pending" });
          return;
        }

        const userVuid = req.tokenPayload?.vuid || req.user?.id || "unknown";
        const userEmail = req.user?.email || "unknown";

        // Check if user already voted
        const hasVoted = await pendingPolicyStorage.hasUserVoted(id, userVuid);
        if (hasVoted) {
          res.status(400).json({ error: "You have already voted on this policy" });
          return;
        }

        const rejected = decision?.rejected === true;

        if (!rejected) {
          // Update the policy request with the newly signed version from Tide enclave
          // This is critical - the signed request contains approval signatures needed for commit
          await pendingPolicyStorage.updatePolicyRequest(id, policyRequest);
          log(`SSH policy ${id} request updated with signed version`);
        }

        await pendingPolicyStorage.addDecision({
          policyRequestId: id,
          userVuid,
          userEmail,
          decision: rejected ? 0 : 1,
        });

        log(`SSH policy ${id} ${rejected ? 'rejected' : 'approved'} by ${userEmail}`);
        res.json({ message: "success" });
      } catch (error) {
        log(`Failed to process policy decision: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // POST /api/admin/ssh-policies/pending/:id/reject - Reject a pending policy
  app.post(
    "/api/admin/ssh-policies/pending/:id/reject",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const policy = await pendingPolicyStorage.getPendingPolicy(id);

        if (!policy) {
          res.status(404).json({ error: "Policy not found" });
          return;
        }

        if (policy.status !== "pending") {
          res.status(400).json({ error: "Policy is not pending" });
          return;
        }

        // Check if user already voted
        const userVuid = req.tokenPayload?.vuid || req.user?.id || "unknown";
        const hasVoted = await pendingPolicyStorage.hasUserVoted(id, userVuid);
        if (hasVoted) {
          res.status(400).json({ error: "You have already voted on this policy" });
          return;
        }

        await pendingPolicyStorage.addDecision({
          policyRequestId: id,
          userVuid,
          userEmail: req.user?.email || "unknown",
          decision: 0, // reject
        });

        log(`SSH policy ${id} rejected by ${req.user?.email}`);
        const updatedPolicy = await pendingPolicyStorage.getPendingPolicy(id);
        res.json({ success: true, policy: updatedPolicy });
      } catch (error) {
        log(`Failed to reject policy: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // POST /api/admin/ssh-policies/pending/:id/commit - Commit an approved policy
  app.post(
    "/api/admin/ssh-policies/pending/:id/commit",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const { signature } = req.body as { signature?: string };

        // Get the pending policy to extract the committed policy bytes
        const pendingPolicy = await pendingPolicyStorage.getPendingPolicy(id);
        if (!pendingPolicy) {
          return res.status(404).json({ error: "Policy not found" });
        }

        // Extract the Policy from the PolicySignRequest and store it WITH the VVK signature
        try {
          const request = PolicySignRequest.decode(base64ToBytes(pendingPolicy.policyRequestData));
          const policy = request.getRequestedPolicy();

          // CRITICAL: Attach the VVK signature to the policy
          // The client sends this signature after executing the PolicySignRequest against Ork
          if (signature) {
            const signatureBytes = base64ToBytes(signature);
            policy.signature = signatureBytes;
            log(`Attached VVK signature to policy (${signatureBytes.length} bytes)`);
          } else {
            log(`Warning: No signature provided for policy commit`);
          }

          const policyBytes = policy.toBytes();
          const policyDataBase64 = bytesToBase64(policyBytes);

          // Store the committed policy bytes in ssh_policies table
          await policyStorage.upsertPolicy({
            roleId: pendingPolicy.roleId,
            contractType: "forseti",
            approvalType: "implicit",
            executionType: "private",
            threshold: pendingPolicy.threshold,
            policyData: policyDataBase64,
          });

          log(`Stored committed policy for role ${pendingPolicy.roleId}, policy bytes: ${policyBytes.length} bytes`);
        } catch (extractError) {
          log(`Warning: Failed to extract policy bytes: ${extractError}`);
          // Continue with commit even if extraction fails
        }

        await pendingPolicyStorage.commitPolicy(id, req.user?.email || "unknown");

        log(`SSH policy ${id} committed by ${req.user?.email}`);
        res.json({ success: true });
      } catch (error) {
        log(`Failed to commit policy: ${error}`);
        res.status(500).json({ error: error instanceof Error ? error.message : "Internal Server Error" });
      }
    }
  );

  // POST /api/admin/ssh-policies/pending/:id/cancel - Cancel a pending policy
  app.post(
    "/api/admin/ssh-policies/pending/:id/cancel",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;

        await pendingPolicyStorage.cancelPolicy(id, req.user?.email || "unknown");

        log(`SSH policy ${id} cancelled by ${req.user?.email}`);
        res.json({ success: true });
      } catch (error) {
        log(`Failed to cancel policy: ${error}`);
        res.status(500).json({ error: error instanceof Error ? error.message : "Internal Server Error" });
      }
    }
  );

  // POST /api/admin/ssh-policies/pending/:id/revoke - Revoke user's decision on a policy
  app.post(
    "/api/admin/ssh-policies/pending/:id/revoke",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const userVuid = req.tokenPayload?.vuid || req.user?.id || "unknown";
        const userEmail = req.user?.email || "unknown";

        const success = await pendingPolicyStorage.revokeDecision(id, userVuid, userEmail);

        if (success) {
          log(`SSH policy ${id} decision revoked by ${userEmail}`);
          res.json({ message: "Decision revoked successfully" });
        } else {
          res.status(400).json({ error: "No decision found to revoke" });
        }
      } catch (error) {
        log(`Failed to revoke decision: ${error}`);
        res.status(500).json({ error: error instanceof Error ? error.message : "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/ssh-policies/logs - Get SSH policy logs
  app.get(
    "/api/admin/ssh-policies/logs",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const limit = parseInt(req.query.limit as string) || 100;
        const logs = await pendingPolicyStorage.getLogs(limit);
        res.json({ logs });
      } catch (error) {
        log(`Failed to fetch policy logs: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/ssh-policies/committed/:roleId - Get committed policy for a role
  // Used by client to attach policy to SSH signing requests
  app.get(
    "/api/ssh-policies/committed/:roleId",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { roleId } = req.params;
        const policy = await policyStorage.getPolicy(roleId);

        if (!policy) {
          return res.status(404).json({ error: "No committed policy found for this role" });
        }

        if (!policy.policyData) {
          return res.status(404).json({ error: "Policy exists but has no committed policy data" });
        }

        res.json({
          roleId: policy.roleId,
          policyData: policy.policyData,
        });
      } catch (error) {
        log(`Failed to fetch committed policy: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/ssh-policies/for-ssh-user/:sshUser - Get committed policy for SSH user
  // Role format is ssh:<sshUser>, e.g. ssh:root, ssh:ubuntu
  app.get(
    "/api/ssh-policies/for-ssh-user/:sshUser",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { sshUser } = req.params;
        const roleId = `ssh:${sshUser}`;

        log(`[PolicyMatch] Looking for policy with roleId: ${roleId}`);

        const policy = await policyStorage.getPolicy(roleId);

        if (!policy) {
          return res.status(404).json({
            error: `No committed policy found for SSH user '${sshUser}'`,
            expectedRoleId: roleId,
          });
        }

        if (!policy.policyData) {
          return res.status(404).json({
            error: `Policy exists for '${sshUser}' but has no committed policy data`,
          });
        }

        log(`[PolicyMatch] Found policy for roleId: ${roleId}`);

        res.json({
          roleId: policy.roleId,
          policyData: policy.policyData,
        });
      } catch (error) {
        log(`Failed to fetch SSH user policy: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // ============================================
  // Admin Session Routes
  // ============================================

  app.get(
    "/api/admin/sessions",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const sessions = await storage.getSessions();
        const servers = await storage.getServers();

        const activeSessions: ActiveSession[] = sessions.map((session) => {
          const server = servers.find((s) => s.id === session.serverId);
          return {
            ...session,
            serverName: server?.name || "Unknown",
            serverHost: server?.host || "Unknown",
          };
        });

        res.json(activeSessions);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch sessions" });
      }
    }
  );

  app.post(
    "/api/admin/sessions/:id/terminate",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const sessionId = req.params.id;

        const terminated = terminateSession(sessionId);
        await storage.endSession(sessionId);

        res.json({
          success: true,
          terminated,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to terminate session" });
      }
    }
  );

  // ============================================
  // Admin Approvals Routes
  // ============================================

  // GET /api/admin/approvals - List all pending approvals
  app.get(
    "/api/admin/approvals",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const approvals = await approvalStorage.getPendingApprovals();
        res.json(approvals);
      } catch (error) {
        log(`Failed to fetch approvals: ${error}`);
        res.status(500).json({ error: "Failed to fetch approvals" });
      }
    }
  );

  // POST /api/admin/approvals - Create new approval or add decision
  app.post(
    "/api/admin/approvals",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const user = req.user!;
        const tokenPayload = req.tokenPayload;
        const userVuid = tokenPayload?.vuid || tokenPayload?.sub || user.id;
        const { type, data, targetUserId, targetUserEmail, approvalId, decision } = req.body;

        // If approvalId is provided, this is a decision on an existing approval
        if (approvalId) {
          if (decision === undefined) {
            res.status(400).json({ error: "Decision is required when approvalId is provided" });
            return;
          }

          const success = await approvalStorage.addDecision(
            approvalId,
            userVuid,
            user.email,
            decision === true || decision === 1
          );

          if (!success) {
            res.status(400).json({ error: "Failed to add decision. You may have already voted." });
            return;
          }

          res.json({ message: "Decision recorded successfully" });
          return;
        }

        // Otherwise, create a new approval request
        if (!type || !data) {
          res.status(400).json({ error: "Type and data are required" });
          return;
        }

        const validTypes: ApprovalType[] = ['user_create', 'user_update', 'user_delete', 'role_assign', 'role_remove'];
        if (!validTypes.includes(type)) {
          res.status(400).json({ error: "Invalid approval type" });
          return;
        }

        const id = await approvalStorage.createApproval(
          type,
          user.email,
          data,
          targetUserId,
          targetUserEmail
        );

        res.json({ message: "Approval request created", id });
      } catch (error) {
        log(`Failed to process approval: ${error}`);
        res.status(500).json({ error: "Failed to process approval" });
      }
    }
  );

  // PUT /api/admin/approvals/:id/commit - Commit an approval
  app.put(
    "/api/admin/approvals/:id/commit",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const user = req.user!;
        const { id } = req.params;

        const success = await approvalStorage.commitApproval(id, user.email);

        if (!success) {
          res.status(404).json({ error: "Approval not found or already processed" });
          return;
        }

        res.json({ message: "Approval committed successfully" });
      } catch (error) {
        log(`Failed to commit approval: ${error}`);
        res.status(500).json({ error: "Failed to commit approval" });
      }
    }
  );

  // PUT /api/admin/approvals/:id/cancel - Cancel an approval
  app.put(
    "/api/admin/approvals/:id/cancel",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const user = req.user!;
        const { id } = req.params;

        const success = await approvalStorage.cancelApproval(id, user.email);

        if (!success) {
          res.status(404).json({ error: "Approval not found or already processed" });
          return;
        }

        res.json({ message: "Approval cancelled successfully" });
      } catch (error) {
        log(`Failed to cancel approval: ${error}`);
        res.status(500).json({ error: "Failed to cancel approval" });
      }
    }
  );

  // DELETE /api/admin/approvals - Delete an approval
  app.delete(
    "/api/admin/approvals",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const user = req.user!;
        const id = req.query.id as string;

        if (!id) {
          res.status(400).json({ error: "Approval ID is required" });
          return;
        }

        const success = await approvalStorage.deleteApproval(id, user.email);

        if (!success) {
          res.status(404).json({ error: "Approval not found" });
          return;
        }

        res.json({ message: "Approval deleted successfully" });
      } catch (error) {
        log(`Failed to delete approval: ${error}`);
        res.status(500).json({ error: "Failed to delete approval" });
      }
    }
  );

  // ============================================
  // TideCloak Access Approvals Routes
  // ============================================

  // GET /api/admin/access-approvals - Get pending access approvals from TideCloak
  app.get(
    "/api/admin/access-approvals",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const data = await GetUserChangeRequests(token);

        const approvals: AccessApproval[] = data.map((item) => {
          // Extract the first user record for display
          const firstUserRecord =
            item.data.userRecord && item.data.userRecord.length > 0
              ? item.data.userRecord[0]
              : null;

          return {
            id: item.data.draftRecordId,
            timestamp: new Date().toISOString(),
            username: firstUserRecord?.username || "Unknown",
            role: item.data.role || "Unknown",
            clientId: item.data.clientId || "Unknown",
            commitReady:
              item.data.status === "APPROVED" ||
              item.data.deleteStatus === "APPROVED" ||
              false,
            decisionMade: false, // Will be determined based on user's vuid
            rejectionFound: false, // Will be determined from API data
            retrievalInfo: item.retrievalInfo,
            data: item.data,
          };
        });

        res.json(approvals);
      } catch (error) {
        log(`Failed to fetch access approvals: ${error}`);
        res.status(500).json({ error: "Failed to fetch access approvals" });
      }
    }
  );

  // POST /api/admin/access-approvals/raw - Get raw change set request for signing
  app.post(
    "/api/admin/access-approvals/raw",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet } = req.body as { changeSet: ChangeSetRequest };

        log(`Getting raw change set request for: ${JSON.stringify(changeSet)}`);

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        if (!changeSet.changeSetType || !changeSet.actionType) {
          res.status(400).json({ error: "changeSetType and actionType are required" });
          return;
        }

        const rawRequest = await GetRawChangeSetRequest(changeSet, token);
        res.json({ rawRequest });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log(`Failed to get raw change set request: ${errorMsg}`);
        res.status(500).json({ error: `Failed to get raw change set request: ${errorMsg}` });
      }
    }
  );

  // POST /api/admin/access-approvals/approve - Approve an access request (legacy without signature)
  app.post(
    "/api/admin/access-approvals/approve",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet, signedRequest } = req.body as {
          changeSet: ChangeSetRequest;
          signedRequest?: string;
        };

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        // If signedRequest is provided, use the new approval with signature
        if (signedRequest) {
          await AddApprovalWithSignedRequest(changeSet, signedRequest, token);
        } else {
          await AddApprovalToChangeRequest(changeSet, token);
        }
        res.json({ message: "Access request approved" });
      } catch (error) {
        log(`Failed to approve access request: ${error}`);
        res.status(500).json({ error: "Failed to approve access request" });
      }
    }
  );

  // POST /api/admin/access-approvals/reject - Reject an access request
  app.post(
    "/api/admin/access-approvals/reject",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet } = req.body as { changeSet: ChangeSetRequest };

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        await AddRejectionToChangeRequest(changeSet, token);
        res.json({ message: "Access request rejected" });
      } catch (error) {
        log(`Failed to reject access request: ${error}`);
        res.status(500).json({ error: "Failed to reject access request" });
      }
    }
  );

  // POST /api/admin/access-approvals/commit - Commit an approved access request
  app.post(
    "/api/admin/access-approvals/commit",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet } = req.body as { changeSet: ChangeSetRequest };

        log(`Committing change set: ${JSON.stringify(changeSet)}`);

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        await CommitChangeRequest(changeSet, token);
        res.json({ message: "Access request committed" });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log(`Failed to commit access request: ${errorMsg}`);
        res.status(500).json({ error: `Failed to commit access request: ${errorMsg}` });
      }
    }
  );

  // POST /api/admin/access-approvals/cancel - Cancel an access request
  app.post(
    "/api/admin/access-approvals/cancel",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet } = req.body as { changeSet: ChangeSetRequest };

        log(`Cancelling change set: ${JSON.stringify(changeSet)}`);

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        await CancelChangeRequest(changeSet, token);
        res.json({ message: "Access request cancelled" });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log(`Failed to cancel access request: ${errorMsg}`);
        res.status(500).json({ error: `Failed to cancel access request: ${errorMsg}` });
      }
    }
  );

  // GET /api/admin/logs/access - Get TideCloak client user events
  app.get(
    "/api/admin/logs/access",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const limit = parseInt(req.query.limit as string) || 100;
        const offset = parseInt(req.query.offset as string) || 0;
        const token = req.accessToken!;
        const events = await GetClientEvents(token, offset, limit);
        res.json(events);
      } catch (error) {
        log(`Failed to fetch access logs: ${error}`);
        res.status(500).json({ message: "Failed to fetch access logs" });
      }
    }
  );

  // ============================================
  // Admin Policy Template Routes
  // ============================================

  // GET /api/admin/policy-templates - List all templates (any admin can view)
  app.get(
    "/api/admin/policy-templates",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const templates = await templateStorage.getAllTemplates();
        res.json({ templates });
      } catch (error) {
        log(`Failed to fetch policy templates: ${error}`);
        res.status(500).json({ error: "Failed to fetch policy templates" });
      }
    }
  );

  // GET /api/admin/policy-templates/:id - Get a specific template
  app.get(
    "/api/admin/policy-templates/:id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const template = await templateStorage.getTemplate(id);

        if (!template) {
          res.status(404).json({ error: "Template not found" });
          return;
        }

        res.json({ template });
      } catch (error) {
        log(`Failed to fetch policy template: ${error}`);
        res.status(500).json({ error: "Failed to fetch policy template" });
      }
    }
  );

  // POST /api/admin/policy-templates - Create a new template (requires policy creator role)
  app.post(
    "/api/admin/policy-templates",
    authenticate,
    requirePolicyCreator,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { name, description, csCode, parameters } = req.body;
        const user = req.user!;

        if (!name || !description || !csCode) {
          res.status(400).json({ error: "name, description, and csCode are required" });
          return;
        }

        // Check if template with same name exists
        const existing = await templateStorage.getTemplateByName(name);
        if (existing) {
          res.status(400).json({ error: "A template with this name already exists" });
          return;
        }

        const template = await templateStorage.createTemplate({
          name,
          description,
          csCode,
          parameters: parameters || [],
          createdBy: user.email,
        });

        log(`Policy template created: ${name} by ${user.email}`);
        res.json({ template });
      } catch (error) {
        log(`Failed to create policy template: ${error}`);
        res.status(500).json({ error: "Failed to create policy template" });
      }
    }
  );

  // PUT /api/admin/policy-templates/:id - Update a template (requires policy creator role)
  app.put(
    "/api/admin/policy-templates/:id",
    authenticate,
    requirePolicyCreator,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const { name, description, csCode, parameters } = req.body;
        const user = req.user!;

        const existing = await templateStorage.getTemplate(id);
        if (!existing) {
          res.status(404).json({ error: "Template not found" });
          return;
        }

        // If changing name, check for conflicts
        if (name && name !== existing.name) {
          const nameConflict = await templateStorage.getTemplateByName(name);
          if (nameConflict) {
            res.status(400).json({ error: "A template with this name already exists" });
            return;
          }
        }

        const template = await templateStorage.updateTemplate(id, {
          name,
          description,
          csCode,
          parameters,
        });

        log(`Policy template updated: ${template?.name} by ${user.email}`);
        res.json({ template });
      } catch (error) {
        log(`Failed to update policy template: ${error}`);
        res.status(500).json({ error: "Failed to update policy template" });
      }
    }
  );

  // DELETE /api/admin/policy-templates/:id - Delete a template (requires policy creator role)
  app.delete(
    "/api/admin/policy-templates/:id",
    authenticate,
    requirePolicyCreator,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const user = req.user!;

        const existing = await templateStorage.getTemplate(id);
        if (!existing) {
          res.status(404).json({ error: "Template not found" });
          return;
        }

        // Prevent deleting system templates
        if (existing.createdBy === "system") {
          res.status(403).json({ error: "Cannot delete system templates" });
          return;
        }

        const success = await templateStorage.deleteTemplate(id);
        if (!success) {
          res.status(500).json({ error: "Failed to delete template" });
          return;
        }

        log(`Policy template deleted: ${existing.name} by ${user.email}`);
        res.json({ success: true });
      } catch (error) {
        log(`Failed to delete policy template: ${error}`);
        res.status(500).json({ error: "Failed to delete policy template" });
      }
    }
  );

  // POST /api/admin/policy-templates/:id/preview - Preview template with parameters replaced
  app.post(
    "/api/admin/policy-templates/:id/preview",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const { params } = req.body;

        const template = await templateStorage.getTemplate(id);
        if (!template) {
          res.status(404).json({ error: "Template not found" });
          return;
        }

        // Replace placeholders with provided values
        let code = template.csCode;
        if (params && typeof params === "object") {
          for (const [key, value] of Object.entries(params)) {
            const placeholder = `{{${key}}}`;
            code = code.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), String(value));
          }
        }

        res.json({ code });
      } catch (error) {
        log(`Failed to preview policy template: ${error}`);
        res.status(500).json({ error: "Failed to preview policy template" });
      }
    }
  );

  // ============================================
  // Forseti Contract Compilation
  // ============================================

  // POST /api/forseti/compile - Compile contract and get hash
  app.post(
    "/api/forseti/compile",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { source, validate = true, entryType } = req.body;

        if (!source || typeof source !== "string") {
          res.status(400).json({ error: "source is required and must be a string" });
          return;
        }

        log(`Compiling Forseti contract (validate=${validate}, entryType=${entryType || "auto"})`);

        const result = await compileForsetiContract(source, { validate, entryType });

        if (!result.success) {
          log(`Contract compilation failed: ${result.error}`);
          res.status(400).json({
            success: false,
            error: result.error,
          });
          return;
        }

        log(`Contract compiled successfully: ${result.contractId?.substring(0, 16)}...`);
        res.json({
          success: true,
          contractId: result.contractId,
          sdkVersion: result.sdkVersion,
          validated: result.validated,
        });
      } catch (error) {
        log(`Failed to compile contract: ${error}`);
        res.status(500).json({ error: "Failed to compile contract" });
      }
    }
  );

  return httpServer;
}
