import type { Express } from "express";
import type { Server } from "http";
import { storage, approvalStorage, type ApprovalType } from "./storage";
import { log } from "./logger";
import { terminateSession } from "./wsBridge";
import type { ServerWithAccess, ActiveSession, ServerStatus, Server as ServerType } from "@shared/schema";

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
        allowedSshUsers: server.sshUsers || [],
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
        allowedSshUsers: server.sshUsers || [],
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

      const server = await storage.getServer(serverId);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      if (user.role !== "admin" && !server.enabled) {
        res.status(404).json({ message: "Server not found" });
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
          allowedSshUsers: server.sshUsers || [],
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
        const { name, description } = req.body;

        if (!name) {
          res.status(400).json({ error: "Role name is required" });
          return;
        }

        await tidecloakAdmin.createRole(token, { name, description });

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

        await tidecloakAdmin.deleteRole(token, roleName);

        res.json({ success: "Role has been deleted!" });
      } catch (error) {
        log(`Failed to delete role: ${error}`);
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

  return httpServer;
}
