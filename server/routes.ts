import type { Express } from "express";
import type { Server } from "http";
import { storage, approvalStorage, policyStorage, pendingPolicyStorage, templateStorage, subscriptionStorage, recordingStorage, fileOperationStorage, type ApprovalType } from "./storage";
import { subscriptionTiers, type SubscriptionTier } from "@shared/schema";
import * as stripeLib from "./lib/stripe";
import { log, logForseti, logError } from "./logger";
import type { ServerWithAccess, ActiveSession, ServerStatus, Server as ServerType } from "@shared/schema";
import { createRequire } from "module";
import { getHomeOrkUrl, GetConfig } from "./lib/auth/tidecloakConfig";
import { createConnection } from "net";
import { createHash } from "crypto";

// Use createRequire for heimdall-tide (CJS module with broken ESM exports)
// In CJS bundle __filename is available; in ESM dev mode use import.meta.url
const require = createRequire(
  typeof __filename !== "undefined" ? __filename : import.meta.url
);
const { PolicySignRequest } = require("heimdall-tide");

// Base64 conversion helpers for Tide request handling
function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function checkTcpReachable(host: string, port: number, timeoutMs = 2500): Promise<boolean> {
  return await new Promise((resolve) => {
    const socket = createConnection({ host, port });
    let settled = false;
    let timeoutId: NodeJS.Timeout | undefined;
    let bannerTimeoutId: NodeJS.Timeout | undefined;

    const cleanup = () => {
      if (timeoutId) clearTimeout(timeoutId);
      if (bannerTimeoutId) clearTimeout(bannerTimeoutId);
      socket.removeAllListeners();
      try {
        socket.destroy();
      } catch {
        // ignore
      }
    };

    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(ok);
    };

    timeoutId = setTimeout(() => finish(false), timeoutMs);

    socket.once("connect", () => {
      // Optional banner sniff for extra confidence; do not fail if banner isn't sent immediately.
      bannerTimeoutId = setTimeout(() => finish(true), 400);
      socket.once("data", (data: Buffer) => {
        const banner = data.toString("utf8");
        void banner; // just a sniff; not strictly required
        finish(true);
      });
    });

    socket.once("error", () => finish(false));
  });
}

// Check server health by calling its health check URL
async function checkServerHealth(server: ServerType): Promise<ServerStatus> {
  const ok = await checkTcpReachable(server.host, server.port ?? 22);
  return ok ? "online" : "offline";
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
  GetRoleChangeRequests,
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
import { verifyTideCloakToken } from "./lib/auth/tideJWT";

// SSH connections are handled via WebSocket TCP bridge
// The browser runs SSH client (using @microsoft/dev-tunnels-ssh)
// and connects through /ws/tcp to reach SSH servers

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // ============================================
  // Stripe Webhook (unauthenticated, must come before auth middleware)
  // ============================================

  app.post("/api/webhooks/stripe", async (req, res) => {
    try {
      if (!stripeLib.isStripeConfigured()) {
        res.status(503).json({ error: "Stripe is not configured" });
        return;
      }

      const signature = req.headers["stripe-signature"];
      if (!signature || typeof signature !== "string") {
        res.status(400).json({ error: "Missing stripe-signature header" });
        return;
      }

      // Use raw body for webhook verification
      const rawBody = (req as any).rawBody;
      if (!rawBody) {
        res.status(400).json({ error: "Missing raw body" });
        return;
      }

      let event;
      try {
        event = stripeLib.constructWebhookEvent(rawBody, signature);
      } catch (err) {
        log(`Webhook signature verification failed: ${err}`);
        res.status(400).json({ error: "Webhook signature verification failed" });
        return;
      }

      log(`Stripe webhook received: ${event.type}`);

      // Handle the event
      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object as any;
          if (session.mode === "subscription" && session.subscription) {
            const subscriptionId = session.subscription as string;
            const customerId = session.customer as string;

            // Get the subscription to find the price/tier
            const stripeSubscription = await stripeLib.getSubscription(subscriptionId);
            const priceId = stripeSubscription.items.data[0]?.price.id;
            const tier = stripeLib.getTierFromPriceId(priceId || "");

            const currentPeriodEnd = stripeSubscription.current_period_end ?? null;

            await subscriptionStorage.upsertSubscription({
              tier,
              stripeCustomerId: customerId,
              stripeSubscriptionId: subscriptionId,
              stripePriceId: priceId,
              status: "active",
              currentPeriodEnd: currentPeriodEnd ?? undefined,
            });

            log(`Subscription created/updated: ${tier} tier for customer ${customerId}`);
          }
          break;
        }

        case "customer.subscription.updated": {
          const subscription = event.data.object as any;
          const priceId = subscription.items.data[0]?.price.id;
          const tier = stripeLib.getTierFromPriceId(priceId || "");

          await subscriptionStorage.upsertSubscription({
            tier,
            stripeSubscriptionId: subscription.id,
            stripePriceId: priceId,
            status: subscription.status,
            currentPeriodEnd: subscription.current_period_end,
            cancelAtPeriodEnd: subscription.cancel_at_period_end,
          });

          log(`Subscription updated: ${tier} tier, status: ${subscription.status}`);
          break;
        }

        case "customer.subscription.deleted": {
          // Subscription cancelled - revert to free tier
          await subscriptionStorage.upsertSubscription({
            tier: "free",
            status: "canceled",
            stripeSubscriptionId: null as any,
            stripePriceId: null as any,
          });

          log(`Subscription deleted - reverted to free tier`);
          break;
        }

        case "invoice.paid": {
          const invoice = event.data.object as any;
          await subscriptionStorage.addBillingRecord({
            stripeInvoiceId: invoice.id,
            amount: invoice.amount_paid,
            currency: invoice.currency,
            status: "paid",
            invoicePdf: invoice.invoice_pdf,
            description: invoice.lines?.data?.[0]?.description || "Subscription payment",
          });

          log(`Invoice paid: ${invoice.id} for ${invoice.amount_paid / 100} ${invoice.currency.toUpperCase()}`);
          break;
        }

        case "invoice.payment_failed": {
          const invoice = event.data.object as any;
          await subscriptionStorage.upsertSubscription({
            status: "past_due",
          });

          await subscriptionStorage.addBillingRecord({
            stripeInvoiceId: invoice.id,
            amount: invoice.amount_due,
            currency: invoice.currency,
            status: "failed",
            description: "Payment failed",
          });

          log(`Invoice payment failed: ${invoice.id}`);
          break;
        }

        default:
          log(`Unhandled webhook event: ${event.type}`);
      }

      res.json({ received: true });
    } catch (error) {
      log(`Webhook error: ${error}`);
      res.status(500).json({ error: "Webhook processing failed" });
    }
  });

  // ============================================
  // Public Auth Config (unauthenticated)
  // ============================================

  app.get("/api/auth/config", (_req, res) => {
    try {
      const config = GetConfig();
      res.json(config);
    } catch (error) {
      log(`Failed to load auth config: ${error}`);
      res.status(500).json({ error: "Failed to load authentication configuration" });
    }
  });

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

      // Refresh and check if SSH access is blocked due to over-limit
      const token = req.accessToken;
      if (token) {
        try {
          const users = await tidecloakAdmin.getUsers(token);
          // Count ALL enabled users (including admins) for the limit check
          const enabledCount = users.filter(u => u.enabled).length;
          const subscription = await subscriptionStorage.getSubscription();
          const tier = (subscription?.tier as SubscriptionTier) || 'free';
          const tierConfig = subscriptionTiers[tier];
          const userLimit = tierConfig.maxUsers;
          const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
          const serverCounts = await subscriptionStorage.getServerCounts();
          const serverLimit = tierConfig.maxServers;
          const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
          await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);
        } catch {
          // If we can't refresh, continue with cached status
        }
      }
      const sshStatus = await subscriptionStorage.isSshBlocked();
      if (sshStatus.blocked) {
        res.status(403).json({ message: sshStatus.reason || "SSH access is currently disabled" });
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

      // Check if recording is enabled for this server/user
      let recordingEnabled = false;
      if (server.recordingEnabled) {
        const recordedUsers = server.recordedUsers || [];
        recordingEnabled = recordedUsers.length === 0 || recordedUsers.includes(sshUser);
      }

      // Include bridge URL and server details in response
      res.json({
        ...session,
        bridgeUrl: process.env.BRIDGE_URL || null,
        host: server.host,
        port: server.port ?? 22,
        recordingEnabled,
      });
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

        // Refresh and check if SSH access is blocked due to over-limit
        const token = req.accessToken;
        if (token) {
          try {
            const users = await tidecloakAdmin.getUsers(token);
            // Count ALL enabled users (including admins) for the limit check
            const enabledCount = users.filter(u => u.enabled).length;
            const subscription = await subscriptionStorage.getSubscription();
            const tier = (subscription?.tier as SubscriptionTier) || 'free';
            const tierConfig = subscriptionTiers[tier];
            const userLimit = tierConfig.maxUsers;
            const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
            const serverCounts = await subscriptionStorage.getServerCounts();
            const serverLimit = tierConfig.maxServers;
            const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
            await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);
          } catch {
            // If we can't refresh, continue with cached status
          }
        }
        const sshStatus = await subscriptionStorage.isSshBlocked();
        if (sshStatus.blocked) {
          res.status(403).json({ message: sshStatus.reason || "SSH access is currently disabled" });
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

  // GET /api/ssh/access-status - Check if SSH access is blocked for the current user
  app.get(
    "/api/ssh/access-status",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        // Refresh the over-limit status using the user's token for real-time accuracy
        const token = req.accessToken;
        if (token) {
          try {
            const users = await tidecloakAdmin.getUsers(token);
            // Count ALL enabled users (including admins) for the limit check
            // Admins count toward the limit, they just can't be individually disabled
            const enabledCount = users.filter(u => u.enabled).length;
            const subscription = await subscriptionStorage.getSubscription();
            const tier = (subscription?.tier as SubscriptionTier) || 'free';
            const tierConfig = subscriptionTiers[tier];
            const userLimit = tierConfig.maxUsers;
            const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
            const serverCounts = await subscriptionStorage.getServerCounts();
            const serverLimit = tierConfig.maxServers;
            const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
            log(`SSH access check: ${enabledCount} enabled users (limit: ${userLimit}), ${serverCounts.enabled} enabled servers (limit: ${serverLimit}), usersOver: ${isUsersOverLimit}, serversOver: ${isServersOverLimit}`);
            await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);
          } catch (err) {
            log(`Failed to refresh over-limit status: ${err}`);
          }
        } else {
          log(`SSH access check: no token available`);
        }

        const status = await subscriptionStorage.isSshBlocked();
        res.json(status);
      } catch (error) {
        log(`Failed to check SSH access status: ${error}`);
        res.status(500).json({ message: "Failed to check SSH access status" });
      }
    }
  );

  // ============================================
  // TCP Bridge Validation Endpoints
  // ============================================

  // POST /api/bridge/validate - Validate session for TCP bridge connection
  // Called by tcp-bridge service to verify a session before allowing SSH traffic
  app.post("/api/bridge/validate", async (req, res) => {
    try {
      const { token, sessionId, serverId } = req.body;

      if (!token || !sessionId || !serverId) {
        res.status(400).json({ valid: false, error: "Missing required parameters" });
        return;
      }

      // Verify JWT token
      const payload = await verifyTideCloakToken(token, []);
      if (!payload) {
        res.status(401).json({ valid: false, error: "Invalid or expired token" });
        return;
      }

      const userId = payload.sub;
      if (!userId) {
        res.status(401).json({ valid: false, error: "Invalid token: missing sub" });
        return;
      }

      // Validate session exists and is active
      const session = await storage.getSession(sessionId);
      if (!session) {
        res.status(404).json({ valid: false, error: "Unknown session" });
        return;
      }
      if (session.status !== "active") {
        res.status(400).json({ valid: false, error: "Session is not active" });
        return;
      }
      if (session.userId !== userId || session.serverId !== serverId) {
        res.status(403).json({ valid: false, error: "Session does not match user/server" });
        return;
      }

      // Enforce SSH username allowlist from JWT roles/claims
      const allowed = getAllowedSshUsersFromToken(payload);
      if (!allowed.includes(session.sshUser)) {
        res.status(403).json({ valid: false, error: `Not allowed to SSH as '${session.sshUser}'` });
        return;
      }

      // Validate server exists and is enabled
      const server = await storage.getServer(serverId);
      if (!server) {
        res.status(404).json({ valid: false, error: "Unknown server" });
        return;
      }
      if (!server.enabled) {
        res.status(403).json({ valid: false, error: "Server is disabled" });
        return;
      }

      // Check subscription limits
      try {
        const users = await tidecloakAdmin.getUsers(token);
        const enabledCount = users.filter(u => u.enabled).length;
        const subscription = await subscriptionStorage.getSubscription();
        const tier = (subscription?.tier as SubscriptionTier) || 'free';
        const tierConfig = subscriptionTiers[tier];
        const userLimit = tierConfig.maxUsers;
        const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
        const serverCounts = await subscriptionStorage.getServerCounts();
        const serverLimit = tierConfig.maxServers;
        const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
        await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);
      } catch {
        // If we can't refresh, continue with cached status
      }
      const sshStatus = await subscriptionStorage.isSshBlocked();
      if (sshStatus.blocked) {
        res.status(403).json({ valid: false, error: "SSH access is currently disabled" });
        return;
      }

      // Check if recording is enabled
      let recordingEnabled = false;
      if (server.recordingEnabled) {
        const recordedUsers = server.recordedUsers || [];
        recordingEnabled = recordedUsers.length === 0 || recordedUsers.includes(session.sshUser);
      }

      res.json({
        valid: true,
        host: server.host,
        port: server.port ?? 22,
        recordingEnabled,
        serverName: server.name,
        sshUser: session.sshUser,
        userEmail: session.userEmail,
      });
    } catch (error) {
      log(`Bridge validation error: ${error}`);
      res.status(500).json({ valid: false, error: "Internal server error" });
    }
  });

  // POST /api/sessions/:id/start-recording - Start a recording for a session
  app.post("/api/sessions/:id/start-recording", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const sessionId = req.params.id;
      const { terminalWidth, terminalHeight } = req.body;

      const session = await storage.getSession(sessionId);
      if (!session) {
        res.status(404).json({ error: "Session not found" });
        return;
      }

      // Only allow starting recording for own sessions
      if (session.userId !== user.id) {
        res.status(403).json({ error: "Access denied" });
        return;
      }

      const server = await storage.getServer(session.serverId);
      if (!server) {
        res.status(404).json({ error: "Server not found" });
        return;
      }

      // Check if recording is enabled for this server/user
      if (!server.recordingEnabled) {
        res.status(400).json({ error: "Recording not enabled for this server" });
        return;
      }

      const recordedUsers = server.recordedUsers || [];
      const shouldRecord = recordedUsers.length === 0 || recordedUsers.includes(session.sshUser);
      if (!shouldRecord) {
        res.status(400).json({ error: "Recording not enabled for this SSH user" });
        return;
      }

      // Create recording
      const width = terminalWidth || 80;
      const height = terminalHeight || 24;
      const recording = await recordingStorage.createRecording({
        sessionId,
        serverId: session.serverId,
        serverName: server.name,
        userId: user.id,
        userEmail: user.email || "",
        sshUser: session.sshUser,
        terminalWidth: width,
        terminalHeight: height,
      });

      // Write asciicast header
      const timestamp = Math.floor(Date.now() / 1000);
      const header = JSON.stringify({ version: 2, width, height, timestamp }) + "\n";
      await recordingStorage.appendData(recording.id, header);

      // Link recording to session
      await storage.updateSession(sessionId, { recordingId: recording.id });

      log(`Started recording ${recording.id} for session ${sessionId}`);
      res.json({ recordingId: recording.id, startTime: Date.now() });
    } catch (error) {
      log(`Start recording error: ${error}`);
      res.status(500).json({ error: "Failed to start recording" });
    }
  });

  // POST /api/sessions/:id/record - Append a recording event
  app.post("/api/sessions/:id/record", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const sessionId = req.params.id;
      const { recordingId, time, eventType, data } = req.body;

      if (!recordingId || time === undefined || !eventType || data === undefined) {
        res.status(400).json({ error: "Missing required fields" });
        return;
      }

      const session = await storage.getSession(sessionId);
      if (!session) {
        res.status(404).json({ error: "Session not found" });
        return;
      }

      if (session.userId !== user.id) {
        res.status(403).json({ error: "Access denied" });
        return;
      }

      // Append recording event (asciicast v2 format)
      const event = JSON.stringify([time, eventType, data]) + "\n";
      await recordingStorage.appendData(recordingId, event);

      // Append text content for search (output only)
      if (eventType === "o") {
        // Strip ANSI codes
        const text = data.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
        await recordingStorage.appendTextContent(recordingId, text);
      }

      res.json({ success: true });
    } catch (error) {
      log(`Record event error: ${error}`);
      res.status(500).json({ error: "Failed to record event" });
    }
  });

  // POST /api/sessions/:id/end-recording - Finalize a recording
  app.post("/api/sessions/:id/end-recording", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const sessionId = req.params.id;
      const { recordingId } = req.body;

      if (!recordingId) {
        res.status(400).json({ error: "Missing recordingId" });
        return;
      }

      const session = await storage.getSession(sessionId);
      if (!session) {
        res.status(404).json({ error: "Session not found" });
        return;
      }

      if (session.userId !== user.id) {
        res.status(403).json({ error: "Access denied" });
        return;
      }

      await recordingStorage.finalizeRecording(recordingId);
      log(`Finalized recording ${recordingId} for session ${sessionId}`);
      res.json({ success: true });
    } catch (error) {
      log(`End recording error: ${error}`);
      res.status(500).json({ error: "Failed to end recording" });
    }
  });

  // POST /api/sessions/:id/file-op - Log a file operation
  app.post("/api/sessions/:id/file-op", authenticate, async (req: AuthenticatedRequest, res) => {
    try {
      const user = req.user!;
      const sessionId = req.params.id;
      const { operation, path, targetPath, fileSize, mode, status, errorMessage } = req.body;

      if (!operation || !path || !mode || !status) {
        res.status(400).json({ error: "Missing required fields" });
        return;
      }

      const session = await storage.getSession(sessionId);
      if (!session) {
        res.status(404).json({ error: "Session not found" });
        return;
      }

      if (session.userId !== user.id) {
        res.status(403).json({ error: "Access denied" });
        return;
      }

      await fileOperationStorage.logOperation({
        sessionId,
        serverId: session.serverId,
        userId: user.id,
        userEmail: session.userEmail || undefined,
        sshUser: session.sshUser,
        operation,
        path,
        targetPath,
        fileSize,
        mode,
        status,
        errorMessage,
      });

      log(`File op: ${operation} ${path} (${mode}, ${status}) - session ${sessionId}`);
      res.json({ success: true });
    } catch (error) {
      log(`File op error: ${error}`);
      res.status(500).json({ error: "Failed to log file operation" });
    }
  });

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

  app.get(
    "/api/admin/servers/status",
    authenticate,
    requireAdmin,
    async (_req: AuthenticatedRequest, res) => {
      try {
        const servers = await storage.getServers();
        const healthStatusMap = await checkServersHealth(servers);
        const statuses: Record<string, ServerStatus> = {};
        for (const s of servers) {
          statuses[s.id] = healthStatusMap.get(s.id) || "unknown";
        }
        res.json({ statuses });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch server statuses" });
      }
    }
  );

  app.post(
    "/api/admin/servers",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        // Check server limit before creating
        const serverCount = await subscriptionStorage.getServerCount();
        const limitCheck = await subscriptionStorage.checkCanAdd('server', serverCount);
        if (!limitCheck.allowed) {
          res.status(403).json({
            error: 'Server limit reached',
            message: `Your ${limitCheck.tierName} plan allows ${limitCheck.limit} servers. Upgrade to add more.`,
            current: limitCheck.current,
            limit: limitCheck.limit,
            tier: limitCheck.tier,
            upgradeRequired: true,
          });
          return;
        }

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

        // Update the over-limit status after deleting user
        // Count ALL enabled users (including admins) for the limit check
        const users = await tidecloakAdmin.getUsers(token);
        const enabledCount = users.filter(u => u.enabled).length;
        const subscription = await subscriptionStorage.getSubscription();
        const tier = (subscription?.tier as SubscriptionTier) || 'free';
        const tierConfig = subscriptionTiers[tier];
        const userLimit = tierConfig.maxUsers;
        const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
        const serverCounts = await subscriptionStorage.getServerCounts();
        const serverLimit = tierConfig.maxServers;
        const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
        await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);

        res.json({ success: true });
      } catch (error) {
        log(`Failed to delete user: ${error}`);
        res.status(400).json({ error: "Failed to delete user" });
      }
    }
  );

  // PUT /api/admin/users/:id/enabled - Enable or disable a user
  app.put(
    "/api/admin/users/:id/enabled",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const userId = req.params.id;
        const { enabled } = req.body;

        if (typeof enabled !== "boolean") {
          res.status(400).json({ error: "enabled must be a boolean" });
          return;
        }

        await tidecloakAdmin.setUserEnabled(token, userId, enabled);

        // Update the over-limit status after changing user enabled state
        // Count ALL enabled users (including admins) for the limit check
        const users = await tidecloakAdmin.getUsers(token);
        const enabledCount = users.filter(u => u.enabled).length;
        const subscription = await subscriptionStorage.getSubscription();
        const tier = (subscription?.tier as SubscriptionTier) || 'free';
        const tierConfig = subscriptionTiers[tier];
        const userLimit = tierConfig.maxUsers;
        const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
        const serverCounts = await subscriptionStorage.getServerCounts();
        const serverLimit = tierConfig.maxServers;
        const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
        await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);

        res.json({ success: true, enabled });
      } catch (error) {
        log(`Failed to set user enabled status: ${error}`);
        res.status(400).json({ error: "Failed to update user status" });
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

        // Check user limit before creating
        const users = await tidecloakAdmin.getUsers(token);
        const limitCheck = await subscriptionStorage.checkCanAdd('user', users.length);
        if (!limitCheck.allowed) {
          res.status(403).json({
            error: 'User limit reached',
            message: `Your ${limitCheck.tierName} plan allows ${limitCheck.limit} users. Upgrade to add more.`,
            current: limitCheck.current,
            limit: limitCheck.limit,
            tier: limitCheck.tier,
            upgradeRequired: true,
          });
          return;
        }

        await tidecloakAdmin.addUser(token, { username, firstName, lastName, email });

        // Update the over-limit status after adding user
        // Count ALL enabled users (including admins) for the limit check
        const updatedUsers = await tidecloakAdmin.getUsers(token);
        const enabledCount = updatedUsers.filter(u => u.enabled).length;
        const subscription = await subscriptionStorage.getSubscription();
        const tier = (subscription?.tier as SubscriptionTier) || 'free';
        const tierConfig = subscriptionTiers[tier];
        const userLimit = tierConfig.maxUsers;
        const isUsersOverLimit = userLimit !== -1 && enabledCount > userLimit;
        const serverCounts = await subscriptionStorage.getServerCounts();
        const serverLimit = tierConfig.maxServers;
        const isServersOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;
        await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);

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
        const result = await tidecloakAdmin.deleteRole(token, roleName);

        // Also delete any associated SSH policy (only if role was actually deleted, not queued for approval)
        if (!result.approvalCreated) {
          try {
            await policyStorage.deletePolicy(roleName);
          } catch (policyError) {
            log(`Warning: Role deleted but failed to delete policy: ${policyError}`);
          }
        }

        // Return appropriate message based on whether an approval was created
        if (result.approvalCreated) {
          res.json({ success: "Approval request created", approvalCreated: true });
        } else {
          res.json({ success: "Role has been deleted!", approvalCreated: false });
        }
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
        const { policyRequest, roleName, threshold, contractCode } = req.body;

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
          contractCode: contractCode || undefined,
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

        // Only reject if policy is committed or cancelled - pending/approved can accept new votes
        if (policy.status === "committed" || policy.status === "cancelled") {
          res.status(400).json({ error: `Policy is ${policy.status}` });
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

        // Only reject if policy is committed or cancelled
        if (policy.status === "committed" || policy.status === "cancelled") {
          res.status(400).json({ error: `Policy is ${policy.status}` });
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
  // Removes approval signature from PolicySignRequest if the revoked decision was an approval
  app.post(
    "/api/admin/ssh-policies/pending/:id/revoke",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { id } = req.params;
        const userVuid = req.tokenPayload?.vuid || req.user?.id || "unknown";
        const userEmail = req.user?.email || "unknown";

        // First check if the user's decision was an approval (1) or rejection (0)
        const decision = await pendingPolicyStorage.getUserDecision(id, userVuid);
        if (decision === null) {
          res.status(400).json({ error: "No decision found to revoke" });
          return;
        }

        // If it was an approval, we need to remove the approval from the PolicySignRequest
        if (decision === 1) {
          const policy = await pendingPolicyStorage.getPendingPolicy(id);
          if (policy) {
            try {
              const request = PolicySignRequest.decode(base64ToBytes(policy.policyRequestData));
              const removalSuccess = request.removeApproval(userVuid);

              if (!removalSuccess) {
                log(`Warning: Could not remove approval from request for ${id}, user ${userVuid}`);
                // Continue anyway - the database decision will still be removed
              } else {
                // Update the stored request with approval removed
                const updatedRequestData = bytesToBase64(request.encode());
                await pendingPolicyStorage.updatePolicyRequest(id, updatedRequestData);
                log(`Removed approval from PolicySignRequest for ${id}`);
              }
            } catch (decodeError) {
              log(`Warning: Could not decode policy request for approval removal: ${decodeError}`);
              // Continue anyway - the database decision will still be removed
            }
          }
        }

        const success = await pendingPolicyStorage.revokeDecision(id, userVuid);

        if (success) {
          // After revoking, check if policy should go back to "pending" status
          const updatedPolicy = await pendingPolicyStorage.getPendingPolicy(id);
          if (updatedPolicy && updatedPolicy.status === "approved") {
            // If approval count dropped below threshold, set back to pending
            const approvalCount = updatedPolicy.approvalCount || 0;
            if (approvalCount < updatedPolicy.threshold) {
              await pendingPolicyStorage.updateStatus(id, "pending");
              log(`SSH policy ${id} status changed back to pending (approvals: ${approvalCount}/${updatedPolicy.threshold})`);
            }
          }
          log(`SSH policy ${id} decision revoked by ${userEmail}`);
          res.json({ message: "Decision revoked successfully" });
        } else {
          res.status(400).json({ error: "Failed to revoke decision" });
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
        const offset = parseInt(req.query.offset as string) || 0;
        const rawLogs = await pendingPolicyStorage.getLogs(limit, offset);
        // Map field names to match client API interface
        const logs = rawLogs.map(log => ({
          id: log.id,
          policyId: log.policyRequestId,
          roleId: log.roleId,
          action: log.type,
          performedBy: log.userEmail,
          performedByEmail: log.userEmail,
          details: log.details,
          createdAt: log.timestamp,
          policyStatus: log.policyStatus,
          policyThreshold: log.policyThreshold,
          policyCreatedAt: log.policyCreatedAt,
          policyRequestedBy: log.policyRequestedBy,
          approvalCount: log.approvalCount,
          rejectionCount: log.rejectionCount,
        }));
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

        // End session in database - the tcp-bridge connection will
        // close when the client's next action fails validation
        await storage.endSession(sessionId);

        res.json({
          success: true,
          message: "Session marked as ended",
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to terminate session" });
      }
    }
  );

  // GET /api/admin/sessions/:id/file-operations - Get file operations for a session
  app.get(
    "/api/admin/sessions/:id/file-operations",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const sessionId = req.params.id;
        const operations = await fileOperationStorage.getOperationsBySession(sessionId);
        res.json({ operations });
      } catch (error) {
        log(`Failed to fetch session file operations: ${error}`);
        res.status(500).json({ message: "Failed to fetch session file operations" });
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

        const rawRequests = await GetRawChangeSetRequest(changeSet, token);
        // Return all sign requests (may include user + policy requests)
        res.json({ rawRequests });
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

  // POST /api/admin/access-approvals/approve-with-id - Approve with explicit changeSetId (for multi-request flow)
  app.post(
    "/api/admin/access-approvals/approve-with-id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSetId, actionType, changeSetType, signedRequest } = req.body as {
          changeSetId: string;
          actionType: string;
          changeSetType: string;
          signedRequest: string;
        };

        if (!changeSetId || !actionType || !changeSetType || !signedRequest) {
          res.status(400).json({ error: "changeSetId, actionType, changeSetType, and signedRequest are required" });
          return;
        }

        // Build changeSet object from explicit IDs
        const changeSet: ChangeSetRequest = {
          changeSetId,
          actionType,
          changeSetType,
        };

        await AddApprovalWithSignedRequest(changeSet, signedRequest, token);
        res.json({ message: "Access request approved" });
      } catch (error) {
        log(`Failed to approve access request with id: ${error}`);
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

  // ============================================
  // Role Approvals API (TideCloak Change Set - Roles)
  // ============================================

  // GET /api/admin/role-approvals - Get pending role change requests from TideCloak
  app.get(
    "/api/admin/role-approvals",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const requests = await GetRoleChangeRequests(token);

        // Transform to match frontend expectations
        const approvals: AccessApproval[] = requests.map((req) => ({
          id: req.retrievalInfo.changeSetId,
          requestType: req.data.actionType || req.data.action,
          status: req.data.status,
          requestedBy: req.data.userRecord?.[0]?.username || "Unknown",
          requestedAt: req.data.createdAt || new Date().toISOString(),
          role: req.data.role,
          compositeRole: req.data.compositeRole,
          clientId: req.data.clientId,
          changeSetType: req.data.changeSetType,
          userRecords: req.data.userRecord || [],
          retrievalInfo: req.retrievalInfo,
        }));
        res.json(approvals);
      } catch (error) {
        log(`Failed to fetch role approvals: ${error}`);
        res.status(500).json({ message: "Failed to fetch role approvals" });
      }
    }
  );

  // POST /api/admin/role-approvals/raw - Get raw change set request for signing
  app.post(
    "/api/admin/role-approvals/raw",
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

        const rawRequests = await GetRawChangeSetRequest(changeSet, token);
        res.json({ rawRequests });
      } catch (error) {
        log(`Failed to get raw role change request: ${error}`);
        res.status(500).json({ error: "Failed to get raw change request" });
      }
    }
  );

  // POST /api/admin/role-approvals/approve - Approve a role change request
  app.post(
    "/api/admin/role-approvals/approve",
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

        if (signedRequest) {
          await AddApprovalWithSignedRequest(changeSet, signedRequest, token);
        } else {
          await AddApprovalToChangeRequest(changeSet, token);
        }
        res.json({ message: "Role change request approved" });
      } catch (error) {
        log(`Failed to approve role change request: ${error}`);
        res.status(500).json({ error: "Failed to approve role change request" });
      }
    }
  );

  // POST /api/admin/role-approvals/approve-with-id - Approve with explicit changeSetId (for multi-request flow)
  app.post(
    "/api/admin/role-approvals/approve-with-id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSetId, actionType, changeSetType, signedRequest } = req.body as {
          changeSetId: string;
          actionType: string;
          changeSetType: string;
          signedRequest: string;
        };

        if (!changeSetId || !actionType || !changeSetType || !signedRequest) {
          res.status(400).json({ error: "changeSetId, actionType, changeSetType, and signedRequest are required" });
          return;
        }

        const changeSet: ChangeSetRequest = {
          changeSetId,
          actionType,
          changeSetType,
        };

        await AddApprovalWithSignedRequest(changeSet, signedRequest, token);
        res.json({ message: "Role change request approved" });
      } catch (error) {
        log(`Failed to approve role change request with id: ${error}`);
        res.status(500).json({ error: "Failed to approve role change request" });
      }
    }
  );

  // POST /api/admin/role-approvals/reject - Reject a role change request
  app.post(
    "/api/admin/role-approvals/reject",
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
        res.json({ message: "Role change request rejected" });
      } catch (error) {
        log(`Failed to reject role change request: ${error}`);
        res.status(500).json({ error: "Failed to reject role change request" });
      }
    }
  );

  // POST /api/admin/role-approvals/commit - Commit an approved role change request
  app.post(
    "/api/admin/role-approvals/commit",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet } = req.body as { changeSet: ChangeSetRequest };

        log(`Committing role change set: ${JSON.stringify(changeSet)}`);

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        await CommitChangeRequest(changeSet, token);
        res.json({ message: "Role change request committed" });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log(`Failed to commit role change request: ${errorMsg}`);
        res.status(500).json({ error: `Failed to commit role change request: ${errorMsg}` });
      }
    }
  );

  // POST /api/admin/role-approvals/cancel - Cancel a role change request
  app.post(
    "/api/admin/role-approvals/cancel",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        const { changeSet } = req.body as { changeSet: ChangeSetRequest };

        log(`Cancelling role change set: ${JSON.stringify(changeSet)}`);

        if (!changeSet || !changeSet.changeSetId) {
          res.status(400).json({ error: "Change set information is required" });
          return;
        }

        await CancelChangeRequest(changeSet, token);
        res.json({ message: "Role change request cancelled" });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log(`Failed to cancel role change request: ${errorMsg}`);
        res.status(500).json({ error: `Failed to cancel role change request: ${errorMsg}` });
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

  // GET /api/admin/logs/file-operations - Get file operation logs
  app.get(
    "/api/admin/logs/file-operations",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const limit = parseInt(req.query.limit as string) || 100;
        const offset = parseInt(req.query.offset as string) || 0;
        const operations = await fileOperationStorage.getOperations(limit, offset);
        const total = await fileOperationStorage.getOperationCount();

        // Enrich operations with server names
        const serverIds = Array.from(new Set(operations.map((op) => op.serverId)));
        const servers = await storage.getServersByIds(serverIds);
        const serverMap = new Map(servers.map((s) => [s.id, s]));

        const enrichedOperations = operations.map((op) => ({
          ...op,
          serverName: serverMap.get(op.serverId)?.name || "Unknown",
          serverHost: serverMap.get(op.serverId)?.host || op.serverId,
        }));

        res.json({ operations: enrichedOperations, total });
      } catch (error) {
        log(`Failed to fetch file operation logs: ${error}`);
        res.status(500).json({ message: "Failed to fetch file operation logs" });
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

  // POST /api/forseti/compile - Compute contract ID (SHA512 hash of source)
  app.post(
    "/api/forseti/compile",
    authenticate,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { source, entryType } = req.body;
        const token = req.accessToken;

        if (!token) {
          res.status(401).json({ error: "Authentication required" });
          return;
        }

        if (!source || typeof source !== "string") {
          res.status(400).json({ error: "source is required and must be a string" });
          return;
        }

        logForseti("▶ Computing Contract ID", {
          entryType: entryType || "auto",
          sourceLen: source.length,
        });

        const startTime = Date.now();

        // Compute SHA512 hash of source code as contract ID
        const contractId = createHash("sha512")
          .update(source, "utf8")
          .digest("hex")
          .toUpperCase();

        const elapsed = Date.now() - startTime;

        logForseti("✓ Contract ID Computed", {
          contractId: contractId.substring(0, 16) + "...",
          elapsed: `${elapsed}ms`,
        });

        res.json({
          success: true,
          contractId,
        });
      } catch (error) {
        log(`Failed to compute contract ID: ${error}`);
        res.status(500).json({ error: "Failed to compute contract ID" });
      }
    }
  );

  // ============================================
  // License Management Routes
  // ============================================

  // GET /api/admin/license - Get current subscription and usage
  app.get(
    "/api/admin/license",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const token = req.accessToken!;
        // Get users from TideCloak and count total/enabled
        // Admins count toward the limit, they just can't be individually disabled
        const users = await tidecloakAdmin.getUsers(token);
        const userCounts = {
          total: users.length, // All users for usage display
          enabled: users.filter(u => u.enabled).length, // All enabled users (including admins) for over-limit check
        };

        // Always validate local subscription against Stripe to ensure consistency
        if (stripeLib.isStripeConfigured()) {
          try {
            const existing = await subscriptionStorage.getSubscription();

            // If we have a Stripe subscription ID, verify it's still valid
            if (existing?.stripeSubscriptionId) {
              try {
                const stripeSubscription = await stripeLib.getSubscription(existing.stripeSubscriptionId);
                const priceId = stripeSubscription.items.data[0]?.price?.id || null;
                const now = Math.floor(Date.now() / 1000);

                // Grant paid tier if:
                // - subscription is active/trialing/past_due, OR
                // - subscription is canceled but still within the paid period
                const isActiveSub = ["active", "trialing", "past_due"].includes(stripeSubscription.status);
                const isCanceledButValid = stripeSubscription.status === "canceled" &&
                  stripeSubscription.current_period_end &&
                  stripeSubscription.current_period_end > now;
                const shouldGrantPaidTier = isActiveSub || isCanceledButValid;
                const tier = shouldGrantPaidTier && priceId ? stripeLib.getTierFromPriceId(priceId) : "free";

                // Sync current state from Stripe
                await subscriptionStorage.upsertSubscription({
                  tier,
                  stripeCustomerId: typeof stripeSubscription.customer === "string"
                    ? stripeSubscription.customer
                    : stripeSubscription.customer?.id || existing.stripeCustomerId,
                  stripeSubscriptionId: shouldGrantPaidTier ? stripeSubscription.id : null as any,
                  stripePriceId: shouldGrantPaidTier ? priceId || undefined : null as any,
                  status: shouldGrantPaidTier ? stripeSubscription.status : "active",
                  currentPeriodEnd: shouldGrantPaidTier ? stripeSubscription.current_period_end : null as any,
                  cancelAtPeriodEnd: shouldGrantPaidTier ? stripeSubscription.cancel_at_period_end : false,
                });
              } catch (stripeError: any) {
                // Subscription not found in Stripe - revert to free
                if (stripeError?.statusCode === 404 || stripeError?.code === "resource_missing") {
                  log(`Stripe subscription ${existing.stripeSubscriptionId} not found - reverting to free tier`);
                  await subscriptionStorage.upsertSubscription({
                    tier: "free",
                    status: "active",
                    stripeSubscriptionId: null as any,
                    stripePriceId: null as any,
                    currentPeriodEnd: null as any,
                    cancelAtPeriodEnd: false,
                  });
                } else {
                  throw stripeError;
                }
              }
            } else if (existing?.stripeCustomerId) {
              // No subscription ID but have customer ID - check for subscriptions
              const stripeSubscription = await stripeLib.findBestSubscriptionForCustomer(existing.stripeCustomerId);
              if (stripeSubscription) {
                const priceId = stripeSubscription.items.data[0]?.price?.id || null;
                const now = Math.floor(Date.now() / 1000);
                const isActiveSub = ["active", "trialing", "past_due"].includes(stripeSubscription.status);
                const isCanceledButValid = stripeSubscription.status === "canceled" &&
                  stripeSubscription.current_period_end &&
                  stripeSubscription.current_period_end > now;
                const shouldGrantPaidTier = isActiveSub || isCanceledButValid;
                const tier = shouldGrantPaidTier && priceId ? stripeLib.getTierFromPriceId(priceId) : "free";

                await subscriptionStorage.upsertSubscription({
                  tier,
                  stripeCustomerId: existing.stripeCustomerId,
                  stripeSubscriptionId: shouldGrantPaidTier ? stripeSubscription.id : null as any,
                  stripePriceId: shouldGrantPaidTier ? priceId || undefined : null as any,
                  status: shouldGrantPaidTier ? stripeSubscription.status : "active",
                  currentPeriodEnd: shouldGrantPaidTier ? stripeSubscription.current_period_end : null as any,
                  cancelAtPeriodEnd: shouldGrantPaidTier ? stripeSubscription.cancel_at_period_end : false,
                });
              } else {
                // Customer exists but no active subscription - ensure free tier
                if (existing.tier !== "free") {
                  await subscriptionStorage.upsertSubscription({
                    tier: "free",
                    status: "active",
                    stripeSubscriptionId: null as any,
                    stripePriceId: null as any,
                    currentPeriodEnd: null as any,
                    cancelAtPeriodEnd: false,
                  });
                }
              }
            } else {
              // No Stripe IDs stored - try to discover by email
              const email = req.user?.email;
              if (email) {
                const customer = await stripeLib.findCustomerByEmail(email);
                if (customer?.id) {
                  const stripeSubscription = await stripeLib.findBestSubscriptionForCustomer(customer.id);
                  if (stripeSubscription) {
                    const priceId = stripeSubscription.items.data[0]?.price?.id || null;
                    const now = Math.floor(Date.now() / 1000);
                    const isActiveSub = ["active", "trialing", "past_due"].includes(stripeSubscription.status);
                    const isCanceledButValid = stripeSubscription.status === "canceled" &&
                      stripeSubscription.current_period_end &&
                      stripeSubscription.current_period_end > now;
                    const shouldGrantPaidTier = isActiveSub || isCanceledButValid;
                    const tier = shouldGrantPaidTier && priceId ? stripeLib.getTierFromPriceId(priceId) : "free";

                    await subscriptionStorage.upsertSubscription({
                      tier,
                      stripeCustomerId: customer.id,
                      stripeSubscriptionId: shouldGrantPaidTier ? stripeSubscription.id : null as any,
                      stripePriceId: shouldGrantPaidTier ? priceId || undefined : null as any,
                      status: shouldGrantPaidTier ? stripeSubscription.status : "active",
                      currentPeriodEnd: shouldGrantPaidTier ? stripeSubscription.current_period_end : null as any,
                      cancelAtPeriodEnd: shouldGrantPaidTier ? stripeSubscription.cancel_at_period_end : false,
                    });
                  }
                }
              }
            }
          } catch (error) {
            log(`Stripe subscription validation failed: ${error}`);
          }
        }

        const licenseInfo = await subscriptionStorage.getLicenseInfo(userCounts);

        // Cache the over-limit status for SSH access control
        const isUsersOverLimit = licenseInfo.overLimit?.users.isOverLimit || false;
        const isServersOverLimit = licenseInfo.overLimit?.servers.isOverLimit || false;
        await subscriptionStorage.updateOverLimitStatus(isUsersOverLimit, isServersOverLimit);

        res.json({ ...licenseInfo, stripeConfigured: stripeLib.isStripeConfigured() });
      } catch (error) {
        log(`Failed to fetch license info: ${error}`);
        res.status(500).json({ error: "Failed to fetch license info" });
      }
    }
  );

  // GET /api/admin/license/check/:resource - Check if can add user or server
  app.get(
    "/api/admin/license/check/:resource",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const { resource } = req.params;
        if (resource !== 'user' && resource !== 'server') {
          res.status(400).json({ error: "Resource must be 'user' or 'server'" });
          return;
        }

        let currentCount: number;
        if (resource === 'user') {
          const token = req.accessToken!;
          const users = await tidecloakAdmin.getUsers(token);
          currentCount = users.length;
        } else {
          currentCount = await subscriptionStorage.getServerCount();
        }

        const limitCheck = await subscriptionStorage.checkCanAdd(resource, currentCount);
        res.json(limitCheck);
      } catch (error) {
        log(`Failed to check license limit: ${error}`);
        res.status(500).json({ error: "Failed to check license limit" });
      }
    }
  );

  // POST /api/admin/license/checkout - Create Stripe checkout session
  app.post(
    "/api/admin/license/checkout",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        if (!stripeLib.isStripeConfigured()) {
          res.status(503).json({ error: "Stripe is not configured" });
          return;
        }

        const { priceId } = req.body;
        if (!priceId) {
          res.status(400).json({ error: "priceId is required" });
          return;
        }

        const subscription = await subscriptionStorage.getSubscription();
        const appUrl = process.env.APP_URL || `${req.protocol}://${req.get("host")}`;

        let session;
        try {
          session = await stripeLib.createCheckoutSession({
            customerId: subscription?.stripeCustomerId || undefined,
            customerEmail: subscription?.stripeCustomerId ? undefined : req.user?.email,
            priceId,
            successUrl: `${appUrl}/admin/license?success=true&session_id={CHECKOUT_SESSION_ID}`,
            cancelUrl: `${appUrl}/admin/license?canceled=true`,
          });
        } catch (checkoutError: any) {
          // If customer doesn't exist in Stripe, clear bad ID and retry with email
          if (checkoutError?.code === "resource_missing" || checkoutError?.message?.includes("No such customer")) {
            log(`Stripe customer ${subscription?.stripeCustomerId} not found - clearing and using email`);
            await subscriptionStorage.upsertSubscription({
              stripeCustomerId: null as any,
            });
            session = await stripeLib.createCheckoutSession({
              customerEmail: req.user?.email,
              priceId,
              successUrl: `${appUrl}/admin/license?success=true&session_id={CHECKOUT_SESSION_ID}`,
              cancelUrl: `${appUrl}/admin/license?canceled=true`,
            });
          } else {
            throw checkoutError;
          }
        }

        res.json({ url: session.url });
      } catch (error) {
        log(`Failed to create checkout session: ${error}`);
        res.status(500).json({ error: "Failed to create checkout session" });
      }
    }
  );

  // POST /api/admin/license/portal - Create Stripe billing portal session
  app.post(
    "/api/admin/license/portal",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        if (!stripeLib.isStripeConfigured()) {
          res.status(503).json({ error: "Stripe is not configured" });
          return;
        }

        const subscription = await subscriptionStorage.getSubscription();
        if (!subscription?.stripeCustomerId) {
          res.status(400).json({ error: "No active subscription found" });
          return;
        }

        const appUrl = process.env.APP_URL || `${req.protocol}://${req.get("host")}`;
        const portalUrl = await stripeLib.createBillingPortalSession(
          subscription.stripeCustomerId,
          `${appUrl}/admin/license`
        );

        res.json({ url: portalUrl });
      } catch (error) {
        log(`Failed to create portal session: ${error}`);
        res.status(500).json({ error: "Failed to create portal session" });
      }
    }
  );

  // GET /api/admin/license/billing - Get billing history
  app.get(
    "/api/admin/license/billing",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const history = await subscriptionStorage.getBillingHistory();
        res.json(history);
      } catch (error) {
        log(`Failed to fetch billing history: ${error}`);
        res.status(500).json({ error: "Failed to fetch billing history" });
      }
    }
  );

  // GET /api/admin/license/prices - Get available price IDs
  app.get(
    "/api/admin/license/prices",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const prices = stripeLib.getAvailablePrices();
        const tiers = {
          free: { ...subscriptionTiers.free, priceId: null },
          pro: { ...subscriptionTiers.pro, priceId: prices.pro || null },
          enterprise: { ...subscriptionTiers.enterprise, priceId: prices.enterprise || null },
        };
        res.json({ tiers, stripeConfigured: stripeLib.isStripeConfigured() });
      } catch (error) {
        log(`Failed to fetch prices: ${error}`);
        res.status(500).json({ error: "Failed to fetch prices" });
      }
    }
  );

  // POST /api/admin/license/sync - Sync subscription state from a Checkout session
  app.post(
    "/api/admin/license/sync",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        if (!stripeLib.isStripeConfigured()) {
          res.status(503).json({ error: "Stripe is not configured" });
          return;
        }

        const { sessionId } = req.body ?? {};
        if (!sessionId || typeof sessionId !== "string") {
          res.status(400).json({ error: "sessionId is required" });
          return;
        }

        const session = await stripeLib.getCheckoutSession(sessionId);

        if (session.mode !== "subscription" || !session.subscription) {
          res.status(400).json({ error: "Checkout session is not a subscription session" });
          return;
        }

        const subscriptionId =
          typeof session.subscription === "string" ? session.subscription : session.subscription.id;
        const customerId =
          typeof session.customer === "string" ? session.customer : session.customer?.id;

        const stripeSubscription = await stripeLib.getSubscription(subscriptionId);
        const priceId = stripeSubscription.items.data[0]?.price?.id || null;
        const tier = priceId ? stripeLib.getTierFromPriceId(priceId) : "free";

        await subscriptionStorage.upsertSubscription({
          tier,
          stripeCustomerId: customerId || undefined,
          stripeSubscriptionId: subscriptionId,
          stripePriceId: priceId || undefined,
          status: stripeSubscription.status,
          currentPeriodEnd: stripeSubscription.current_period_end,
          cancelAtPeriodEnd: stripeSubscription.cancel_at_period_end,
        });

        res.json({ success: true, tier });
      } catch (error) {
        log(`Failed to sync subscription from Stripe: ${error}`);
        res.status(500).json({ error: "Failed to sync subscription from Stripe" });
      }
    }
  );

  // POST /api/admin/license/sync-manual - Sync subscription by Stripe subscription ID or customer ID
  app.post(
    "/api/admin/license/sync-manual",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        if (!stripeLib.isStripeConfigured()) {
          res.status(503).json({ error: "Stripe is not configured" });
          return;
        }

        const { subscriptionId, customerId } = req.body ?? {};

        if (!subscriptionId && !customerId) {
          res.status(400).json({ error: "Either subscriptionId or customerId is required" });
          return;
        }

        let stripeSubscription;

        if (subscriptionId) {
          stripeSubscription = await stripeLib.getSubscription(subscriptionId);
        } else {
          stripeSubscription = await stripeLib.findBestSubscriptionForCustomer(customerId);
          if (!stripeSubscription) {
            res.status(404).json({ error: "No subscription found for this customer" });
            return;
          }
        }

        const priceId = stripeSubscription.items.data[0]?.price?.id || null;
        const tier = priceId ? stripeLib.getTierFromPriceId(priceId) : "free";
        const customerIdFromSub = typeof stripeSubscription.customer === "string"
          ? stripeSubscription.customer
          : stripeSubscription.customer?.id;

        await subscriptionStorage.upsertSubscription({
          tier,
          stripeCustomerId: customerIdFromSub || customerId || undefined,
          stripeSubscriptionId: stripeSubscription.id,
          stripePriceId: priceId || undefined,
          status: stripeSubscription.status,
          currentPeriodEnd: stripeSubscription.current_period_end,
          cancelAtPeriodEnd: stripeSubscription.cancel_at_period_end,
        });

        log(`Manual subscription sync: ${tier} tier, status: ${stripeSubscription.status}`);
        res.json({ success: true, tier, status: stripeSubscription.status });
      } catch (error) {
        log(`Failed to manually sync subscription: ${error}`);
        res.status(500).json({ error: "Failed to sync subscription from Stripe" });
      }
    }
  );

  // ============================================
  // Session Recording Endpoints (Admin only)
  // ============================================

  // GET /api/admin/recordings - List all recordings
  app.get(
    "/api/admin/recordings",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const limit = parseInt(req.query.limit as string) || 50;
        const offset = parseInt(req.query.offset as string) || 0;
        const serverId = req.query.serverId as string | undefined;
        const userId = req.query.userId as string | undefined;
        const search = req.query.search as string | undefined;

        let recordings;
        if (search) {
          recordings = await recordingStorage.searchRecordings(search, limit);
        } else if (serverId) {
          recordings = await recordingStorage.getRecordingsByServer(serverId, limit);
        } else if (userId) {
          recordings = await recordingStorage.getRecordingsByUser(userId, limit);
        } else {
          recordings = await recordingStorage.getRecordings(limit, offset);
        }

        // Get total count and storage usage
        const totalCount = await recordingStorage.getRecordingCount();
        const totalStorage = await recordingStorage.getTotalStorageBytes();

        res.json({
          recordings: recordings.map(r => ({
            id: r.id,
            sessionId: r.sessionId,
            serverId: r.serverId,
            serverName: r.serverName,
            userId: r.userId,
            userEmail: r.userEmail,
            sshUser: r.sshUser,
            startedAt: r.startedAt.toISOString(),
            endedAt: r.endedAt?.toISOString() || null,
            duration: r.duration,
            terminalWidth: r.terminalWidth,
            terminalHeight: r.terminalHeight,
            fileSize: r.fileSize,
            // Don't include full data in list response
          })),
          totalCount,
          totalStorage,
        });
      } catch (error) {
        log(`Failed to list recordings: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/recordings/:id - Get a specific recording with full data
  app.get(
    "/api/admin/recordings/:id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const recording = await recordingStorage.getRecording(req.params.id);
        if (!recording) {
          res.status(404).json({ error: "Recording not found" });
          return;
        }

        res.json({
          id: recording.id,
          sessionId: recording.sessionId,
          serverId: recording.serverId,
          serverName: recording.serverName,
          userId: recording.userId,
          userEmail: recording.userEmail,
          sshUser: recording.sshUser,
          startedAt: recording.startedAt.toISOString(),
          endedAt: recording.endedAt?.toISOString() || null,
          duration: recording.duration,
          terminalWidth: recording.terminalWidth,
          terminalHeight: recording.terminalHeight,
          fileSize: recording.fileSize,
          data: recording.data, // Full asciicast data for playback
        });
      } catch (error) {
        log(`Failed to get recording: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/recordings/:id/download - Download recording as asciicast file
  app.get(
    "/api/admin/recordings/:id/download",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const recording = await recordingStorage.getRecording(req.params.id);
        if (!recording) {
          res.status(404).json({ error: "Recording not found" });
          return;
        }

        const filename = `recording-${recording.id}-${recording.serverName}-${recording.startedAt.toISOString().split('T')[0]}.cast`;

        res.setHeader("Content-Type", "application/x-asciicast");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.send(recording.data);
      } catch (error) {
        log(`Failed to download recording: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/recordings/:id/search - Search within a recording's text content
  app.get(
    "/api/admin/recordings/:id/search",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const recording = await recordingStorage.getRecording(req.params.id);
        if (!recording) {
          res.status(404).json({ error: "Recording not found" });
          return;
        }

        const query = req.query.q as string;
        if (!query) {
          res.status(400).json({ error: "Query parameter 'q' is required" });
          return;
        }

        // Find all occurrences in text content
        const textContent = recording.textContent;
        const matches: { index: number; context: string }[] = [];
        let searchIndex = 0;

        while (true) {
          const index = textContent.toLowerCase().indexOf(query.toLowerCase(), searchIndex);
          if (index === -1) break;

          // Get surrounding context (50 chars before and after)
          const start = Math.max(0, index - 50);
          const end = Math.min(textContent.length, index + query.length + 50);
          const context = textContent.slice(start, end);

          matches.push({ index, context });
          searchIndex = index + 1;
        }

        res.json({ matches, total: matches.length });
      } catch (error) {
        log(`Failed to search recording: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // DELETE /api/admin/recordings/:id - Delete a recording
  app.delete(
    "/api/admin/recordings/:id",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const deleted = await recordingStorage.deleteRecording(req.params.id);
        if (!deleted) {
          res.status(404).json({ error: "Recording not found" });
          return;
        }

        log(`Recording ${req.params.id} deleted by ${req.user?.email}`);
        res.json({ success: true });
      } catch (error) {
        log(`Failed to delete recording: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  // GET /api/admin/recordings/stats - Get recording statistics
  app.get(
    "/api/admin/recordings/stats",
    authenticate,
    requireAdmin,
    async (req: AuthenticatedRequest, res) => {
      try {
        const totalCount = await recordingStorage.getRecordingCount();
        const totalStorage = await recordingStorage.getTotalStorageBytes();

        res.json({
          totalCount,
          totalStorage,
          totalStorageFormatted: formatBytes(totalStorage),
        });
      } catch (error) {
        log(`Failed to get recording stats: ${error}`);
        res.status(500).json({ error: "Internal Server Error" });
      }
    }
  );

  return httpServer;
}

// Helper function to format bytes
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}
