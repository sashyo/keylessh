import { WebSocketServer, WebSocket } from "ws";
import { createConnection, Socket } from "net";
import type { Server, IncomingMessage } from "http";
import type { Duplex } from "stream";
import { log } from "./logger";
import { storage, subscriptionStorage, recordingStorage, fileOperationStorage } from "./storage";
import { verifyTideCloakToken, type TokenPayload } from "./lib/auth/tideJWT";
import { getAllowedSshUsersFromToken } from "./lib/auth/sshUsers";
import { tidecloakAdmin } from "./auth";
import { subscriptionTiers, type SubscriptionTier } from "@shared/schema";

// External bridge configuration
const BRIDGE_URL = process.env.BRIDGE_URL; // e.g., wss://keylessh-tcp-bridge.azurecontainerapps.io
const USE_EXTERNAL_BRIDGE = !!BRIDGE_URL;

interface ConnectionInfo {
  ws: WebSocket;
  tcp: Socket | null;
  remoteWs: WebSocket | null;
  host: string;
  port: number;
  serverId: string;
  userId: string;
  sessionId: string;
  // Recording state
  recordingId: string | null;
  recordingStartTime: number | null;
}

// Asciicast v2 format helpers
// Header: {"version": 2, "width": 80, "height": 24, "timestamp": 1234567890}
// Events: [time, "o", "data"] for output, [time, "i", "data"] for input
function createAsciicastHeader(width: number, height: number, timestamp: number): string {
  return JSON.stringify({ version: 2, width, height, timestamp }) + "\n";
}

function createAsciicastEvent(relativeTime: number, eventType: "o" | "i", data: string): string {
  return JSON.stringify([relativeTime, eventType, data]) + "\n";
}

// Strip ANSI codes for searchable text content
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
}

const connections = new Map<WebSocket, ConnectionInfo>();
const socketsBySessionId = new Map<string, Set<WebSocket>>();

function trackSessionSocket(sessionId: string, ws: WebSocket) {
  const existing = socketsBySessionId.get(sessionId);
  if (existing) {
    existing.add(ws);
    return;
  }
  socketsBySessionId.set(sessionId, new Set([ws]));
}

function untrackSessionSocket(sessionId: string, ws: WebSocket) {
  const set = socketsBySessionId.get(sessionId);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) {
    socketsBySessionId.delete(sessionId);
  }
}

function cleanupConnection(ws: WebSocket, reason?: string) {
  const conn = connections.get(ws);
  if (!conn) return;

  try {
    conn.tcp?.destroy();
  } catch {
    // ignore
  }

  try {
    conn.remoteWs?.close();
  } catch {
    // ignore
  }

  untrackSessionSocket(conn.sessionId, ws);
  connections.delete(ws);

  // Mark DB session completed only when the last WebSocket for this sessionId closes.
  // This allows multiple browser tabs/windows to attach to the same session without
  // one tab closing and prematurely ending the session for the others.
  const remainingSockets = socketsBySessionId.get(conn.sessionId);
  if (!remainingSockets || remainingSockets.size === 0) {
    void storage.endSession(conn.sessionId);

    // Finalize recording if one was active
    if (conn.recordingId) {
      void recordingStorage.finalizeRecording(conn.recordingId).then(() => {
        log(`Finalized recording ${conn.recordingId} for session ${conn.sessionId}`);
      }).catch(err => {
        log(`Error finalizing recording: ${err.message}`);
      });
    }
  }

  if (reason) {
    log(`Cleaned up session ${conn.sessionId}: ${reason}`);
  }
}

type JWTPayload = TokenPayload;

// Extract token from request (Authorization header or query param)
function extractToken(req: IncomingMessage): string | null {
  // Try Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  // Try query parameter
  const url = new URL(req.url || "", `http://${req.headers.host}`);
  const token = url.searchParams.get("token");
  if (token) {
    return token;
  }

  return null;
}

async function verifyJwt(token: string): Promise<JWTPayload | null> {
  // Verifies signature + issuer + exp using TideCloak JWKS from config.
  return await verifyTideCloakToken(token, []);
}

export function setupWSBridge(httpServer: Server): WebSocketServer {
  const wss = new WebSocketServer({
    noServer: true,
  });

  // Handle upgrade requests only for /ws/tcp path
  httpServer.on("upgrade", (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    const url = new URL(request.url || "", `http://${request.headers.host}`);

    // Only handle /ws/tcp path, let other WebSocket connections (like Vite HMR) pass through
    if (url.pathname === "/ws/tcp") {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request);
      });
    }
    // Don't close the socket for other paths - let Vite or other handlers deal with them
  });

  wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
    void (async () => {
      const url = new URL(req.url || "", `http://${req.headers.host}`);
      const host = url.searchParams.get("host");
      const port = parseInt(url.searchParams.get("port") || "22", 10);
      const serverId = url.searchParams.get("serverId");
      const sessionId = url.searchParams.get("sessionId");

      // Validate required parameters
      if (!host || !serverId || !sessionId) {
        log("WebSocket connection rejected: missing host, serverId, or sessionId");
        ws.close(4000, "Missing required parameters: host, serverId, sessionId");
        return;
      }

      // Validate JWT token
      const token = extractToken(req);
      if (!token) {
        log("WebSocket connection rejected: no token");
        ws.close(4001, "Authentication required");
        return;
      }

      const payload = await verifyJwt(token);
      if (!payload) {
        log("WebSocket connection rejected: invalid or expired token");
        ws.close(4001, "Invalid or expired token");
        return;
      }

      const userId = payload.sub || "";
      if (!userId) {
        log("WebSocket connection rejected: missing sub");
        ws.close(4001, "Invalid token");
        return;
      }

      // Validate session record belongs to this user/server and is active
      const session = await storage.getSession(sessionId);
      if (!session) {
        log(`WebSocket connection rejected: unknown session ${sessionId}`);
        ws.close(4004, "Unknown session");
        return;
      }
      if (session.status !== "active") {
        log(`WebSocket connection rejected: session not active ${sessionId}`);
        ws.close(4004, "Session is not active");
        return;
      }
      if (session.userId !== userId || session.serverId !== serverId) {
        log(`WebSocket connection rejected: session mismatch ${sessionId}`);
        ws.close(4003, "Session does not match user/server");
        return;
      }

      // Enforce SSH username allowlist from JWT roles/claims (all users)
      const allowed = getAllowedSshUsersFromToken(payload);
      if (!allowed.includes(session.sshUser)) {
        log(`WebSocket connection rejected: ssh user not allowed '${session.sshUser}' for user ${userId}`);
        ws.close(4003, `Not allowed to SSH as '${session.sshUser}'`);
        return;
      }

      // Prevent connecting to arbitrary hosts: enforce serverId->host/port mapping
      const configuredServer = await storage.getServer(serverId);
      if (!configuredServer) {
        log(`WebSocket connection rejected: unknown server ${serverId}`);
        ws.close(4004, "Unknown server");
        return;
      }
      if (!configuredServer.enabled) {
        log(`WebSocket connection rejected: server disabled ${serverId}`);
        ws.close(4003, "Server is disabled");
        return;
      }
      if (configuredServer.host !== host || (configuredServer.port ?? 22) !== port) {
        log(`WebSocket connection rejected: host/port mismatch for server ${serverId}`);
        ws.close(4003, "Invalid server connection details");
        return;
      }

      // Refresh and check if SSH access is blocked due to over-limit
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
        log(`WebSocket connection rejected: SSH access blocked - ${sshStatus.reason}`);
        ws.close(4003, "SSH access is currently disabled");
        return;
      }

      // Check if recording is enabled for this server/user combination
      let recordingId: string | null = null;
      let recordingStartTime: number | null = null;

      if (configuredServer.recordingEnabled) {
        const recordedUsers = configuredServer.recordedUsers || [];
        // Empty recordedUsers array means record ALL users on this server
        const shouldRecord = recordedUsers.length === 0 || recordedUsers.includes(session.sshUser);

        if (shouldRecord) {
          try {
            const userEmail = session.userEmail || payload.email || "";
            const recording = await recordingStorage.createRecording({
              sessionId,
              serverId,
              serverName: configuredServer.name,
              userId,
              userEmail,
              sshUser: session.sshUser,
              terminalWidth: 80,  // Default, will be updated if client sends resize
              terminalHeight: 24,
            });
            recordingId = recording.id;
            recordingStartTime = Date.now();

            // Write asciicast header
            const header = createAsciicastHeader(80, 24, Math.floor(recordingStartTime / 1000));
            await recordingStorage.appendData(recordingId, header);

            // Link recording to session
            await storage.updateSession(sessionId, { recordingId: recording.id });

            log(`Started recording ${recordingId} for session ${sessionId} (server: ${configuredServer.name}, sshUser: ${session.sshUser})`);
          } catch (err) {
            log(`Failed to start recording for session ${sessionId}: ${(err as Error).message}`);
            // Continue without recording - don't block the session
          }
        }
      }

      trackSessionSocket(sessionId, ws);
      log(`WebSocket TCP bridge: connecting to ${host}:${port} for user ${userId} session ${sessionId}`);

      if (USE_EXTERNAL_BRIDGE) {
        // === EXTERNAL BRIDGE MODE ===
        // Forward original JWT to external bridge (bridge verifies against JWKS)
        const bridgeParams = new URLSearchParams({
          token: token,
          host: host,
          port: port.toString(),
          serverId: serverId,
        });
        const bridgeWsUrl = `${BRIDGE_URL}?${bridgeParams.toString()}`;

        log(`Connecting to external bridge: ${BRIDGE_URL}`);

        const remoteWs = new WebSocket(bridgeWsUrl);

        // Store connection info
        connections.set(ws, { ws, tcp: null, remoteWs, host, port, serverId, userId, sessionId, recordingId, recordingStartTime });

        remoteWs.on("open", () => {
          log(`Connected to external bridge for ${host}:${port}`);
        });

        remoteWs.on("message", (data, isBinary) => {
          if (ws.readyState !== WebSocket.OPEN) return;

          // Note: Recording is now done via browser-side events (decrypted data)
          // The data here is encrypted SSH protocol, not suitable for recording

          // Preserve text frames as text for the browser. If we forward a Buffer that
          // represents a text frame, the browser receives it as binary and won't
          // parse our JSON control messages (e.g. {type:"connected"}).
          if (isBinary) {
            ws.send(data);
            return;
          }

          if (typeof data === "string") {
            ws.send(data);
            return;
          }

          ws.send(data.toString("utf-8"));
        });

        remoteWs.on("error", (err: Error) => {
          log(`External bridge error: ${err.message}`);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "error", message: err.message }));
            ws.close(4002, `Bridge error: ${err.message}`);
          }
        });

        remoteWs.on("close", () => {
          log(`External bridge closed for ${host}:${port}`);
          if (ws.readyState === WebSocket.OPEN) {
            ws.close(1000, "Bridge connection closed");
          }
          cleanupConnection(ws, "remote bridge closed");
        });

        // Forward client messages to bridge
        ws.on("message", (data: Buffer | string) => {
          const conn = connections.get(ws);
          if (!conn) return;

          // Check if it's a JSON control message (text frame starting with '{')
          // WS library sends text frames as Buffer in Node.js, so check first byte
          const firstByte = Buffer.isBuffer(data) ? data[0] : (data.length > 0 ? data.charCodeAt(0) : 0);
          if (firstByte === 0x7B) { // '{' character
            try {
              const dataStr = Buffer.isBuffer(data) ? data.toString("utf-8") : data;
              const msg = JSON.parse(dataStr);
              // Handle recording events from browser (decrypted terminal I/O)
              if (msg.type === "record" && conn.recordingId) {
                void (async () => {
                  try {
                    const event = createAsciicastEvent(msg.time, msg.eventType, msg.data);
                    await recordingStorage.appendData(conn.recordingId!, event);
                    if (msg.eventType === "o") {
                      await recordingStorage.appendTextContent(conn.recordingId!, stripAnsi(msg.data));
                    }
                  } catch {
                    // Ignore recording errors
                  }
                })();
                return; // Don't forward recording messages to bridge
              }
              // Handle file operation events from browser
              if (msg.type === "file_op") {
                void (async () => {
                  try {
                    const session = await storage.getSession(conn.sessionId);
                    await fileOperationStorage.logOperation({
                      sessionId: conn.sessionId,
                      serverId: conn.serverId,
                      userId: conn.userId,
                      userEmail: session?.userEmail || undefined,
                      sshUser: session?.sshUser || "unknown",
                      operation: msg.operation,
                      path: msg.path,
                      targetPath: msg.targetPath,
                      fileSize: msg.fileSize,
                      mode: msg.mode,
                      status: msg.status,
                      errorMessage: msg.errorMessage,
                    });
                    log(`File op: ${msg.operation} ${msg.path} (${msg.mode}, ${msg.status}) - session ${conn.sessionId}`);
                  } catch (err) {
                    log(`Error logging file op: ${(err as Error).message}`);
                  }
                })();
                return; // Don't forward file op messages to bridge
              }
              // Other JSON control messages - don't forward to bridge
              return;
            } catch {
              // Not valid JSON despite starting with '{', forward to bridge
            }
          }

          if (conn.remoteWs && conn.remoteWs.readyState === WebSocket.OPEN) {
            conn.remoteWs.send(data);
          }
        });

        ws.on("close", () => {
          cleanupConnection(ws, "websocket closed");
          log(`WebSocket closed for ${host}:${port}`);
        });

        ws.on("error", (err: Error) => {
          log(`WebSocket error for ${host}:${port}: ${err.message}`);
          cleanupConnection(ws, `websocket error: ${err.message}`);
        });
      } else {
        // === LOCAL BRIDGE MODE ===
        // Create TCP connection to target
        const tcp = createConnection({ host, port }, () => {
          log(`TCP connected to ${host}:${port}`);
          // Notify client that TCP connection is established
          ws.send(JSON.stringify({ type: "connected" }));
        });

        // Store connection info
        connections.set(ws, { ws, tcp, remoteWs: null, host, port, serverId, userId, sessionId, recordingId, recordingStartTime });

        // Handle TCP data -> WebSocket
        tcp.on("data", (data: Buffer) => {
          if (ws.readyState === WebSocket.OPEN) {
            // Note: Recording is now done via browser-side events (decrypted data)
            // The data here is encrypted SSH protocol, not suitable for recording
            ws.send(data);
          }
        });

        // Handle TCP errors
        tcp.on("error", (err: Error) => {
          log(`TCP error for ${host}:${port}: ${err.message}`);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "error", message: err.message }));
            ws.close(4002, `TCP error: ${err.message}`);
          }
        });

        // Handle TCP close
        tcp.on("close", () => {
          log(`TCP closed for ${host}:${port}`);
          if (ws.readyState === WebSocket.OPEN) {
            ws.close(1000, "TCP connection closed");
          }
          cleanupConnection(ws, "tcp closed");
        });

        // Handle WebSocket messages -> TCP
        ws.on("message", (data: Buffer | string) => {
          const conn = connections.get(ws);
          if (!conn) return;

          // Check if it's a JSON control message (text frame starting with '{')
          // WS library sends text frames as Buffer in Node.js, so check first byte
          const firstByte = Buffer.isBuffer(data) ? data[0] : (data.length > 0 ? data.charCodeAt(0) : 0);
          if (firstByte === 0x7B) { // '{' character
            try {
              const dataStr = Buffer.isBuffer(data) ? data.toString("utf-8") : data;
              const msg = JSON.parse(dataStr);
              // Handle ping/pong
              if (msg.type === "ping") {
                ws.send(JSON.stringify({ type: "pong" }));
                return;
              }
              // Handle recording events from browser (decrypted terminal I/O)
              if (msg.type === "record" && conn.recordingId) {
                void (async () => {
                  try {
                    const event = createAsciicastEvent(msg.time, msg.eventType, msg.data);
                    await recordingStorage.appendData(conn.recordingId!, event);
                    if (msg.eventType === "o") {
                      await recordingStorage.appendTextContent(conn.recordingId!, stripAnsi(msg.data));
                    }
                  } catch {
                    // Ignore recording errors
                  }
                })();
                return; // Don't forward recording messages to TCP
              }
              // Handle file operation events from browser
              if (msg.type === "file_op") {
                void (async () => {
                  try {
                    const session = await storage.getSession(conn.sessionId);
                    await fileOperationStorage.logOperation({
                      sessionId: conn.sessionId,
                      serverId: conn.serverId,
                      userId: conn.userId,
                      userEmail: session?.userEmail || undefined,
                      sshUser: session?.sshUser || "unknown",
                      operation: msg.operation,
                      path: msg.path,
                      targetPath: msg.targetPath,
                      fileSize: msg.fileSize,
                      mode: msg.mode,
                      status: msg.status,
                      errorMessage: msg.errorMessage,
                    });
                    log(`File op: ${msg.operation} ${msg.path} (${msg.mode}, ${msg.status}) - session ${conn.sessionId}`);
                  } catch (err) {
                    log(`Error logging file op: ${(err as Error).message}`);
                  }
                })();
                return; // Don't forward file op messages to TCP
              }
              // Unknown JSON message - don't forward to TCP (it would corrupt SSH protocol)
              return;
            } catch {
              // Not valid JSON despite starting with '{', forward to TCP
            }
          }

          // Forward binary/raw data to TCP
          if (conn.tcp && !conn.tcp.destroyed) {
            conn.tcp.write(Buffer.isBuffer(data) ? data : Buffer.from(data));
          }
        });

        // Handle WebSocket close
        ws.on("close", () => {
          cleanupConnection(ws, "websocket closed");
          log(`WebSocket closed for ${host}:${port}`);
        });

        // Handle WebSocket errors
        ws.on("error", (err: Error) => {
          log(`WebSocket error for ${host}:${port}: ${err.message}`);
          cleanupConnection(ws, `websocket error: ${err.message}`);
        });
      }
    })();
  });

  if (USE_EXTERNAL_BRIDGE) {
    log(`WebSocket TCP bridge initialized on /ws/tcp (external: ${BRIDGE_URL})`);
  } else {
    log("WebSocket TCP bridge initialized on /ws/tcp (local mode)");
  }
  return wss;
}

export function terminateSession(sessionId: string, reason = "Terminated by admin"): boolean {
  const sockets = socketsBySessionId.get(sessionId);
  if (!sockets || sockets.size === 0) {
    return false;
  }

  for (const ws of Array.from(sockets)) {
    const conn = connections.get(ws);
    try {
      conn?.tcp?.destroy();
    } catch {
      // ignore
    }
    try {
      conn?.remoteWs?.close();
    } catch {
      // ignore
    }

    if (ws.readyState === WebSocket.OPEN) {
      ws.close(4005, reason);
    } else {
      try {
        ws.terminate();
      } catch {
        // ignore
      }
    }

    cleanupConnection(ws, "terminated by admin");
  }

  return true;
}
