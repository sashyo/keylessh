import { WebSocketServer, WebSocket } from "ws";
import { createConnection, Socket } from "net";
import type { Server, IncomingMessage } from "http";
import type { Duplex } from "stream";
import { createHmac } from "crypto";
import { log } from "./logger";
import { storage } from "./storage";
import { verifyTideCloakToken, type TokenPayload } from "./lib/auth/tideJWT";

// External bridge configuration
const BRIDGE_URL = process.env.BRIDGE_URL; // e.g., wss://keylessh-tcp-bridge.azurecontainerapps.io
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || "change-me-in-production";
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

  // Ensure DB session is marked completed to avoid stale "active" sessions.
  void storage.endSession(conn.sessionId);

  if (reason) {
    log(`Cleaned up session ${conn.sessionId}: ${reason}`);
  }
}

// Create signed session token for external bridge
function createSessionToken(
  host: string,
  port: number,
  serverId: string,
  userId: string
): string {
  const payload = {
    host,
    port,
    serverId,
    userId,
    exp: Date.now() + 60000, // 1 minute expiry
  };

  const payloadStr = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", BRIDGE_SECRET)
    .update(payloadStr)
    .digest("base64url");

  return `${payloadStr}.${signature}`;
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

      trackSessionSocket(sessionId, ws);
      log(`WebSocket TCP bridge: connecting to ${host}:${port} for user ${userId} session ${sessionId}`);

      if (USE_EXTERNAL_BRIDGE) {
        // === EXTERNAL BRIDGE MODE ===
        // Create session token and connect to external bridge
        const sessionToken = createSessionToken(host, port, serverId, userId);
        const bridgeWsUrl = `${BRIDGE_URL}?token=${sessionToken}`;

        log(`Connecting to external bridge: ${BRIDGE_URL}`);

        const remoteWs = new WebSocket(bridgeWsUrl);

        // Store connection info
        connections.set(ws, { ws, tcp: null, remoteWs, host, port, serverId, userId, sessionId });

        remoteWs.on("open", () => {
          log(`Connected to external bridge for ${host}:${port}`);
        });

        remoteWs.on("message", (data, isBinary) => {
          if (ws.readyState !== WebSocket.OPEN) return;

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
          if (conn?.remoteWs && conn.remoteWs.readyState === WebSocket.OPEN) {
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
        connections.set(ws, { ws, tcp, remoteWs: null, host, port, serverId, userId, sessionId });

        // Handle TCP data -> WebSocket
        tcp.on("data", (data: Buffer) => {
          if (ws.readyState === WebSocket.OPEN) {
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
          if (conn?.tcp && !conn.tcp.destroyed) {
            // Forward binary data to TCP
            if (Buffer.isBuffer(data)) {
              conn.tcp.write(data);
            } else if (typeof data === "string") {
              // Check if it's a control message (JSON)
              try {
                const msg = JSON.parse(data);
                // Handle control messages if needed
                if (msg.type === "ping") {
                  ws.send(JSON.stringify({ type: "pong" }));
                  return;
                }
              } catch {
                // Not JSON, treat as raw data
              }
              conn.tcp.write(data);
            }
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
