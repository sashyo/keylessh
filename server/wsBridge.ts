import { Server as HTTPServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect } from "net";
import { verifyTideCloakToken } from "./lib/auth/tideJWT";

/**
 * Embedded WebSocket-to-TCP bridge for local development.
 * Production deployments should use the external tcp-bridge service.
 */

let activeConnections = 0;

export function setupWSBridge(httpServer: HTTPServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/tcp" });

  wss.on("connection", async (ws: WebSocket, req) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");
    const host = url.searchParams.get("host");
    const port = parseInt(url.searchParams.get("port") || "22", 10);
    const sessionId = url.searchParams.get("sessionId");

    if (!token) {
      ws.close(4001, "Missing token");
      return;
    }

    if (!host || !sessionId) {
      ws.close(4000, "Missing required parameters");
      return;
    }

    // Validate JWT using existing auth infrastructure
    const payload = await verifyTideCloakToken(token, []);
    if (!payload) {
      ws.close(4002, "Invalid token");
      return;
    }

    const userId = payload.sub || "unknown";
    console.log(`[WSBridge] Connection: ${userId} -> ${host}:${port} (session: ${sessionId})`);
    activeConnections++;

    // Connect to SSH server
    const tcpSocket: Socket = connect({ host, port });
    let tcpConnected = false;

    tcpSocket.on("connect", () => {
      tcpConnected = true;
      console.log(`[WSBridge] TCP connected to ${host}:${port}`);
      ws.send(JSON.stringify({ type: "connected" }));
    });

    tcpSocket.on("data", (data: Buffer) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    tcpSocket.on("error", (err: Error) => {
      console.log(`[WSBridge] TCP error: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "error", message: err.message }));
        ws.close(4003, "TCP error");
      }
    });

    tcpSocket.on("close", () => {
      console.log("[WSBridge] TCP closed");
      if (ws.readyState === WebSocket.OPEN) {
        ws.close(1000, "TCP closed");
      }
    });

    ws.on("message", (data: Buffer) => {
      if (tcpConnected && !tcpSocket.destroyed) {
        tcpSocket.write(data);
      }
    });

    ws.on("close", () => {
      console.log("[WSBridge] WebSocket closed");
      activeConnections--;
      if (!tcpSocket.destroyed) {
        tcpSocket.destroy();
      }
    });

    ws.on("error", (err: Error) => {
      console.log(`[WSBridge] WebSocket error: ${err.message}`);
      if (!tcpSocket.destroyed) {
        tcpSocket.destroy();
      }
    });
  });

  console.log("[WSBridge] Local WebSocket bridge enabled at /ws/tcp");
}

export function getActiveConnections(): number {
  return activeConnections;
}
