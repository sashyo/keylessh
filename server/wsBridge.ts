import { Server as HTTPServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect, isIP } from "net";
import { lookup } from "dns";
import { exec } from "child_process";
import { verifyTideCloakToken } from "./lib/auth/tideJWT";

/**
 * Embedded WebSocket-to-TCP bridge for local development.
 * Production deployments should use the external tcp-bridge service.
 */

/**
 * Fallback: resolve hostname using system commands.
 * Handles WINS/NetBIOS on Windows, and nsswitch sources on Linux.
 */
function resolveWithSystem(host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const isWindows = process.platform === "win32";
    // Windows ping triggers WINS/NetBIOS lookup
    // Linux getent queries nsswitch.conf (may include wins if configured)
    const cmd = isWindows ? `ping -n 1 -w 1000 ${host}` : `getent hosts ${host}`;

    exec(cmd, { timeout: 5000 }, (err, stdout) => {
      if (err) {
        reject(new Error(`System lookup failed: ${err.message}`));
        return;
      }

      let ip: string | null = null;
      if (isWindows) {
        // Parse Windows ping output: "Pinging hostname [192.168.1.1]" or "Reply from 192.168.1.1"
        const match = stdout.match(/\[(\d+\.\d+\.\d+\.\d+)\]/) ||
                      stdout.match(/Reply from (\d+\.\d+\.\d+\.\d+)/i);
        if (match) ip = match[1];
      } else {
        // Parse getent output: "192.168.1.1    hostname"
        const match = stdout.match(/^(\S+)/);
        if (match && isIP(match[1])) ip = match[1];
      }

      if (ip) {
        resolve(ip);
      } else {
        reject(new Error("Could not parse IP from system command"));
      }
    });
  });
}

/**
 * Resolve hostname to IP address.
 * Tries OS resolver first (dns.lookup), falls back to system commands for WINS/NetBIOS.
 */
function resolveHost(host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (isIP(host)) {
      resolve(host);
      return;
    }

    // Try OS resolver first (handles /etc/hosts, DNS, etc.)
    lookup(host, { family: 0 }, (err, address) => {
      if (!err && address) {
        resolve(address);
        return;
      }

      // Fallback to system command for WINS/NetBIOS
      console.log(`[WSBridge] dns.lookup failed for ${host}, trying system command`);
      resolveWithSystem(host)
        .then(resolve)
        .catch(() => reject(err)); // Return original DNS error if both fail
    });
  });
}

let activeConnections = 0;

export function setupWSBridge(httpServer: HTTPServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/tcp" });

  wss.on("connection", async (ws: WebSocket, req) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");
    // Decode host to handle URL-encoded IPv6 scoped addresses (e.g., %25 -> %)
    const hostParam = url.searchParams.get("host");
    const host = hostParam ? decodeURIComponent(hostParam) : null;
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

    // Resolve hostname first
    let resolvedHost: string;
    try {
      resolvedHost = await resolveHost(host);
      if (resolvedHost !== host) {
        console.log(`[WSBridge] DNS resolved ${host} -> ${resolvedHost}`);
      }
    } catch (err: any) {
      console.log(`[WSBridge] DNS resolution failed for ${host}: ${err.message}`);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "error", message: `DNS lookup failed for ${host}` }));
        ws.close(4003, "DNS error");
      }
      activeConnections--;
      return;
    }

    // Connect to SSH server using resolved IP
    const tcpSocket: Socket = connect({ host: resolvedHost, port });
    let tcpConnected = false;

    tcpSocket.on("connect", () => {
      tcpConnected = true;
      console.log(`[WSBridge] TCP connected to ${host}:${port} (${resolvedHost})`);
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
