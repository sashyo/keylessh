import { Server as HTTPServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect, isIP } from "net";
import { lookup, Resolver } from "dns";
import { verifyTideCloakToken } from "./lib/auth/tideJWT";

/**
 * Embedded WebSocket-to-TCP bridge for local development.
 * Production deployments should use the external tcp-bridge service.
 */

// Public DNS servers for fallback resolution
const PUBLIC_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"];

/**
 * Fallback: resolve hostname using public DNS servers directly.
 * Uses Node's c-ares DNS client to bypass OS resolver.
 */
function resolveWithPublicDns(host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const resolver = new Resolver();
    resolver.setServers(PUBLIC_DNS_SERVERS);

    // Try IPv4 first
    resolver.resolve4(host, (err4, addresses4) => {
      if (!err4 && addresses4?.length) {
        resolve(addresses4[0]);
        return;
      }

      // Fall back to IPv6
      resolver.resolve6(host, (err6, addresses6) => {
        if (!err6 && addresses6?.length) {
          resolve(addresses6[0]);
          return;
        }

        reject(err4 || err6 || new Error(`DNS lookup failed for ${host}`));
      });
    });
  });
}

/**
 * Resolve hostname to IP address.
 * Tries OS resolver first (dns.lookup), falls back to public DNS servers.
 */
function resolveHost(host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (isIP(host)) {
      resolve(host);
      return;
    }

    // Try OS resolver first (handles /etc/hosts, WINS if configured, etc.)
    lookup(host, { family: 0 }, (err, address) => {
      if (!err && address) {
        resolve(address);
        return;
      }

      // Fallback to public DNS servers
      console.log(`[WSBridge] OS lookup failed for ${host}, trying public DNS`);
      resolveWithPublicDns(host)
        .then(resolve)
        .catch(() => reject(err)); // Return original error if both fail
    });
  });
}

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
