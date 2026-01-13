import { Server as HTTPServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect, isIP } from "net";
import { exec } from "child_process";
import { readFileSync } from "fs";
import { verifyTideCloakToken } from "./lib/auth/tideJWT";

/**
 * Embedded WebSocket-to-TCP bridge for local development.
 * Production deployments should use the external tcp-bridge service.
 */

/**
 * Detect if running in WSL (Windows Subsystem for Linux)
 */
function isWSL(): boolean {
  try {
    const release = readFileSync("/proc/version", "utf-8");
    return release.toLowerCase().includes("microsoft");
  } catch {
    return false;
  }
}

/**
 * Resolve hostname using system commands.
 * Handles WINS/NetBIOS on Windows, WSL, and Linux.
 * Tries IPv4 first, falls back to IPv6 if needed.
 */
function resolveWithSystem(host: string, forceIPv4 = true): Promise<string> {
  return new Promise((resolve, reject) => {
    const isWindows = process.platform === "win32";
    const wsl = isWSL();

    // Windows: ping triggers WINS/NetBIOS lookup
    // WSL: use Windows cmd.exe to resolve via Windows networking
    // Linux: getent queries nsswitch.conf (may include wins if configured)
    let cmd: string;
    const ipv4Flag = forceIPv4 ? "-4 " : "";
    if (isWindows) {
      cmd = `ping ${ipv4Flag}-n 1 -w 1000 ${host}`;
    } else if (wsl) {
      // Use Windows ping via cmd.exe for WINS resolution
      cmd = `cmd.exe /c ping ${ipv4Flag}-n 1 -w 1000 ${host}`;
    } else {
      cmd = `getent hosts ${host}`;
    }

    exec(cmd, { timeout: 5000 }, (err, stdout) => {
      if (err) {
        // If IPv4 failed, try IPv6
        if (forceIPv4 && (isWindows || wsl)) {
          console.log(`[WSBridge] IPv4 lookup failed for ${host}, trying IPv6...`);
          resolveWithSystem(host, false).then(resolve).catch(reject);
          return;
        }
        reject(new Error(`System lookup failed: ${err.message}`));
        return;
      }

      console.log(`[WSBridge] System command output: ${stdout.substring(0, 200)}`);

      let ip: string | null = null;
      if (isWindows || wsl) {
        // Parse Windows ping output: "Pinging hostname [ip]" or "Reply from ip"
        // Handles both IPv4 (192.168.1.1) and IPv6 (fe80::1%5)
        const bracketMatch = stdout.match(/\[([^\]]+)\]/);
        const replyMatch = stdout.match(/Reply from ([^\s:]+)/i);
        if (bracketMatch) ip = bracketMatch[1];
        else if (replyMatch) ip = replyMatch[1];
      } else {
        // Parse getent output: "192.168.1.1    hostname"
        const match = stdout.match(/^(\S+)/);
        if (match && isIP(match[1])) ip = match[1];
      }

      if (ip) {
        // For WSL: Windows scope IDs (like %5) don't work in Linux
        // Replace with eth0 which is the WSL virtual network interface
        if (wsl && ip.includes("%")) {
          const baseIp = ip.split("%")[0];
          // Link-local IPv6 (fe80::) needs scope ID for routing
          if (baseIp.toLowerCase().startsWith("fe80:")) {
            ip = `${baseIp}%eth0`;
            console.log(`[WSBridge] Mapped Windows scope ID to WSL: ${ip}`);
          } else {
            ip = baseIp;
          }
        }
        resolve(ip);
      } else {
        reject(new Error("Could not parse IP from system command"));
      }
    });
  });
}

/**
 * Check if string is an IPv6 address (with optional scope ID like %eth1)
 */
function isIPv6WithScope(host: string): boolean {
  // IPv6 with scope ID: fe80::1%eth1 or fe80::1%5
  if (host.includes("%")) {
    const base = host.split("%")[0];
    return isIP(base) === 6;
  }
  return false;
}

/**
 * Resolve hostname to IP address using system commands.
 * Uses ping for WINS/NetBIOS resolution.
 */
function resolveHost(host: string): Promise<string> {
  // Already an IP address (v4 or v6)
  if (isIP(host)) {
    return Promise.resolve(host);
  }
  // IPv6 with scope ID (isIP doesn't recognize these)
  if (isIPv6WithScope(host)) {
    return Promise.resolve(host);
  }
  return resolveWithSystem(host);
}

let activeConnections = 0;

export function setupWSBridge(httpServer: HTTPServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/tcp" });

  wss.on("connection", async (ws: WebSocket, req) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");
    // searchParams.get() already decodes URL-encoded values (e.g., %25 -> %)
    // Strip brackets from IPv6 addresses (URL notation uses [::1] but connect() wants just ::1)
    const hostParam = url.searchParams.get("host");
    const host = hostParam?.replace(/^\[|\]$/g, "") || null;
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
