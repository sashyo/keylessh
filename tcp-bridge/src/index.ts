import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect, isIP } from "net";
import { exec } from "child_process";
import { jwtVerify, createLocalJWKSet, JWTPayload } from "jose";
import { readFileSync } from "fs";
import { join } from "path";

/**
 * TCP Bridge - Stateless WebSocket to TCP bridge for SSH connections.
 *
 * - Validates JWT using embedded JWKS (no external API calls)
 * - Receives host/port from browser (browser got them from main server session creation)
 * - Forwards WebSocket data to TCP and vice versa
 * - Scales horizontally (Azure Container Apps)
 *
 * Environment variables:
 * - PORT: Port to listen on (default: 8080)
 * - TIDECLOAK_CONFIG_PATH: Path to tidecloak.json with JWKS
 * - TIDECLOAK_CONFIG_B64: Base64-encoded config (alternative for Azure)
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

    exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
      if (err) {
        // If IPv4 failed, try IPv6
        if (forceIPv4 && (isWindows || wsl)) {
          console.log(`[Bridge] IPv4 lookup failed for ${host}, trying IPv6...`);
          resolveWithSystem(host, false).then(resolve).catch(reject);
          return;
        }
        reject(new Error(`System lookup failed: ${err.message}`));
        return;
      }

      console.log(`[Bridge] System command output: ${stdout.substring(0, 200)}`);

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
            console.log(`[Bridge] Mapped Windows scope ID to WSL: ${ip}`);
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

const PORT = parseInt(process.env.PORT || "8081");
const CONFIG_B64 = process.env.TIDECLOAK_CONFIG_B64;

// Config path priority: env var > ./data/tidecloak.json > ../data/tidecloak.json
function resolveConfigPath(): string {
  if (process.env.TIDECLOAK_CONFIG_PATH) {
    return process.env.TIDECLOAK_CONFIG_PATH;
  }
  // Check local data/ first (running from repo root)
  const localPath = join(process.cwd(), "data", "tidecloak.json");
  // Fall back to parent data/ (running from tcp-bridge/)
  const parentPath = join(process.cwd(), "..", "data", "tidecloak.json");

  try {
    readFileSync(localPath);
    return localPath;
  } catch {
    return parentPath;
  }
}

interface TidecloakConfig {
  realm: string;
  "auth-server-url": string;
  resource: string;
  jwk: {
    keys: Array<{
      kid: string;
      kty: string;
      alg: string;
      use: string;
      crv: string;
      x: string;
    }>;
  };
}

let tcConfig: TidecloakConfig | null = null;
let JWKS: ReturnType<typeof createLocalJWKSet> | null = null;

function loadConfig(): boolean {
  try {
    let configData: string;

    if (CONFIG_B64) {
      configData = Buffer.from(CONFIG_B64, "base64").toString("utf-8");
      console.log("[Bridge] Loading JWKS from TIDECLOAK_CONFIG_B64");
    } else {
      const configPath = resolveConfigPath();
      configData = readFileSync(configPath, "utf-8");
      console.log(`[Bridge] Loading JWKS from ${configPath}`);
    }

    tcConfig = JSON.parse(configData) as TidecloakConfig;

    if (!tcConfig.jwk?.keys?.length) {
      console.error("[Bridge] No JWKS keys found in config");
      return false;
    }

    JWKS = createLocalJWKSet(tcConfig.jwk);
    console.log("[Bridge] JWKS loaded successfully");
    return true;
  } catch (err) {
    console.error("[Bridge] Failed to load config:", err);
    return false;
  }
}

async function verifyToken(token: string): Promise<JWTPayload | null> {
  if (!JWKS || !tcConfig) return null;

  try {
    const issuer = tcConfig["auth-server-url"].endsWith("/")
      ? `${tcConfig["auth-server-url"]}realms/${tcConfig.realm}`
      : `${tcConfig["auth-server-url"]}/realms/${tcConfig.realm}`;

    const { payload } = await jwtVerify(token, JWKS, { issuer });

    if (payload.azp !== tcConfig.resource) {
      console.log(`[Bridge] AZP mismatch: expected ${tcConfig.resource}, got ${payload.azp}`);
      return null;
    }

    return payload;
  } catch (err) {
    console.log("[Bridge] JWT verification failed:", err);
    return null;
  }
}

// Load config on startup
if (!loadConfig()) {
  console.error("[Bridge] Failed to load TideCloak config. Exiting.");
  process.exit(1);
}

const server = createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", connections: activeConnections }));
    return;
  }
  res.writeHead(404);
  res.end("Not found");
});

let activeConnections = 0;

const wss = new WebSocketServer({ server });

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

  // Validate JWT
  const payload = await verifyToken(token);
  if (!payload) {
    ws.close(4002, "Invalid token");
    return;
  }

  const userId = payload.sub || "unknown";
  console.log(`[Bridge] Connection: ${userId} -> ${host}:${port} (session: ${sessionId})`);
  activeConnections++;

  // Resolve hostname first (handles WINS/NetBIOS via system command fallback)
  let resolvedHost: string;
  try {
    resolvedHost = await resolveHost(host);
    if (resolvedHost !== host) {
      console.log(`[Bridge] Resolved ${host} -> ${resolvedHost}`);
    }
  } catch (err: any) {
    console.log(`[Bridge] Resolution failed for ${host}: ${err?.message}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "error", message: `Cannot resolve ${host}` }));
      ws.close(4003, "Resolution error");
    }
    activeConnections--;
    return;
  }

  // Connect to SSH server using resolved IP
  console.log(`[Bridge] Attempting TCP connect to ${resolvedHost}:${port}`);
  let tcpSocket: Socket;
  try {
    tcpSocket = connect({ host: resolvedHost, port });
  } catch (err: any) {
    console.log(`[Bridge] TCP connect threw: ${err.message}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "error", message: err.message }));
      ws.close(4003, "TCP error");
    }
    activeConnections--;
    return;
  }
  let tcpConnected = false;

  tcpSocket.on("connect", () => {
    tcpConnected = true;
    console.log(`[Bridge] TCP connected to ${host}:${port} (${resolvedHost})`);
    ws.send(JSON.stringify({ type: "connected" }));
  });

  tcpSocket.on("data", (data: Buffer) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });

  tcpSocket.on("error", (err: Error) => {
    console.log(`[Bridge] TCP error: ${err.message}`);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "error", message: err.message }));
      ws.close(4003, "TCP error");
    }
  });

  tcpSocket.on("close", () => {
    console.log("[Bridge] TCP closed");
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
    console.log(`[Bridge] WebSocket closed (tcpConnected: ${tcpConnected})`);
    activeConnections--;
    if (!tcpSocket.destroyed) {
      console.log("[Bridge] Destroying TCP socket due to WebSocket close");
      tcpSocket.destroy();
    }
  });

  ws.on("error", (err: Error) => {
    console.log(`[Bridge] WebSocket error: ${err.message}`);
    if (!tcpSocket.destroyed) {
      tcpSocket.destroy();
    }
  });
});

server.listen(PORT, () => {
  console.log(`[Bridge] TCP Bridge listening on port ${PORT}`);
  console.log(`[Bridge] Health check: http://localhost:${PORT}/health`);
});

process.on("SIGTERM", () => {
  console.log("[Bridge] Shutting down...");
  wss.clients.forEach((client) => client.close(1001, "Server shutting down"));
  server.close(() => {
    console.log("[Bridge] Shutdown complete");
    process.exit(0);
  });
});
