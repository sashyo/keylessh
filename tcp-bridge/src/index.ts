import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect, isIP } from "net";
import { lookup } from "dns";
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
      console.log(`[Bridge] dns.lookup failed for ${host}, trying system command`);
      resolveWithSystem(host)
        .then(resolve)
        .catch(() => reject(err)); // Return original DNS error if both fail
    });
  });
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

  // Validate JWT
  const payload = await verifyToken(token);
  if (!payload) {
    ws.close(4002, "Invalid token");
    return;
  }

  const userId = payload.sub || "unknown";
  console.log(`[Bridge] Connection: ${userId} -> ${host}:${port} (session: ${sessionId})`);
  activeConnections++;

  // Resolve hostname first
  let resolvedHost: string;
  try {
    resolvedHost = await resolveHost(host);
    if (resolvedHost !== host) {
      console.log(`[Bridge] DNS resolved ${host} -> ${resolvedHost}`);
    }
  } catch (err: any) {
    console.log(`[Bridge] DNS resolution failed for ${host}: ${err.message}`);
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
    console.log("[Bridge] WebSocket closed");
    activeConnections--;
    if (!tcpSocket.destroyed) {
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
