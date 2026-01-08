import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect } from "net";
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

  // Validate JWT
  const payload = await verifyToken(token);
  if (!payload) {
    ws.close(4002, "Invalid token");
    return;
  }

  const userId = payload.sub || "unknown";
  console.log(`[Bridge] Connection: ${userId} -> ${host}:${port} (session: ${sessionId})`);
  activeConnections++;

  // Connect to SSH server
  const tcpSocket: Socket = connect({ host, port });
  let tcpConnected = false;

  tcpSocket.on("connect", () => {
    tcpConnected = true;
    console.log(`[Bridge] TCP connected to ${host}:${port}`);
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
