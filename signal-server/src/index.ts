import { createServer as createHttpServer } from "http";
import { createServer as createHttpsServer } from "https";
import { WebSocketServer, WebSocket } from "ws";
import { jwtVerify, createLocalJWKSet, JWTPayload } from "jose";
import { readFileSync, existsSync } from "fs";
import { join, extname } from "path";
import { fileURLToPath } from "url";
import { timingSafeEqual, createHmac } from "crypto";
import { createRegistry, type ConnectionType, type WafMetadata } from "./signaling/registry.js";
import { pairClient, pairClientWithWaf, forwardCandidate, forwardSdp } from "./signaling/pairing.js";
import { createHttpRelay, handleHttpResponse, rejectPendingForWaf } from "./relay/http-relay.js";

/**
 * Signal Server — P2P signaling + HTTP relay + portal
 *
 * Handles WAF registration, client pairing, SDP/ICE exchange,
 * TURN credential generation, HTTP relay tunneling, and WAF selection portal.
 *
 * Environment variables:
 * - PORT: Port to listen on (default: 9090)
 * - client_adapter: JSON string of tidecloak.json config (highest priority)
 * - TIDECLOAK_CONFIG_B64: Base64-encoded config
 * - API_SECRET: Shared secret for WAF registration authentication
 * - ICE_SERVERS: Comma-separated STUN server URLs (e.g. "stun:relay.example.com:3478")
 * - TURN_SERVER: TURN server URL for WebRTC relay fallback (e.g. "turn:relay.example.com:3478")
 * - TURN_SECRET: Shared secret for TURN REST API ephemeral credentials (HMAC-SHA256)
 * - TLS_CERT_PATH: Path to TLS certificate file (enables HTTPS/WSS)
 * - TLS_KEY_PATH: Path to TLS private key file
 */

const PORT = parseInt(process.env.PORT || "9090");
const CLIENT_ADAPTER = process.env.client_adapter;
const CONFIG_B64 = process.env.TIDECLOAK_CONFIG_B64;
const API_SECRET = process.env.API_SECRET || "";
const ICE_SERVERS = process.env.ICE_SERVERS ? process.env.ICE_SERVERS.split(",") : [];
const TURN_SERVER = process.env.TURN_SERVER || "";
const TURN_SECRET = process.env.TURN_SECRET || "";
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || "";
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || "";
const useTls = !!(TLS_CERT_PATH && TLS_KEY_PATH);

// ── TideCloak config + JWKS ──────────────────────────────────────

function resolveConfigPath(): string | null {
  const candidates = [
    join(process.cwd(), "data", "tidecloak.json"),
    join(process.cwd(), "..", "data", "tidecloak.json"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
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

    if (CLIENT_ADAPTER) {
      configData = CLIENT_ADAPTER;
      console.log("[Signal] Loading config from client_adapter env variable");
    } else if (CONFIG_B64) {
      configData = Buffer.from(CONFIG_B64, "base64").toString("utf-8");
      console.log("[Signal] Loading config from TIDECLOAK_CONFIG_B64");
    } else {
      const configPath = resolveConfigPath();
      if (!configPath) {
        console.error("[Signal] No tidecloak.json found in data directory");
        return false;
      }
      configData = readFileSync(configPath, "utf-8");
      console.log(`[Signal] Loading config from ${configPath}`);
    }

    tcConfig = JSON.parse(configData) as TidecloakConfig;

    if (!tcConfig.jwk?.keys?.length) {
      console.error("[Signal] No JWKS keys found in config");
      return false;
    }

    JWKS = createLocalJWKSet(tcConfig.jwk);
    console.log("[Signal] JWKS loaded successfully");
    return true;
  } catch (err) {
    console.error("[Signal] Failed to load config:", err);
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
      console.log(`[Signal] AZP mismatch: expected ${tcConfig.resource}, got ${payload.azp}`);
      return null;
    }

    return payload;
  } catch (err) {
    console.log("[Signal] JWT verification failed:", err);
    return null;
  }
}

// Load config on startup
if (!loadConfig()) {
  console.error("[Signal] Failed to load TideCloak config. Exiting.");
  process.exit(1);
}

// ── Static file serving ──────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const PUBLIC_DIR = join(__filename, "..", "..", "public");

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json",
  ".css": "text/css; charset=utf-8",
};

function serveStaticFile(res: import("http").ServerResponse, filename: string): void {
  const filePath = join(PUBLIC_DIR, filename);
  if (filePath.includes("..")) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const content = readFileSync(filePath);
    const ext = extname(filename);
    const contentType = MIME_TYPES[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  }
}

function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

// ── Signaling Registry ──────────────────────────────────────────

const registry = createRegistry();
const relayHandler = createHttpRelay(registry, useTls);

// ── HTTP Server ─────────────────────────────────────────────────

const requestHandler = (req: import("http").IncomingMessage, res: import("http").ServerResponse) => {
  const url = req.url || "/";
  const path = url.split("?")[0];

  // ── Security headers ──────────────────────────────────────────
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // ── CORS ──────────────────────────────────────────────────────
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (req.method === "OPTIONS" && origin) {
    res.writeHead(204, { "Access-Control-Max-Age": "86400" });
    res.end();
    return;
  }

  // ── Portal: show WAF selection when no cookie is set ─────────
  if (path === "/portal" && req.method === "GET") {
    res.setHeader("Set-Cookie", "waf_relay=; Path=/; HttpOnly; Max-Age=0");
    serveStaticFile(res, "portal.html");
    return;
  }

  if (path === "/" && req.method === "GET") {
    const hasCookie = parseCookie(req.headers.cookie, "waf_relay");
    if (!hasCookie) {
      serveStaticFile(res, "portal.html");
      return;
    }
    // Has cookie → fall through to relay
  }

  // ── Health check ──────────────────────────────────────────────
  if (path === "/health") {
    const signalStats = registry.getStats();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      ...signalStats,
    }));
    return;
  }

  // ── WebRTC config (STUN/TURN credentials for P2P upgrade) ────
  if (path === "/webrtc-config" && req.method === "GET") {
    const host = req.headers.host || "localhost";
    const webrtcConfig: Record<string, unknown> = {
      signalingUrl: `${useTls ? "wss" : "ws"}://${host}`,
      stunServer: ICE_SERVERS[0]
        ? `stun:${ICE_SERVERS[0].replace("stun:", "")}`
        : null,
    };
    if (TURN_SERVER && TURN_SECRET) {
      // Generate ephemeral TURN credentials (valid for 1 hour)
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      const turnUsername = `${expiry}`;
      const turnPassword = createHmac("sha256", TURN_SECRET)
        .update(turnUsername)
        .digest("base64");
      webrtcConfig.turnServer = TURN_SERVER;
      webrtcConfig.turnUsername = turnUsername;
      webrtcConfig.turnPassword = turnPassword;
    }
    // Include selected WAF ID from HttpOnly cookie so JS can target it
    const selectedWaf = parseCookie(req.headers.cookie, "waf_relay");
    if (selectedWaf) {
      webrtcConfig.targetWafId = selectedWaf;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(webrtcConfig));
    return;
  }

  // ── API: List WAFs ────────────────────────────────────────────
  if (path === "/api/wafs" && req.method === "GET") {
    const wafs = registry.getAllWafs().map((w) => ({
      id: w.id,
      displayName: w.metadata.displayName || w.id,
      description: w.metadata.description || "",
      backends: w.metadata.backends || [],
      clientCount: w.pairedClients.size,
      online: w.ws.readyState === w.ws.OPEN,
    }));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ wafs }));
    return;
  }

  // ── API: Select WAF (POST — sets affinity cookie) ─────────────
  if (path === "/api/select-waf" && req.method === "POST") {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    const MAX_BODY = 64 * 1024;
    req.on("data", (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY) {
        req.destroy();
        if (!res.headersSent) {
          res.writeHead(413, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Request body too large" }));
        }
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", () => {
      if (!res.headersSent) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request stream error" }));
      }
    });
    req.on("end", () => {
      if (res.headersSent) return;
      try {
        const { wafId, backend } = JSON.parse(Buffer.concat(chunks).toString());
        const waf = registry.getWaf(wafId);
        if (!waf) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "WAF not found" }));
          return;
        }
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Set-Cookie": `waf_relay=${wafId}; Path=/; HttpOnly; SameSite=None; Secure`,
        });
        res.end(JSON.stringify({ success: true, wafId, backend: backend || null }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid request body" }));
      }
    });
    return;
  }

  // ── API: Select WAF (GET — redirect with cookie) ──────────────
  if (path === "/api/select" && req.method === "GET") {
    const params = new URLSearchParams(url.split("?")[1] || "");
    const wafId = params.get("waf");
    const backend = params.get("backend");
    if (!wafId || !registry.getWaf(wafId)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "WAF not found" }));
      return;
    }
    const cookies: string[] = [
      `waf_relay=${wafId}; Path=/; HttpOnly; SameSite=None; Secure`,
    ];
    const location = backend
      ? `/__b/${encodeURIComponent(backend)}/`
      : "/";
    res.writeHead(302, {
      Location: location,
      "Set-Cookie": cookies,
    });
    res.end();
    return;
  }

  // ── API: Clear WAF selection ──────────────────────────────────
  if (path === "/api/clear-selection" && req.method === "POST") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Set-Cookie": "waf_relay=; Path=/; HttpOnly; Max-Age=0",
    });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // ── Relay all other HTTP requests to a WAF ────────────────────
  relayHandler(req, res);
};

const server = useTls
  ? createHttpsServer(
      {
        key: readFileSync(TLS_KEY_PATH),
        cert: readFileSync(TLS_CERT_PATH),
      },
      requestHandler
    )
  : createHttpServer(requestHandler);

// ── WebSocket Server (signaling on any path) ────────────────────

const signalWss = new WebSocketServer({ noServer: true, maxPayload: 1 * 1024 * 1024 });

server.on("upgrade", (req, socket, head) => {
  signalWss.handleUpgrade(req, socket, head, (ws) => {
    signalWss.emit("connection", ws, req);
  });
});

// ── Signaling Handler ───────────────────────────────────────────

interface SignalMessage {
  type: string;
  role?: "waf" | "client";
  id?: string;
  secret?: string;
  token?: string;
  addresses?: string[];
  metadata?: WafMetadata;
  targetId?: string;
  targetWafId?: string;
  fromId?: string;
  candidate?: unknown;
  sdp?: string;
  sdpType?: string;
  action?: string;
  clientId?: string;
  connectionType?: ConnectionType;
}

const MAX_CONNECTIONS_PER_IP = 20;
const MAX_MESSAGES_PER_SEC = 100;
const connectionsByIp = new Map<string, number>();

signalWss.on("connection", (ws: WebSocket, req) => {
  const clientIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    || req.socket.remoteAddress
    || "unknown";

  // Per-IP connection limit
  const ipCount = connectionsByIp.get(clientIp) || 0;
  if (ipCount >= MAX_CONNECTIONS_PER_IP) {
    ws.close(1013, "Too many connections from this IP");
    return;
  }
  connectionsByIp.set(clientIp, ipCount + 1);

  // Per-connection message rate limiting
  let messageCount = 0;
  const rateLimitInterval = setInterval(() => { messageCount = 0; }, 1000);

  ws.on("message", (data) => {
    messageCount++;
    if (messageCount > MAX_MESSAGES_PER_SEC) {
      ws.close(1008, "Rate limit exceeded");
      return;
    }

    let msg: SignalMessage;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    switch (msg.type) {
      case "register":
        handleRegister(ws, msg, clientIp);
        break;
      case "candidate":
        handleCandidate(ws, msg);
        break;
      case "sdp_offer":
      case "sdp_answer":
        handleSdp(ws, msg);
        break;
      case "http_response":
        handleHttpResponse(msg as unknown as {
          id: string;
          statusCode: number;
          headers: Record<string, string | string[]>;
          body: string;
        });
        break;
      case "client_status":
        if (msg.clientId && msg.connectionType) {
          const statusClient = registry.getClient(msg.clientId);
          if (statusClient?.pairedWafId) {
            const senderWaf = registry.getWaf(statusClient.pairedWafId);
            if (senderWaf && senderWaf.ws === ws) {
              registry.updateClientConnection(msg.clientId, msg.connectionType);
            }
          }
        }
        break;
      case "admin_action":
        handleAdminAction(ws, msg);
        break;
      default:
        safeSend(ws, { type: "error", message: `Unknown message type: ${msg.type}` });
    }
  });

  ws.on("close", () => {
    clearInterval(rateLimitInterval);
    const info = registry.getInfoByWs(ws);
    if (info?.type === "waf") {
      rejectPendingForWaf(info.id);
    }
    registry.removeByWs(ws);
    const count = connectionsByIp.get(clientIp) || 0;
    if (count <= 1) {
      connectionsByIp.delete(clientIp);
    } else {
      connectionsByIp.set(clientIp, count - 1);
    }
  });

  ws.on("error", () => {
    clearInterval(rateLimitInterval);
    const info = registry.getInfoByWs(ws);
    if (info?.type === "waf") {
      rejectPendingForWaf(info.id);
    }
    registry.removeByWs(ws);
    const count = connectionsByIp.get(clientIp) || 0;
    if (count <= 1) {
      connectionsByIp.delete(clientIp);
    } else {
      connectionsByIp.set(clientIp, count - 1);
    }
  });
});

async function handleRegister(ws: WebSocket, msg: SignalMessage, clientIp: string): Promise<void> {
  if (!msg.id || !msg.role) {
    safeSend(ws, { type: "error", message: "Missing id or role" });
    return;
  }

  if (msg.role === "waf") {
    // WAF registration requires API_SECRET (timing-safe comparison)
    if (API_SECRET) {
      const secret = msg.secret || "";
      const expected = Buffer.from(API_SECRET);
      const received = Buffer.from(secret);
      if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
        console.log(`[Signal] WAF registration rejected: invalid secret (id: ${msg.id})`);
        safeSend(ws, { type: "error", message: "Invalid API secret" });
        ws.close(4001, "Unauthorized");
        return;
      }
    }

    registry.registerWaf(msg.id, msg.addresses || [], ws, msg.metadata);
    safeSend(ws, { type: "registered", role: "waf", id: msg.id });
  } else if (msg.role === "client") {
    // Client registration requires a valid JWT from KeyleSSH
    if (!msg.token) {
      safeSend(ws, { type: "error", message: "Authentication required" });
      ws.close(4001, "Missing token");
      return;
    }

    const payload = await verifyToken(msg.token);
    if (!payload) {
      safeSend(ws, { type: "error", message: "Invalid or expired token" });
      ws.close(4002, "Invalid token");
      return;
    }

    console.log(`[Signal] Client authenticated: ${payload.sub || "unknown"} (${msg.id})`);
    registry.registerClient(msg.id, ws, msg.token);
    registry.updateClientReflexive(msg.id, clientIp);
    safeSend(ws, { type: "registered", role: "client", id: msg.id });

    // Explicit WAF selection or auto-pair
    if (msg.targetWafId) {
      pairClientWithWaf(registry, msg.id, msg.targetWafId);
    } else {
      pairClient(registry, msg.id);
    }
  } else {
    safeSend(ws, { type: "error", message: `Unknown role: ${msg.role}` });
  }
}

function handleSdp(ws: WebSocket, msg: SignalMessage): void {
  if (!msg.targetId || !msg.sdp || !msg.fromId) {
    safeSend(ws, { type: "error", message: "Missing targetId, fromId, or sdp" });
    return;
  }
  forwardSdp(registry, msg.fromId, msg.targetId, msg.type, msg.sdp, msg.sdpType);
}

function handleCandidate(ws: WebSocket, msg: SignalMessage): void {
  if (!msg.targetId || !msg.candidate) {
    safeSend(ws, { type: "error", message: "Missing targetId or candidate" });
    return;
  }
  const fromId = msg.fromId || "unknown";
  forwardCandidate(registry, fromId, msg.targetId, msg.candidate);
}

async function handleAdminAction(ws: WebSocket, msg: SignalMessage): Promise<void> {
  // Verify admin JWT
  if (msg.token) {
    const payload = await verifyToken(msg.token);
    if (!payload) {
      safeSend(ws, { type: "error", message: "Invalid or insufficient permissions" });
      return;
    }
  } else {
    safeSend(ws, { type: "error", message: "Authentication required" });
    return;
  }

  if (!msg.action || !msg.targetId) {
    safeSend(ws, { type: "error", message: "Missing action or targetId" });
    return;
  }

  let success = false;
  if (msg.action === "disconnect_client") {
    success = registry.forceDisconnectClient(msg.targetId);
  } else if (msg.action === "drain_waf") {
    success = registry.drainWaf(msg.targetId);
  }

  safeSend(ws, {
    type: "admin_result",
    action: msg.action,
    targetId: msg.targetId,
    success,
  });
}

function safeSend(ws: WebSocket, data: unknown): void {
  try {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(data));
    }
  } catch {
    // Connection lost
  }
}

// ── Start ───────────────────────────────────────────────────────

const scheme = useTls ? "https" : "http";
const wsScheme = useTls ? "wss" : "ws";

server.listen(PORT, () => {
  console.log(`[Signal] Signal Server listening on ${scheme}://localhost:${PORT}`);
  console.log(`[Signal] Signaling: ${wsScheme}://localhost:${PORT}`);
  console.log(`[Signal] Portal: ${scheme}://localhost:${PORT}/portal`);
  console.log(`[Signal] Health: ${scheme}://localhost:${PORT}/health`);
  if (useTls) {
    console.log(`[Signal] TLS: ${TLS_CERT_PATH}`);
  }
  console.log(`[Signal] API Secret: ${API_SECRET ? "set" : "disabled (open)"}`);
});

process.on("SIGTERM", () => {
  console.log("[Signal] Shutting down...");
  signalWss.clients.forEach((client) => client.close(1001, "Server shutting down"));
  server.close(() => {
    console.log("[Signal] Shutdown complete");
    process.exit(0);
  });
});
