import { createServer as createHttpServer, request as httpRequest } from "http";
import { createServer as createHttpsServer, request as httpsRequest } from "https";
import { WebSocketServer, WebSocket } from "ws";
import { readFileSync } from "fs";
import { timingSafeEqual, createHmac, randomBytes } from "crypto";
import { createRegistry, type ConnectionType, type GatewayMetadata } from "./signaling/registry.js";
import { pairClient, pairClientWithGateway, forwardCandidate, forwardSdp } from "./signaling/pairing.js";
import { createHttpRelay, handleHttpResponse, handleHttpResponseStart, handleHttpResponseChunk, handleHttpResponseEnd, rejectPendingForGateway } from "./relay/http-relay.js";

/**
 * Signal Server — P2P signaling + HTTP relay
 *
 * Handles gateway registration, client pairing, SDP/ICE exchange,
 * TURN credential generation, and HTTP relay tunneling.
 *
 * Environment variables:
 * - PORT: Port to listen on (default: 9090)
 * - API_SECRET: Shared secret for gateway registration authentication
 * - ICE_SERVERS: Comma-separated STUN server URLs (e.g. "stun:relay.example.com:3478")
 * - TURN_SERVER: TURN server URL for WebRTC relay fallback (e.g. "turn:relay.example.com:3478")
 * - TURN_SECRET: Shared secret for TURN REST API ephemeral credentials (HMAC-SHA1)
 * - TLS_CERT_PATH: Path to TLS certificate file (enables HTTPS/WSS)
 * - TLS_KEY_PATH: Path to TLS private key file
 */

const PORT = parseInt(process.env.PORT || "9090");
const API_SECRET = process.env.API_SECRET || "";
const ICE_SERVERS = process.env.ICE_SERVERS ? process.env.ICE_SERVERS.split(",") : [];
const TURN_SERVER = process.env.TURN_SERVER || "";
const TURN_SECRET = process.env.TURN_SECRET || "";
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || "";
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || "";
const useTls = !!(TLS_CERT_PATH && TLS_KEY_PATH);
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? new Set(process.env.ALLOWED_ORIGINS.split(",").map(o => o.trim()))
  : null; // null = allow same-origin only (derive from Host header)
const TRUSTED_PROXIES = process.env.TRUSTED_PROXIES
  ? new Set(process.env.TRUSTED_PROXIES.split(",").map(p => p.trim()))
  : null; // null = never trust X-Forwarded-For

// ── TideCloak Reverse Proxy (cookie jar) ─────────────────────────
// Proxies /realms/* and /resources/* to TideCloak, storing TC cookies
// server-side so the Tide auth flow stays on the signal server's origin.
// Gateways handle actual JWT verification — the signal server just proxies.

const tcAuthServerUrl = (process.env.TIDECLOAK_URL || "").replace(/\/$/, "");
const tcProxyEnabled = !!tcAuthServerUrl;
const tcProxyUrl = tcProxyEnabled ? new URL(tcAuthServerUrl) : null!;
const tcProxyIsHttps = tcProxyEnabled && tcProxyUrl.protocol === "https:";
const makeTcRequest = tcProxyIsHttps ? httpsRequest : httpRequest;

if (tcProxyEnabled) {
  console.log(`[Signal] TideCloak proxy: ${tcAuthServerUrl}`);
} else {
  console.log("[Signal] TideCloak proxy disabled (no TIDECLOAK_URL set)");
}

interface TcSession { cookies: Map<string, string>; lastAccess: number; }
const tcCookieJar = new Map<string, TcSession>();
const TC_SESS_MAX_AGE = 3600;
const TC_SESS_MAX_ENTRIES = 10000;

function getTcSessionId(cookieHeader: string | undefined): { id: string; isNew: boolean } {
  const existing = parseCookieValue(cookieHeader, "tc_sess");
  if (existing) {
    const session = tcCookieJar.get(existing);
    if (session) {
      session.lastAccess = Date.now();
      return { id: existing, isNew: false };
    }
  }
  const id = randomBytes(16).toString("hex");
  tcCookieJar.set(id, { cookies: new Map(), lastAccess: Date.now() });
  return { id, isNew: true };
}

function parseCookieValue(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

function storeTcCookies(sessionId: string, setCookieHeaders: string | string[] | undefined): void {
  if (!setCookieHeaders) return;
  const session = tcCookieJar.get(sessionId);
  if (!session) return;
  session.lastAccess = Date.now();
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const h of headers) {
    const eq = h.indexOf("=");
    if (eq < 0) continue;
    const name = h.slice(0, eq).trim();
    const rest = h.slice(eq + 1);
    const semi = rest.indexOf(";");
    const value = semi >= 0 ? rest.slice(0, semi) : rest;
    if (!value || /Max-Age=0/i.test(h)) {
      session.cookies.delete(name);
    } else {
      session.cookies.set(name, value);
    }
  }
}

function getTcCookieHeader(sessionId: string): string {
  const session = tcCookieJar.get(sessionId);
  if (!session || session.cookies.size === 0) return "";
  session.lastAccess = Date.now();
  return Array.from(session.cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
}

// Evict stale sessions every 10 min
setInterval(() => {
  const now = Date.now();
  const maxAge = TC_SESS_MAX_AGE * 1000;
  for (const [id, session] of tcCookieJar) {
    if (now - session.lastAccess > maxAge) tcCookieJar.delete(id);
  }
  if (tcCookieJar.size > TC_SESS_MAX_ENTRIES) {
    const sorted = [...tcCookieJar.entries()].sort((a, b) => a[1].lastAccess - b[1].lastAccess);
    for (const [id] of sorted.slice(0, tcCookieJar.size - TC_SESS_MAX_ENTRIES)) {
      tcCookieJar.delete(id);
    }
  }
}, 600_000).unref();

function proxyTideCloak(
  req: import("http").IncomingMessage,
  res: import("http").ServerResponse,
  publicOrigin: string,
): void {
  const tcSess = getTcSessionId(req.headers.cookie);

  const proxyHeaders = { ...req.headers } as Record<string, string | string[] | undefined>;
  proxyHeaders.host = tcProxyUrl.host;
  delete proxyHeaders["x-forwarded-proto"];
  delete proxyHeaders["x-forwarded-host"];
  delete proxyHeaders["x-forwarded-for"];
  delete proxyHeaders["x-forwarded-port"];
  delete proxyHeaders["accept-encoding"];

  const jarCookies = getTcCookieHeader(tcSess.id);
  if (jarCookies) {
    const existing = (proxyHeaders.cookie as string) || "";
    proxyHeaders.cookie = existing ? `${existing}; ${jarCookies}` : jarCookies;
  }

  const tcReq = makeTcRequest(
    {
      hostname: tcProxyUrl.hostname,
      port: tcProxyUrl.port || (tcProxyIsHttps ? 443 : 80),
      path: req.url,
      method: req.method,
      headers: proxyHeaders,
      rejectUnauthorized: false,
    },
    (tcRes: import("http").IncomingMessage) => {
      const headers = { ...tcRes.headers } as Record<string, string | string[] | undefined>;

      if (headers.location && typeof headers.location === "string") {
        headers.location = headers.location
          .replaceAll(tcProxyUrl.origin, publicOrigin)
          .replaceAll(tcAuthServerUrl, publicOrigin)
          .replaceAll(encodeURIComponent(tcProxyUrl.origin), encodeURIComponent(publicOrigin))
          .replaceAll(encodeURIComponent(tcAuthServerUrl), encodeURIComponent(publicOrigin));
      }

      delete headers["content-encoding"];
      delete headers["transfer-encoding"];
      delete headers["content-security-policy"];
      delete headers["content-security-policy-report-only"];

      storeTcCookies(tcSess.id, headers["set-cookie"] as string | string[] | undefined);

      const tcSessCookie = `tc_sess=${tcSess.id}; HttpOnly; Path=/; Max-Age=${TC_SESS_MAX_AGE}; SameSite=None; Secure`;
      if (headers["set-cookie"] || tcSess.isNew) {
        headers["set-cookie"] = [tcSessCookie];
      }

      const contentType = (headers["content-type"] || "") as string;
      const isText = contentType.includes("text/") ||
        contentType.includes("application/javascript") ||
        contentType.includes("application/json");

      if (isText) {
        const chunks: Buffer[] = [];
        tcRes.on("data", (chunk: Buffer) => chunks.push(chunk));
        tcRes.on("end", () => {
          if (res.headersSent) return;
          let body = Buffer.concat(chunks).toString("utf-8");
          body = body.replaceAll(tcProxyUrl.origin, publicOrigin);
          body = body.replaceAll(
            tcProxyUrl.origin.replaceAll("/", "\\/"),
            publicOrigin.replaceAll("/", "\\/"),
          );
          body = body.replaceAll(
            encodeURIComponent(tcProxyUrl.origin),
            encodeURIComponent(publicOrigin),
          );
          if (tcAuthServerUrl !== tcProxyUrl.origin) {
            body = body.replaceAll(tcAuthServerUrl, publicOrigin);
            body = body.replaceAll(
              tcAuthServerUrl.replaceAll("/", "\\/"),
              publicOrigin.replaceAll("/", "\\/"),
            );
            body = body.replaceAll(
              encodeURIComponent(tcAuthServerUrl),
              encodeURIComponent(publicOrigin),
            );
          }
          headers["content-length"] = Buffer.byteLength(body).toString();
          res.writeHead(tcRes.statusCode || 200, headers);
          res.end(body);
        });
      } else {
        res.writeHead(tcRes.statusCode || 200, headers);
        tcRes.pipe(res);
      }
    },
  );

  tcReq.on("error", (err: Error) => {
    console.error("[Signal] TC proxy error:", err.message);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "TideCloak proxy error" }));
    }
  });

  req.pipe(tcReq);
}

// ── Cookie helper ────────────────────────────────────────────────

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

const requestHandler = async (req: import("http").IncomingMessage, res: import("http").ServerResponse) => {
  const url = req.url || "/";
  const path = url.split("?")[0];

  // ── Security headers ──────────────────────────────────────────
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // ── CORS ──────────────────────────────────────────────────────
  const origin = req.headers.origin;
  if (origin) {
    // Validate origin: explicit allowlist, or fall back to same-host check
    const hostOrigin = `${useTls ? "https" : "http"}://${req.headers.host}`;
    const allowed = ALLOWED_ORIGINS
      ? ALLOWED_ORIGINS.has(origin)
      : origin === hostOrigin;
    if (allowed) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
  }
  if (req.method === "OPTIONS" && origin) {
    res.writeHead(204, { "Access-Control-Max-Age": "86400" });
    res.end();
    return;
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
      const turnPassword = createHmac("sha1", TURN_SECRET)
        .update(turnUsername)
        .digest("base64");
      webrtcConfig.turnServer = TURN_SERVER;
      webrtcConfig.turnUsername = turnUsername;
      webrtcConfig.turnPassword = turnPassword;
    }
    // Include selected gateway ID from HttpOnly cookie so JS can target it
    const selectedGatewayRaw = parseCookie(req.headers.cookie, "gateway_relay");
    if (selectedGatewayRaw) {
      const gatewayId = decodeURIComponent(selectedGatewayRaw);
      webrtcConfig.targetGatewayId = gatewayId;
      // Include backendAuth map for eddsa backends (so RDP client auto-connects)
      const gateway = registry.getGateway(gatewayId);
      if (gateway) {
        const authMap: Record<string, string> = {};
        for (const b of gateway.metadata.backends || []) {
          if (b.auth === "eddsa") authMap[b.name] = "eddsa";
        }
        if (Object.keys(authMap).length > 0) {
          webrtcConfig.backendAuth = authMap;
        }
      }
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(webrtcConfig));
    return;
  }

  // ── API: List gateways ────────────────────────────────────────────
  if (path === "/api/gateways" && req.method === "GET") {
    const gateways = registry.getAllGateways().map((w) => ({
      id: w.id,
      displayName: w.metadata.displayName || w.id,
      description: w.metadata.description || "",
      backends: w.metadata.backends || [],
      clientCount: w.pairedClients.size,
      online: w.ws.readyState === w.ws.OPEN,
    }));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ gateways }));
    return;
  }

  // ── API: Select gateway (POST — sets affinity cookie) ─────────────
  if (path === "/api/select-gateway" && req.method === "POST") {
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
        const { gatewayId, backend } = JSON.parse(Buffer.concat(chunks).toString());
        const gateway = registry.getGateway(gatewayId);
        if (!gateway) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Gateway not found" }));
          return;
        }
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Set-Cookie": `gateway_relay=${encodeURIComponent(gatewayId)}; Path=/; HttpOnly; SameSite=None; Secure`,
        });
        res.end(JSON.stringify({ success: true, gatewayId, backend: backend || null }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid request body" }));
      }
    });
    return;
  }

  // ── API: Select gateway (GET — redirect with cookie) ──────────────
  // Accepts optional &token= with a KeyleSSH JWT to forward to the gateway
  // so the user doesn't have to log in again via TideCloak.
  if (path === "/api/select" && req.method === "GET") {
    const params = new URLSearchParams(url.split("?")[1] || "");
    const gatewayId = params.get("gateway");
    const backend = params.get("backend");
    const token = params.get("token");
    if (!gatewayId || !registry.getGateway(gatewayId)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Gateway not found" }));
      return;
    }
    const cookies: string[] = [
      `gateway_relay=${encodeURIComponent(gatewayId)}; Path=/; HttpOnly; SameSite=None; Secure`,
    ];
    // Pass token through as cookies — gateway handles verification
    if (token) {
      cookies.push(`gateway_access=${token}; Path=/; HttpOnly; SameSite=None; Secure`);
      cookies.push(`keylessh_token=${token}; Path=/; SameSite=None; Secure`);
    }
    const redirect = params.get("redirect");
    const location = redirect
      ? redirect
      : backend
        ? `/__b/${encodeURIComponent(backend)}/`
        : "/";
    res.writeHead(302, {
      Location: location,
      "Set-Cookie": cookies,
    });
    res.end();
    return;
  }

  // ── API: Clear gateway selection ──────────────────────────────────
  if (path === "/api/clear-selection" && req.method === "POST") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Set-Cookie": "gateway_relay=; Path=/; HttpOnly; Max-Age=0",
    });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // ── TideCloak reverse proxy (/realms/*, /resources/*) ─────────
  // If a gateway serves this realm, relay to it; otherwise proxy to TideCloak directly.
  if (tcProxyEnabled && (path.startsWith("/realms/") || path.startsWith("/resources/"))) {
    const realmMatch = path.match(/\/(?:realms|resources)\/([^/]+)\//);
    if (realmMatch) {
      const realmGateway = registry.getGatewayByRealm(realmMatch[1]);
      if (realmGateway) {
        relayHandler(req, res);
        return;
      }
    }
    const proto = req.headers["x-forwarded-proto"] || (useTls ? "https" : "http");
    const host = req.headers.host || "localhost";
    const publicOrigin = `${proto}://${host}`;
    proxyTideCloak(req, res, publicOrigin);
    return;
  }

  // ── Relay all other HTTP requests to a gateway ────────────────────
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

const signalWss = new WebSocketServer({ noServer: true, maxPayload: 5 * 1024 * 1024 });

server.on("upgrade", (req, socket, head) => {
  signalWss.handleUpgrade(req, socket, head, (ws) => {
    signalWss.emit("connection", ws, req);
  });
});

// ── Signaling Handler ───────────────────────────────────────────

interface SignalMessage {
  type: string;
  role?: "gateway" | "client";
  id?: string;
  secret?: string;
  token?: string;
  addresses?: string[];
  metadata?: GatewayMetadata;
  targetId?: string;
  targetGatewayId?: string;
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
const gatewayWebSockets = new Set<WebSocket>();

signalWss.on("connection", (ws: WebSocket, req) => {
  const socketIp = req.socket.remoteAddress || "unknown";
  const clientIp = (TRUSTED_PROXIES && TRUSTED_PROXIES.has(socketIp)
    ? (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    : null)
    || socketIp;

  // Per-IP connection limit
  const ipCount = connectionsByIp.get(clientIp) || 0;
  if (ipCount >= MAX_CONNECTIONS_PER_IP) {
    ws.close(1013, "Too many connections from this IP");
    return;
  }
  connectionsByIp.set(clientIp, ipCount + 1);

  // Per-connection message rate limiting (exempt gateways — they're authenticated)
  let messageCount = 0;
  const rateLimitInterval = setInterval(() => { messageCount = 0; }, 1000);

  ws.on("message", (data) => {
    if (!gatewayWebSockets.has(ws)) {
      messageCount++;
      if (messageCount > MAX_MESSAGES_PER_SEC) {
        ws.close(1008, "Rate limit exceeded");
        return;
      }
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
      case "http_response_start":
        handleHttpResponseStart(msg as unknown as {
          id: string;
          statusCode: number;
          headers: Record<string, string | string[]>;
        });
        break;
      case "http_response_chunk":
        handleHttpResponseChunk(msg as unknown as {
          id: string;
          data: string;
        });
        break;
      case "http_response_end":
        handleHttpResponseEnd(msg as unknown as { id: string });
        break;
      case "client_status":
        if (msg.clientId && msg.connectionType) {
          const statusClient = registry.getClient(msg.clientId);
          if (statusClient?.pairedGatewayId) {
            const senderGateway = registry.getGateway(statusClient.pairedGatewayId);
            if (senderGateway && senderGateway.ws === ws) {
              registry.updateClientConnection(msg.clientId, msg.connectionType);
            }
          }
        }
        break;
      case "admin_action":
        safeSend(ws, { type: "error", message: "Admin actions not supported" });
        break;
      default:
        safeSend(ws, { type: "error", message: `Unknown message type: ${msg.type}` });
    }
  });

  ws.on("close", () => {
    clearInterval(rateLimitInterval);
    gatewayWebSockets.delete(ws);
    const info = registry.getInfoByWs(ws);
    if (info?.type === "gateway") {
      rejectPendingForGateway(info.id);
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
    gatewayWebSockets.delete(ws);
    const info = registry.getInfoByWs(ws);
    if (info?.type === "gateway") {
      rejectPendingForGateway(info.id);
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

  if (msg.role === "gateway") {
    // Gateway registration requires API_SECRET (timing-safe comparison)
    if (API_SECRET) {
      const secret = msg.secret || "";
      const expected = Buffer.from(API_SECRET);
      const received = Buffer.from(secret);
      if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
        console.log(`[Signal] Gateway registration rejected: invalid secret (id: ${msg.id})`);
        safeSend(ws, { type: "error", message: "Invalid API secret" });
        ws.close(4001, "Unauthorized");
        return;
      }
    }

    registry.registerGateway(msg.id, msg.addresses || [], ws, msg.metadata);
    gatewayWebSockets.add(ws);
    safeSend(ws, { type: "registered", role: "gateway", id: msg.id });
  } else if (msg.role === "client") {
    // Signal server is a dumb relay — gateway handles auth.
    // Just pass the token through so the gateway can validate it.
    console.log(`[Signal] Client registered: ${msg.id}`);
    registry.registerClient(msg.id, ws, msg.token || "");
    registry.updateClientReflexive(msg.id, clientIp);
    safeSend(ws, { type: "registered", role: "client", id: msg.id });

    // Explicit gateway selection or auto-pair
    if (msg.targetGatewayId) {
      pairClientWithGateway(registry, msg.id, msg.targetGatewayId);
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
