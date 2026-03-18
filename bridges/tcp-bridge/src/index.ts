import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect } from "net";
import { jwtVerify, createLocalJWKSet, JWTPayload } from "jose";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { createPublicKey, createHash, verify as cryptoVerify } from "crypto";

/**
 * TCP Bridge — Stateless WebSocket-to-TCP forwarder for SSH connections.
 *
 * Clients connect via WebSocket with JWT auth, and the bridge opens a TCP
 * connection to the target SSH server, forwarding data bidirectionally.
 *
 * Environment variables:
 * - PORT: Port to listen on (default: 8081)
 * - client_adapter: JSON string of tidecloak.json config (highest priority)
 * - TIDECLOAK_CONFIG_B64: Base64-encoded config (alternative for Azure)
 */

const PORT = parseInt(process.env.PORT || "8081");
const CLIENT_ADAPTER = process.env.client_adapter;
const CONFIG_B64 = process.env.TIDECLOAK_CONFIG_B64;

// Resolve path to tidecloak.json in data directory
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
      console.log("[Bridge] Loading config from client_adapter env variable");
    } else if (CONFIG_B64) {
      configData = Buffer.from(CONFIG_B64, "base64").toString("utf-8");
      console.log("[Bridge] Loading config from TIDECLOAK_CONFIG_B64");
    } else {
      const configPath = resolveConfigPath();
      if (!configPath) {
        console.error("[Bridge] No tidecloak.json found in data directory");
        return false;
      }
      configData = readFileSync(configPath, "utf-8");
      console.log(`[Bridge] Loading config from ${configPath}`);
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

// ── DPoP Proof Verification (RFC 9449) ──────────────────────────

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(str: string): Buffer {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function computeJwkThumbprint(jwk: any): string {
  let canonical: string;
  if (jwk.kty === "EC") {
    canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  } else if (jwk.kty === "OKP") {
    canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  } else if (jwk.kty === "RSA") {
    canonical = `{"e":"${jwk.e}","kty":"${jwk.kty}","n":"${jwk.n}"}`;
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
  return base64UrlEncode(createHash("sha256").update(canonical).digest());
}

const seenJtis = new Map<string, number>();

function checkAndStoreJti(jti: string): boolean {
  const now = Date.now();
  if (seenJtis.size > 1000) {
    seenJtis.forEach((exp, k) => { if (exp < now) seenJtis.delete(k); });
  }
  if (seenJtis.has(jti)) return false;
  seenJtis.set(jti, now + 120_000);
  return true;
}

function verifyDPoPProof(
  proofJwt: string,
  httpMethod: string,
  httpUrl: string,
  expectedJkt?: string,
): { valid: boolean; error?: string } {
  try {
    const parts = proofJwt.split(".");
    if (parts.length !== 3) return { valid: false, error: "Invalid JWT structure" };

    const header = JSON.parse(base64UrlDecode(parts[0]).toString());
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString());

    if (header.typ !== "dpop+jwt") return { valid: false, error: "Invalid typ" };

    const supportedAlgs = ["EdDSA", "ES256", "ES384", "ES512"];
    if (!supportedAlgs.includes(header.alg)) return { valid: false, error: `Unsupported alg: ${header.alg}` };
    if (!header.jwk) return { valid: false, error: "Missing jwk in header" };

    const publicKey = createPublicKey({ key: header.jwk, format: "jwk" });
    const signInput = `${parts[0]}.${parts[1]}`;
    const signature = base64UrlDecode(parts[2]);
    const alg = header.alg === "EdDSA" ? null : header.alg.toLowerCase().replace("es", "sha");
    if (!cryptoVerify(alg, Buffer.from(signInput), publicKey, signature)) {
      return { valid: false, error: "Invalid signature" };
    }

    if (payload.htm !== httpMethod) return { valid: false, error: `htm mismatch` };
    const expectedHtu = httpUrl.split("?")[0];
    if (payload.htu !== expectedHtu) return { valid: false, error: "htu mismatch" };

    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.iat) > 120) return { valid: false, error: "iat too far from current time" };
    if (!payload.jti || !checkAndStoreJti(payload.jti)) return { valid: false, error: "jti missing or replayed" };

    if (expectedJkt) {
      const thumbprint = computeJwkThumbprint(header.jwk);
      if (thumbprint !== expectedJkt) return { valid: false, error: "JWK thumbprint does not match cnf.jkt" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: `DPoP verification error: ${err}` };
  }
}

function extractCnfJkt(token: string): string | undefined {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return undefined;
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString());
    return payload?.cnf?.jkt;
  } catch { return undefined; }
}

// Load config on startup
if (!loadConfig()) {
  console.error("[Bridge] Failed to load TideCloak config. Exiting.");
  process.exit(1);
}

// ── HTTP Server ─────────────────────────────────────────────────

let activeTcpConnections = 0;

const server = createServer((req, res) => {
  const url = req.url || "/";
  const path = url.split("?")[0];

  if (path === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      tcpConnections: activeTcpConnections,
    }));
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

// ── WebSocket Server ────────────────────────────────────────────

const wss = new WebSocketServer({ server });

wss.on("connection", async (ws: WebSocket, req) => {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);
  const host = url.searchParams.get("host");
  const port = parseInt(url.searchParams.get("port") || "22", 10);
  const sessionId = url.searchParams.get("sessionId");

  // Extract token: Authorization header (DPoP or Bearer) first, then query param
  let token: string | null = null;
  let isDPoP = false;
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("DPoP ")) {
    token = authHeader.slice(5);
    isDPoP = true;
  } else if (authHeader?.startsWith("Bearer ")) {
    token = authHeader.slice(7);
  } else {
    token = url.searchParams.get("token");
  }

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

  // DPoP proof verification (RFC 9449)
  const cnfJkt = extractCnfJkt(token);
  const dpopQueryProof = url.searchParams.get("dpop");
  if (isDPoP) {
    const dpopProof = req.headers["dpop"] as string | undefined;
    if (!dpopProof) {
      ws.close(4003, "DPoP proof required");
      return;
    }
    const requestUrl = `${req.headers["x-forwarded-proto"] || "http"}://${req.headers.host}${(req.url || "/").split("?")[0]}`;
    const result = verifyDPoPProof(dpopProof, "GET", requestUrl, cnfJkt);
    if (!result.valid) {
      console.warn("[Bridge] DPoP proof verification failed:", result.error);
      ws.close(4003, `DPoP proof invalid: ${result.error}`);
      return;
    }
  } else if (dpopQueryProof) {
    // DPoP proof passed as query param (WebSocket can't set custom headers)
    const requestUrl = `${req.headers["x-forwarded-proto"] || "http"}://${req.headers.host}${(req.url || "/").split("?")[0]}`;
    const result = verifyDPoPProof(dpopQueryProof, "GET", requestUrl, cnfJkt);
    if (!result.valid) {
      console.warn("[Bridge] DPoP query proof verification failed:", result.error);
      ws.close(4003, `DPoP proof invalid: ${result.error}`);
      return;
    }
  } else if (cnfJkt && authHeader) {
    // Token is DPoP-bound but used Bearer scheme via header — reject
    ws.close(4003, "DPoP-bound token requires DPoP authorization scheme");
    return;
  }
  // Note: query-param tokens without dpop proof still accepted (backwards compat)

  const userId = payload.sub || "unknown";
  console.log(`[Bridge] Connection: ${userId} -> ${host}:${port} (session: ${sessionId})`);
  activeTcpConnections++;

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
    activeTcpConnections--;
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

// ── Start ───────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`[Bridge] TCP Bridge listening on port ${PORT}`);
  console.log(`[Bridge] Health: http://localhost:${PORT}/health`);
});

process.on("SIGTERM", () => {
  console.log("[Bridge] Shutting down...");
  wss.clients.forEach((client) => client.close(1001, "Server shutting down"));
  server.close(() => {
    console.log("[Bridge] Shutdown complete");
    process.exit(0);
  });
});
