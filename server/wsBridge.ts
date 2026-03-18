import { Server as HTTPServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { Socket, connect } from "net";
import crypto from "crypto";
import { verifyTideCloakToken } from "./lib/auth/tideJWT";
import { storage } from "./storage";

/**
 * Embedded WebSocket-to-TCP bridge for local development.
 * Production deployments should use the external tcp-bridge service.
 */

// ============================================
// DPoP Proof Verification (RFC 9449)
// ============================================

function base64UrlDecode(str: string): Buffer {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
  return base64UrlEncode(crypto.createHash("sha256").update(canonical).digest());
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

    const publicKey = crypto.createPublicKey({ key: header.jwk, format: "jwk" });
    const signInput = `${parts[0]}.${parts[1]}`;
    const signature = base64UrlDecode(parts[2]);
    const alg = header.alg === "EdDSA" ? null : header.alg.toLowerCase().replace("es", "sha");
    if (!crypto.verify(alg, Buffer.from(signInput), publicKey, signature)) {
      return { valid: false, error: "Invalid signature" };
    }

    if (payload.htm !== httpMethod) return { valid: false, error: "htm mismatch" };
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
    return payload.cnf?.jkt;
  } catch {
    return undefined;
  }
}

let activeConnections = 0;
const sessionConnections = new Map<string, WebSocket>();

export function setupWSBridge(httpServer: HTTPServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/tcp" });

  wss.on("connection", async (ws: WebSocket, req) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");
    const host = url.searchParams.get("host");
    const port = parseInt(url.searchParams.get("port") || "22", 10);
    const sessionId = url.searchParams.get("sessionId");
    const dpopProof = url.searchParams.get("dpop");

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

    // DPoP proof verification if provided (RFC 9449)
    const cnfJkt = extractCnfJkt(token);
    if (dpopProof) {
      const requestUrl = `${req.headers["x-forwarded-proto"] || "http"}://${req.headers.host}${(req.url || "/").split("?")[0]}`;
      const result = verifyDPoPProof(dpopProof, "GET", requestUrl, cnfJkt);
      if (!result.valid) {
        console.warn("[WSBridge] DPoP proof verification failed:", result.error);
        ws.close(4003, `DPoP proof invalid: ${result.error}`);
        return;
      }
    }

    const userId = payload.sub || "unknown";
    console.log(`[WSBridge] Connection: ${userId} -> ${host}:${port} (session: ${sessionId})`);
    activeConnections++;
    if (sessionId) sessionConnections.set(sessionId, ws);

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
      if (sessionId) sessionConnections.delete(sessionId);
      if (!tcpSocket.destroyed) {
        tcpSocket.destroy();
      }
      // End the session record in the database so it doesn't appear as a ghost session
      if (sessionId) {
        storage.endSession(sessionId).catch((err) => {
          console.log(`[WSBridge] Failed to end session ${sessionId}:`, err);
        });
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

/**
 * Forcibly close the WebSocket for a given session, which tears down the
 * TCP tunnel and triggers the normal close-handler cleanup.
 * Returns true if a connection was found and closed.
 */
export function terminateSession(sessionId: string): boolean {
  const ws = sessionConnections.get(sessionId);
  if (!ws) return false;
  ws.close(4004, "Terminated by admin");
  return true;
}
