/**
 * RDCleanPath session handler.
 *
 * Processes the RDCleanPath protocol for a single client session:
 *
 * 1. AWAITING_REQUEST: parse client's RDCleanPath Request PDU,
 *    validate JWT, resolve backend name to rdp://host:port.
 * 2. CONNECTING: open TCP to RDP server, send X.224 Connection Request,
 *    read X.224 Connection Confirm, perform TLS handshake, extract
 *    server certificate chain, send RDCleanPath Response PDU.
 * 3. RELAY: bidirectional pipe — client binary ↔ TLS socket.
 *
 * Called from peer-handler.ts as a virtual WebSocket handler
 * (no real WebSocket — messages flow over DataChannel).
 */

import { connect as netConnect, type Socket } from "net";
import { connect as tlsConnect, type TLSSocket } from "tls";
import type { JWTPayload } from "jose";
import type { BackendEntry } from "../config.js";
import {
  parseRDCleanPathRequest,
  buildRDCleanPathResponse,
  buildRDCleanPathError,
  RDCLEANPATH_ERROR_GENERAL,
  type RDCleanPathRequest,
} from "./rdcleanpath.js";
import { performCredSSP } from "./credssp-client.js";

// ── Public interface ─────────────────────────────────────────────

export interface RDCleanPathSession {
  /** Handle a binary message from the client */
  handleMessage(data: Buffer): void;
  /** Close the session */
  close(): void;
}

export interface RDCleanPathSessionOptions {
  /** Send a binary WS message back to the client */
  sendBinary: (data: Buffer) => void;
  /** Send a close frame back to the client */
  sendClose: (code: number, reason: string) => void;
  /** Available backends for resolution */
  backends: BackendEntry[];
  /** JWT verification function */
  verifyToken: (token: string) => Promise<JWTPayload | null>;
  /** Gateway ID for dest: role enforcement */
  gatewayId?: string;
  /** TideCloak client ID for role extraction */
  tcClientId?: string;
}

const enum State {
  AWAITING_REQUEST,
  CONNECTING,
  CREDSSP,
  RELAY,
  CLOSED,
}

const CONNECT_TIMEOUT = 10_000;
const TLS_TIMEOUT = 10_000;
const X224_READ_TIMEOUT = 10_000;

// ── Session factory ──────────────────────────────────────────────

export function createRDCleanPathSession(opts: RDCleanPathSessionOptions): RDCleanPathSession {
  let state = State.AWAITING_REQUEST;
  let tcpSocket: Socket | null = null;
  let tlsSocket: TLSSocket | null = null;
  let relayBytesToClient = 0;
  let relayBytesFromClient = 0;

  function sendError(errorCode: number, httpStatus?: number, wsaError?: number, tlsAlert?: number): void {
    try {
      const pdu = buildRDCleanPathError({
        errorCode,
        httpStatusCode: httpStatus,
        wsaLastError: wsaError,
        tlsAlertCode: tlsAlert,
      });
      opts.sendBinary(pdu);
    } catch {
      // best effort
    }
    cleanup();
    opts.sendClose(1000, "RDCleanPath error");
  }

  function cleanup(): void {
    state = State.CLOSED;
    if (tlsSocket) {
      try { tlsSocket.destroy(); } catch {}
      tlsSocket = null;
    }
    if (tcpSocket) {
      try { tcpSocket.destroy(); } catch {}
      tcpSocket = null;
    }
  }

  async function processRequest(data: Buffer): Promise<void> {
    // Parse the RDCleanPath Request PDU
    let request: RDCleanPathRequest;
    try {
      request = parseRDCleanPathRequest(data);
    } catch (err) {
      console.error("[RDCleanPath] Failed to parse request:", (err as Error).message);
      sendError(RDCLEANPATH_ERROR_GENERAL, 400);
      return;
    }

    // Validate JWT
    const payload = await opts.verifyToken(request.proxyAuth);
    if (!payload) {
      console.warn("[RDCleanPath] JWT validation failed");
      sendError(RDCLEANPATH_ERROR_GENERAL, 401);
      return;
    }

    // Enforce dest: role
    const backendName = request.destination;
    if (opts.gatewayId) {
      const realmRoles: string[] = (payload as any)?.realm_access?.roles ?? [];
      const clientRoles: string[] = opts.tcClientId
        ? ((payload as any)?.resource_access?.[opts.tcClientId]?.roles ?? [])
        : [];
      const allRoles = [...realmRoles, ...clientRoles];
      const gwIdLower = opts.gatewayId.toLowerCase();
      const backendLower = backendName.toLowerCase();
      const hasAccess = allRoles.some((r: string) => {
        if (!/^dest:/i.test(r)) return false;
        const firstColon = r.indexOf(":");
        const secondColon = r.indexOf(":", firstColon + 1);
        if (secondColon < 0) return false;
        const gwId = r.slice(firstColon + 1, secondColon);
        const bk = r.slice(secondColon + 1);
        return gwId.toLowerCase() === gwIdLower && bk.toLowerCase() === backendLower;
      });
      if (!hasAccess) {
        console.warn(`[RDCleanPath] dest role denied: backend="${backendName}"`);
        sendError(RDCLEANPATH_ERROR_GENERAL, 403);
        return;
      }
    }

    // Resolve backend name → host:port
    const backend = opts.backends.find((b) => b.name === backendName && b.protocol === "rdp");
    if (!backend) {
      console.warn(`[RDCleanPath] No matching RDP backend: "${backendName}"`);
      sendError(RDCLEANPATH_ERROR_GENERAL, 404);
      return;
    }

    let host: string;
    let port: number;
    try {
      const url = new URL(backend.url);
      host = url.hostname;
      port = parseInt(url.port || "3389", 10);
    } catch {
      console.error(`[RDCleanPath] Invalid backend URL: ${backend.url}`);
      sendError(RDCLEANPATH_ERROR_GENERAL, 500);
      return;
    }

    console.log(`[RDCleanPath] Connecting to ${host}:${port} for backend "${backendName}"`);
    state = State.CONNECTING;

    try {
      // Step 1: TCP connect to RDP server
      tcpSocket = await tcpConnect(host, port);

      // Step 2: Send X.224 Connection Request
      tcpSocket.write(request.x224ConnectionPdu);

      // Step 3: Read X.224 Connection Confirm (TPKT-framed)
      const x224Response = await readTpktMessage(tcpSocket);
      console.log(`[RDCleanPath] X.224 response: ${x224Response.length} bytes`);

      // Step 4: TLS handshake with RDP server
      tlsSocket = await tlsUpgrade(tcpSocket, host);

      // Step 5: Extract server certificate chain
      const certChain = extractCertChain(tlsSocket);
      console.log(`[RDCleanPath] TLS complete, ${certChain.length} cert(s) in chain`);

      // CredSSP/NLA with TideSSP via NEGOEX (NegoExtender)
      if (backend.auth === "eddsa") {
        console.log(`[RDCleanPath] Starting CredSSP with TideSSP/NEGOEX for "${backendName}"`);
        state = State.CREDSSP;

        // Extract username from JWT (preferred_username or sub)
        const username = (payload as any).preferred_username || (payload as any).sub;
        if (!username) {
          throw new Error("JWT has no username claim (preferred_username or sub)");
        }

        // Send JWT directly to TideSSP — it verifies the EdDSA signature
        await performCredSSP(tlsSocket, username, request.proxyAuth);

        console.log(`[RDCleanPath] CredSSP/NLA completed for "${backendName}"`);
      }

      // Step 6: Send RDCleanPath Response PDU
      const responsePdu = buildRDCleanPathResponse({
        x224ConnectionPdu: x224Response,
        serverCertChain: certChain,
        serverAddr: host,
      });
      console.log(`[RDCleanPath] Sending response PDU: ${responsePdu.length} bytes`);
      opts.sendBinary(responsePdu);

      // Step 7: Enter relay mode
      state = State.RELAY;
      console.log(`[RDCleanPath] Relay mode active for "${backendName}"`);

      // TLS socket → client
      tlsSocket.on("data", (data: Buffer) => {
        if (state !== State.RELAY) return;
        relayBytesToClient += data.length;
        console.log(`[RDCleanPath] Relay RDP→client: ${data.length} bytes (total: ${relayBytesToClient})`);
        opts.sendBinary(data);
      });

      tlsSocket.on("close", () => {
        console.log(`[RDCleanPath] TLS socket closed for "${backendName}" (state=${state}, toClient=${relayBytesToClient}, fromClient=${relayBytesFromClient})`);
        if (state !== State.RELAY) return;
        cleanup();
        opts.sendClose(1000, "RDP connection closed");
      });

      tlsSocket.on("error", (err: Error) => {
        console.error(`[RDCleanPath] TLS socket error for "${backendName}" (state=${state}): ${err.message}`);
        if (state !== State.RELAY) return;
        cleanup();
        opts.sendClose(1006, "RDP connection error");
      });
    } catch (err) {
      const msg = (err as Error).message || "Connection failed";
      console.error(`[RDCleanPath] Connection failed: ${msg}`);
      // Determine error type
      if (msg.includes("TLS") || msg.includes("tls")) {
        sendError(RDCLEANPATH_ERROR_GENERAL, undefined, undefined, 40);
      } else {
        sendError(RDCLEANPATH_ERROR_GENERAL, undefined, 10061);
      }
    }
  }

  return {
    handleMessage(data: Buffer): void {
      switch (state) {
        case State.AWAITING_REQUEST:
          processRequest(data).catch((err) => {
            console.error("[RDCleanPath] Unhandled error:", err);
            sendError(RDCLEANPATH_ERROR_GENERAL, 500);
          });
          break;

        case State.RELAY:
          // Forward client data to TLS socket
          if (tlsSocket && !tlsSocket.destroyed) {
            relayBytesFromClient += data.length;
            console.log(`[RDCleanPath] Relay client→RDP: ${data.length} bytes (total: ${relayBytesFromClient})`);
            tlsSocket.write(data);
          }
          break;

        case State.CONNECTING:
        case State.CREDSSP:
          // Buffer or drop — client shouldn't send data during handshake
          break;

        case State.CLOSED:
          break;
      }
    },

    close(): void {
      cleanup();
    },
  };
}

// ── TCP helpers ──────────────────────────────────────────────────

function tcpConnect(host: string, port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const sock = netConnect({ host, port, timeout: CONNECT_TIMEOUT });

    sock.on("connect", () => {
      sock.setTimeout(0);
      resolve(sock);
    });

    sock.on("timeout", () => {
      sock.destroy();
      reject(new Error(`TCP connect timeout: ${host}:${port}`));
    });

    sock.on("error", (err: Error) => {
      reject(new Error(`TCP connect error: ${err.message}`));
    });
  });
}

/**
 * Read a TPKT-framed message from a TCP socket.
 * TPKT header: [version=0x03][reserved=0x00][length_hi][length_lo]
 */
function readTpktMessage(sock: Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalLen = 0;
    let expectedLen = 0;

    const timer = setTimeout(() => {
      sock.off("data", onData);
      reject(new Error("X.224 response timeout"));
    }, X224_READ_TIMEOUT);

    function onData(data: Buffer): void {
      chunks.push(data);
      totalLen += data.length;

      if (expectedLen === 0 && totalLen >= 4) {
        const header = Buffer.concat(chunks);
        if (header[0] !== 0x03) {
          clearTimeout(timer);
          sock.off("data", onData);
          reject(new Error(`Not a TPKT header: first byte 0x${header[0].toString(16)}`));
          return;
        }
        expectedLen = header.readUInt16BE(2);
        if (expectedLen < 4 || expectedLen > 512) {
          clearTimeout(timer);
          sock.off("data", onData);
          reject(new Error(`Invalid TPKT length: ${expectedLen}`));
          return;
        }
      }

      if (expectedLen > 0 && totalLen >= expectedLen) {
        clearTimeout(timer);
        sock.off("data", onData);
        resolve(Buffer.concat(chunks).subarray(0, expectedLen));
      }
    }

    sock.on("data", onData);
    sock.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    sock.on("close", () => {
      clearTimeout(timer);
      reject(new Error("Socket closed before X.224 response"));
    });
  });
}

/**
 * Upgrade a TCP socket to TLS (wrapping the existing connection).
 * Uses rejectUnauthorized=false because the RDP server typically
 * uses a self-signed certificate — IronRDP validates it via CredSSP.
 */
function tlsUpgrade(sock: Socket, servername: string): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("TLS handshake timeout"));
    }, TLS_TIMEOUT);

    const tls = tlsConnect({
      socket: sock,
      rejectUnauthorized: false,
      servername,
    }, () => {
      clearTimeout(timer);
      resolve(tls);
    });

    tls.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(new Error(`TLS error: ${err.message}`));
    });
  });
}

/**
 * Extract the TLS certificate chain from a connected TLS socket.
 * Returns an array of DER-encoded X.509 certificates (leaf first).
 */
function extractCertChain(tls: TLSSocket): Buffer[] {
  const chain: Buffer[] = [];
  const seen = new Set<string>();

  let cert = tls.getPeerCertificate(true);
  while (cert && cert.raw) {
    const fp = cert.fingerprint256 || cert.raw.toString("hex").slice(0, 64);
    if (seen.has(fp)) break;
    seen.add(fp);
    chain.push(cert.raw);
    cert = (cert as any).issuerCertificate;
  }

  return chain;
}
