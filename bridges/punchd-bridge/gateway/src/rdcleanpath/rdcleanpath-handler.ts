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
  let needsMcsPatch = false; // eddsa: patch first relay message

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

        // Read and consume the 4-byte Early User Authorization Result PDU
        // (MS-RDPBCGR §2.2.10.2) — sent by the server after NLA completes.
        const authResult = await readExactBytes(tlsSocket, 4);
        const authValue = authResult.readUInt32LE(0);
        console.log(`[RDCleanPath] Early User Auth Result: 0x${authValue.toString(16).padStart(8, "0")}`);
        if (authValue !== 0x00000000) {
          throw new Error(`Early User Authorization denied: 0x${authValue.toString(16).padStart(8, "0")}`);
        }

        // Modify X.224 selectedProtocol from PROTOCOL_HYBRID (2) to
        // PROTOCOL_SSL (1) so IronRDP skips NLA (we already did it).
        // selectedProtocol is at byte offset 15 (LE uint32).
        if (x224Response.length >= 19) {
          x224Response[15] = 0x01; // PROTOCOL_SSL
          x224Response[16] = 0x00;
          x224Response[17] = 0x00;
          x224Response[18] = 0x00;
          console.log(`[RDCleanPath] Patched X.224 selectedProtocol to PROTOCOL_SSL`);
          needsMcsPatch = true; // need to fix serverSelectedProtocol in first MCS message
        }
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
        const hex = data.subarray(0, Math.min(64, data.length)).toString("hex");
        console.log(`[RDCleanPath] Relay RDP→client: ${data.length} bytes (total: ${relayBytesToClient}) hex: ${hex}`);
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
            // For eddsa: patch serverSelectedProtocol in the first MCS Connect Initial
            // We changed X.224 selectedProtocol to PROTOCOL_SSL (1) so IronRDP skips NLA,
            // but IronRDP echoes that value in MCS CS_CORE. The server expects PROTOCOL_HYBRID (2).
            if (needsMcsPatch) {
              needsMcsPatch = false;
              // Log full MCS hex before patching for diagnosis
              console.log(`[RDCleanPath] MCS Connect Initial BEFORE patch (${data.length} bytes):`);
              for (let off = 0; off < data.length; off += 48) {
                const slice = data.subarray(off, Math.min(off + 48, data.length));
                console.log(`[RDCleanPath]   +${off.toString().padStart(3, "0")}: ${slice.toString("hex")}`);
              }
              patchMcsSelectedProtocol(data);
              decodeMcsConnectInitial(data);
            }
            relayBytesFromClient += data.length;
            console.log(`[RDCleanPath] Relay client→RDP: ${data.length} bytes (total: ${relayBytesFromClient}), tls: readable=${tlsSocket.readable} writable=${tlsSocket.writable}`);
            const writeOk = tlsSocket.write(data);
            console.log(`[RDCleanPath] tlsSocket.write returned ${writeOk}`);
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

/**
 * Read exactly `n` bytes from a TLS socket.
 */
function readExactBytes(sock: TLSSocket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let got = 0;

    const timer = setTimeout(() => {
      sock.off("data", onData);
      reject(new Error(`readExactBytes timeout (wanted ${n}, got ${got})`));
    }, X224_READ_TIMEOUT);

    function onData(data: Buffer): void {
      chunks.push(data);
      got += data.length;
      if (got >= n) {
        clearTimeout(timer);
        sock.off("data", onData);
        resolve(Buffer.concat(chunks).subarray(0, n));
      }
    }

    sock.on("data", onData);
    sock.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    sock.on("close", () => {
      clearTimeout(timer);
      reject(new Error(`Socket closed (wanted ${n} bytes, got ${got})`));
    });
  });
}

/**
 * Patch the serverSelectedProtocol field in an MCS Connect Initial PDU.
 *
 * After eddsa NLA, we patched X.224 selectedProtocol to PROTOCOL_SSL (1)
 * so IronRDP skips NLA. But IronRDP echoes this value in the CS_CORE
 * block of the MCS Connect Initial. The RDP server validates it against
 * the original PROTOCOL_HYBRID (2) it sent, and disconnects on mismatch.
 *
 * CS_CORE layout: type(2) + length(2) + fixed fields(128) + optional fields.
 * serverSelectedProtocol is at byte offset 212 within CS_CORE, present
 * when block length >= 216.
 */
function patchMcsSelectedProtocol(data: Buffer): void {
  // Search for CS_CORE header: type 0xC001 (LE: 01 C0)
  for (let i = 7; i < data.length - 216; i++) {
    if (data[i] === 0x01 && data[i + 1] === 0xC0) {
      const blockLen = data.readUInt16LE(i + 2);
      if (blockLen >= 216 && blockLen < 1024 && i + blockLen <= data.length) {
        // serverSelectedProtocol is at offset 212 within CS_CORE
        const spOffset = i + 212;
        const current = data.readUInt32LE(spOffset);
        console.log(`[RDCleanPath] CS_CORE at offset ${i}, len=${blockLen}, serverSelectedProtocol=${current}`);
        if (current === 0x01) { // PROTOCOL_SSL
          data.writeUInt32LE(0x02, spOffset); // PROTOCOL_HYBRID
          console.log(`[RDCleanPath] Patched MCS serverSelectedProtocol: SSL(1)→HYBRID(2)`);
        }
        return;
      }
    }
  }
  console.warn("[RDCleanPath] Could not find CS_CORE in MCS Connect Initial");
}

/**
 * Decode and log the GCC user data blocks from an MCS Connect Initial PDU.
 * Helps diagnose what IronRDP is sending vs what the server expects.
 */
function decodeMcsConnectInitial(data: Buffer): void {
  // Find GCC Conference Create Request inside MCS Connect Initial
  // Look for the T.124 GCC key: 00 05 00 14 7c 00 01
  const gccKey = Buffer.from([0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01]);
  let gccPos = -1;
  for (let i = 7; i < data.length - gccKey.length; i++) {
    if (data.subarray(i, i + gccKey.length).equals(gccKey)) {
      gccPos = i;
      break;
    }
  }
  if (gccPos < 0) {
    console.log("[RDCleanPath] MCS decode: GCC key not found");
    return;
  }
  console.log(`[RDCleanPath] MCS decode: GCC key at offset ${gccPos}`);

  // Skip past GCC header to find user data blocks
  // After the GCC key, there's conference name + PER-encoded user data
  // Look for the first CS_ block header (0xC0xx LE)
  let udPos = -1;
  for (let i = gccPos + gccKey.length; i < data.length - 4; i++) {
    if (data[i + 1] === 0xC0 && data[i] >= 0x01 && data[i] <= 0x0A) {
      udPos = i;
      break;
    }
  }
  if (udPos < 0) {
    console.log("[RDCleanPath] MCS decode: no user data blocks found");
    return;
  }

  // Parse user data blocks
  let pos = udPos;
  while (pos + 4 <= data.length) {
    const type = data.readUInt16LE(pos);
    const len = data.readUInt16LE(pos + 2);
    if (len < 4 || pos + len > data.length) break;
    const typeName =
      type === 0xC001 ? "CS_CORE" :
      type === 0xC002 ? "CS_SECURITY" :
      type === 0xC003 ? "CS_NET" :
      type === 0xC004 ? "CS_CLUSTER" :
      type === 0xC005 ? "CS_MONITOR" :
      type === 0xC006 ? "CS_MCS_MSGCHANNEL" :
      type === 0xC008 ? "CS_MONITOR_EX" :
      type === 0xC00A ? "CS_MULTITRANSPORT" :
      `0x${type.toString(16)}`;
    console.log(`[RDCleanPath] MCS block: ${typeName} (type=0x${type.toString(16)}, len=${len})`);

    if (type === 0xC001 && len >= 216) {
      // CS_CORE details
      const ver = data.readUInt32LE(pos + 4);
      const width = data.readUInt16LE(pos + 8);
      const height = data.readUInt16LE(pos + 10);
      const colorDepth = data.readUInt16LE(pos + 12);
      const sasSeq = data.readUInt16LE(pos + 14);
      const kbLayout = data.readUInt32LE(pos + 16);
      const clientBuild = data.readUInt32LE(pos + 20);
      // clientName is at offset 28 (24 bytes from pos+4), 32 bytes UTF-16LE
      const clientName = data.subarray(pos + 28, pos + 60).toString("utf16le").replace(/\0+$/, "");
      const earlyCapFlags = len >= 212 ? data.readUInt32LE(pos + 200) : 0;
      const selProto = len >= 216 ? data.readUInt32LE(pos + 212) : -1;
      console.log(`[RDCleanPath]   CS_CORE: ver=0x${ver.toString(16)}, ${width}x${height}, colorDepth=${colorDepth}, sas=${sasSeq}`);
      console.log(`[RDCleanPath]   CS_CORE: kbLayout=0x${kbLayout.toString(16)}, build=${clientBuild}, client="${clientName}"`);
      console.log(`[RDCleanPath]   CS_CORE: earlyCapFlags=0x${earlyCapFlags.toString(16)}, serverSelectedProtocol=${selProto}`);
    }

    if (type === 0xC002) {
      // CS_SECURITY
      const encMethods = data.readUInt32LE(pos + 4);
      const extEncMethods = len >= 12 ? data.readUInt32LE(pos + 8) : 0;
      console.log(`[RDCleanPath]   CS_SECURITY: encMethods=0x${encMethods.toString(16)}, extEncMethods=0x${extEncMethods.toString(16)}`);
    }

    pos += len;
  }
}
