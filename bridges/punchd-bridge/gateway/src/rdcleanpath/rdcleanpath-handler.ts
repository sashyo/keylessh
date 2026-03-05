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
  let mcsPatchProtocol = 0; // eddsa: original selectedProtocol to restore in MCS

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
      // For eddsa backends, set RESTRICTED_ADMIN_MODE_REQUIRED flag so termsrv
      // uses the NLA token directly (no password re-auth with MSV1_0).
      if (backend.auth === "eddsa") {
        patchX224RestrictedAdmin(request.x224ConnectionPdu);
      }
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

        // Send JWT directly to TideSSP — it verifies the EdDSA signature.
        // Username is extracted by TideSSP during NLA and stored in the session map;
        // LogonUserEx2 looks it up by session key during desktop logon.
        await performCredSSP(tlsSocket, request.proxyAuth);

        console.log(`[RDCleanPath] CredSSP/NLA completed for "${backendName}" at ${Date.now()}`);

        // Read and consume the 4-byte Early User Authorization Result PDU
        // (MS-RDPBCGR §2.2.10.2) — sent by the server after NLA completes.
        const authResult = await readExactBytes(tlsSocket, 4);
        const authValue = authResult.readUInt32LE(0);
        const pendingAfterAuth = tlsSocket.readableLength;
        console.log(`[RDCleanPath] Early User Auth Result: 0x${authValue.toString(16).padStart(8, "0")} at ${Date.now()}, pendingBytes=${pendingAfterAuth}, destroyed=${tlsSocket.destroyed}`);
        if (authValue !== 0x00000000) {
          throw new Error(`Early User Authorization denied: 0x${authValue.toString(16).padStart(8, "0")}`);
        }

        // Probe: wait 50ms to detect if server disconnects after auth result
        // (before we send MCS). If server RSTs here, the issue is server-side.
        const tls = tlsSocket!;
        const probeResult = await new Promise<string>((resolve) => {
          const timer = setTimeout(() => {
            tls.off("data", onProbeData);
            tls.off("error", onProbeErr);
            resolve("stable");
          }, 50);
          function onProbeData(chunk: Buffer) {
            clearTimeout(timer);
            tls.off("error", onProbeErr);
            tls.unshift(chunk);
            resolve(`server_data:${chunk.length}b:${chunk.subarray(0, 16).toString("hex")}`);
          }
          function onProbeErr(err: Error) {
            clearTimeout(timer);
            tls.off("data", onProbeData);
            resolve(`error:${err.message}`);
          }
          tls.on("data", onProbeData);
          tls.on("error", onProbeErr);
        });
        console.log(`[RDCleanPath] Post-auth probe (50ms): ${probeResult} at ${Date.now()}`);
        if (probeResult.startsWith("error:")) {
          throw new Error(`Server disconnected after successful auth: ${probeResult}`);
        }

        // Save original selectedProtocol, then patch to PROTOCOL_SSL so IronRDP
        // skips NLA (we already did it). We'll restore the real value in MCS later.
        if (x224Response.length >= 19) {
          mcsPatchProtocol = x224Response.readUInt32LE(15);
          console.log(`[RDCleanPath] Original X.224 selectedProtocol=${mcsPatchProtocol} (0x${mcsPatchProtocol.toString(16)})`);
          x224Response[15] = 0x01; // PROTOCOL_SSL
          x224Response[16] = 0x00;
          x224Response[17] = 0x00;
          x224Response[18] = 0x00;
          console.log(`[RDCleanPath] Patched X.224 to PROTOCOL_SSL, will restore ${mcsPatchProtocol} in MCS`);
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
      console.log(`[RDCleanPath] Relay mode active for "${backendName}" at ${Date.now()}`);

      // Monitor underlying TCP socket for errors (before TLS reports them)
      if (tcpSocket) {
        tcpSocket.on("error", (err: Error) => {
          console.error(`[RDCleanPath] TCP socket error for "${backendName}": ${err.message} at ${Date.now()}`);
        });
        tcpSocket.on("close", (hadError: boolean) => {
          console.log(`[RDCleanPath] TCP socket closed for "${backendName}" (hadError=${hadError}) at ${Date.now()}`);
        });
        tcpSocket.on("end", () => {
          console.log(`[RDCleanPath] TCP socket end for "${backendName}" at ${Date.now()}`);
        });
      }

      // TLS socket → client
      tlsSocket.on("data", (data: Buffer) => {
        if (state !== State.RELAY) return;
        relayBytesToClient += data.length;
        const hex = data.subarray(0, Math.min(64, data.length)).toString("hex");
        console.log(`[RDCleanPath] Relay RDP→client: ${data.length} bytes (total: ${relayBytesToClient}) hex: ${hex} at ${Date.now()}`);
        opts.sendBinary(data);
      });

      tlsSocket.on("close", () => {
        console.log(`[RDCleanPath] TLS socket closed for "${backendName}" (state=${state}, toClient=${relayBytesToClient}, fromClient=${relayBytesFromClient}) at ${Date.now()}`);
        if (state !== State.RELAY) return;
        cleanup();
        opts.sendClose(1000, "RDP connection closed");
      });

      tlsSocket.on("end", () => {
        console.log(`[RDCleanPath] TLS socket end (graceful) for "${backendName}" at ${Date.now()}`);
      });

      tlsSocket.on("error", (err: Error) => {
        console.error(`[RDCleanPath] TLS socket error for "${backendName}" (state=${state}): ${err.message} at ${Date.now()}`);
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
            // For eddsa: patch serverSelectedProtocol in first MCS Connect Initial.
            // IronRDP wrote PROTOCOL_SSL(1) because we patched X.224; restore original value.
            if (mcsPatchProtocol > 0) {
              const proto = mcsPatchProtocol;
              mcsPatchProtocol = 0;
              // Log first relay message type
              const firstByte = data[0];
              if (firstByte === 0x03) {
                console.log(`[RDCleanPath] First relay: TPKT/MCS (${data.length} bytes)`);
              } else if (firstByte === 0x30) {
                console.log(`[RDCleanPath] First relay: ASN.1/CredSSP (${data.length} bytes) — unexpected!`);
              } else {
                console.log(`[RDCleanPath] First relay: unknown 0x${firstByte.toString(16)} (${data.length} bytes)`);
              }
              // Full hex dump for diagnosis
              for (let off = 0; off < data.length; off += 48) {
                const slice = data.subarray(off, Math.min(off + 48, data.length));
                console.log(`[RDCleanPath]   +${off.toString().padStart(3, "0")}: ${slice.toString("hex")}`);
              }
              patchMcsSelectedProtocol(data, proto);
              decodeMcsConnectInitial(data);
            }
            relayBytesFromClient += data.length;
            console.log(`[RDCleanPath] Relay client→RDP: ${data.length} bytes (total: ${relayBytesFromClient}), tls: readable=${tlsSocket.readable} writable=${tlsSocket.writable} at ${Date.now()}`);
            const writeOk = tlsSocket.write(data);
            console.log(`[RDCleanPath] tlsSocket.write returned ${writeOk} at ${Date.now()}`);
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
 * Any extra bytes received beyond `n` are pushed back into the stream
 * via unshift() so they are not lost.
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
        const full = Buffer.concat(chunks);
        if (full.length > n) {
          const extra = full.subarray(n);
          console.log(`[RDCleanPath] readExactBytes: got ${full.length} bytes, wanted ${n}, pushing back ${extra.length} extra bytes: ${extra.toString("hex")}`);
          sock.unshift(extra);
        }
        resolve(full.subarray(0, n));
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
 * Patch X.224 Connection Request to set RESTRICTED_ADMIN_MODE_REQUIRED flag.
 *
 * RDP_NEG_REQ (8 bytes at end of X.224 CR):
 *   [type=0x01] [flags] [length=0x08,0x00] [requestedProtocols (4 bytes LE)]
 *
 * Flag 0x01 = RESTRICTED_ADMIN_MODE_REQUIRED — tells termsrv to use the NLA
 * token (SECPKG_ATTR_ACCESS_TOKEN) directly for the desktop session instead
 * of re-authenticating with MSV1_0 + password from TSCredentials.
 */
function patchX224RestrictedAdmin(pdu: Buffer): void {
  // RDP_NEG_REQ is the last 8 bytes of the X.224 Connection Request.
  // Identify by type=0x01 and length=0x0008.
  for (let i = pdu.length - 8; i >= 4; i--) {
    if (pdu[i] === 0x01 && pdu[i + 2] === 0x08 && pdu[i + 3] === 0x00) {
      const oldFlags = pdu[i + 1];
      pdu[i + 1] = oldFlags | 0x01; // RESTRICTED_ADMIN_MODE_REQUIRED
      console.log(`[RDCleanPath] Set RESTRICTED_ADMIN flag in X.224 CR (offset ${i}, flags: 0x${oldFlags.toString(16)} → 0x${pdu[i + 1].toString(16)})`);
      return;
    }
  }
  console.warn("[RDCleanPath] Could not find RDP_NEG_REQ in X.224 Connection Request");
}

/**
 * Patch the serverSelectedProtocol field in an MCS Connect Initial PDU.
 *
 * IronRDP writes PROTOCOL_SSL(1) because we patched X.224, but the RDP server
 * expects the original value (e.g. PROTOCOL_HYBRID_EX=8). This finds CS_CORE
 * and overwrites serverSelectedProtocol at offset 212 within the block.
 */
function patchMcsSelectedProtocol(data: Buffer, targetProtocol: number): void {
  for (let i = 7; i < data.length - 216; i++) {
    if (data[i] === 0x01 && data[i + 1] === 0xC0) {
      const blockLen = data.readUInt16LE(i + 2);
      if (blockLen >= 216 && blockLen < 1024 && i + blockLen <= data.length) {
        const spOffset = i + 212;
        const current = data.readUInt32LE(spOffset);
        console.log(`[RDCleanPath] CS_CORE at offset ${i}, len=${blockLen}, serverSelectedProtocol=${current}`);
        if (current !== targetProtocol) {
          data.writeUInt32LE(targetProtocol, spOffset);
          console.log(`[RDCleanPath] Patched MCS serverSelectedProtocol: ${current}→${targetProtocol} (0x${targetProtocol.toString(16)})`);
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
  // Find H.221 non-standard key "Duca" (Microsoft) in GCC Conference Create Request
  let ducaPos = -1;
  for (let i = 7; i < data.length - 6; i++) {
    if (data[i] === 0x44 && data[i + 1] === 0x75 && data[i + 2] === 0x63 && data[i + 3] === 0x61) {
      ducaPos = i;
      break;
    }
  }
  if (ducaPos < 0) {
    console.log("[RDCleanPath] MCS decode: H.221 key 'Duca' not found");
    return;
  }

  // After "Duca", read PER-encoded length of user data
  let udStart = ducaPos + 4;
  const lenByte = data[udStart];
  let udLen: number;
  if (lenByte < 0x80) {
    udLen = lenByte;
    udStart += 1;
  } else {
    // Two-byte PER length: (first & 0x3F) << 8 | second
    udLen = ((lenByte & 0x3F) << 8) | data[udStart + 1];
    udStart += 2;
  }
  console.log(`[RDCleanPath] MCS decode: Duca at ${ducaPos}, userdata: offset=${udStart}, len=${udLen}`);

  // Parse user data blocks
  let pos = udStart;
  const udEnd = Math.min(udStart + udLen, data.length);
  while (pos + 4 <= udEnd) {
    const type = data.readUInt16LE(pos);
    const len = data.readUInt16LE(pos + 2);
    if (len < 4 || pos + len > udEnd) break;
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
    console.log(`[RDCleanPath] MCS block: ${typeName} (type=0x${type.toString(16)}, len=${len}, offset=${pos})`);

    if (type === 0xC001) {
      // CS_CORE details — offsets relative to data start (pos+4)
      const d = pos + 4;
      const dLen = len - 4;
      const ver = data.readUInt32LE(d);
      const width = data.readUInt16LE(d + 4);
      const height = data.readUInt16LE(d + 6);
      const colorDepth = data.readUInt16LE(d + 8);
      const sasSeq = data.readUInt16LE(d + 10);
      const kbLayout = data.readUInt32LE(d + 12);
      const clientBuild = data.readUInt32LE(d + 16);
      const clientName = data.subarray(d + 20, d + 52).toString("utf16le").replace(/\0+$/, "");
      console.log(`[RDCleanPath]   ver=0x${ver.toString(16)}, ${width}x${height}, color=0x${colorDepth.toString(16)}, sas=0x${sasSeq.toString(16)}`);
      console.log(`[RDCleanPath]   kbLayout=0x${kbLayout.toString(16)}, build=${clientBuild}, client="${clientName}"`);
      if (dLen >= 140) console.log(`[RDCleanPath]   highColor=${data.readUInt16LE(d + 136)}, supportedDepths=0x${data.readUInt16LE(d + 138).toString(16)}`);
      if (dLen >= 142) console.log(`[RDCleanPath]   earlyCapFlags=0x${data.readUInt16LE(d + 140).toString(16)}`);
      if (dLen >= 208) console.log(`[RDCleanPath]   connectionType=${data[d + 206]}`);
      if (dLen >= 212) console.log(`[RDCleanPath]   serverSelectedProtocol=${data.readUInt32LE(d + 208)}`);
    }

    if (type === 0xC002) {
      const encMethods = data.readUInt32LE(pos + 4);
      const extEncMethods = len >= 12 ? data.readUInt32LE(pos + 8) : 0;
      console.log(`[RDCleanPath]   encMethods=0x${encMethods.toString(16)}, extEncMethods=0x${extEncMethods.toString(16)}`);
    }

    if (type === 0xC003 && len >= 8) {
      console.log(`[RDCleanPath]   channelCount=${data.readUInt32LE(pos + 4)}`);
    }

    pos += len;
  }
  console.log(`[RDCleanPath] MCS decode: ${pos - udStart}/${udLen} bytes parsed`);
}
