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

import { connect as netConnect, createServer, type Socket, type Server } from "net";
import { connect as tlsConnect, type TLSSocket } from "tls";
import { randomBytes } from "crypto";
import type { JWTPayload } from "jose";
import type { BackendEntry } from "../config.js";
import {
  parseRDCleanPathRequest,
  buildRDCleanPathResponse,
  buildRDCleanPathError,
  RDCLEANPATH_ERROR_GENERAL,
  type RDCleanPathRequest,
} from "./rdcleanpath.js";
import { performCredSSP, type SmartCardInfo } from "./credssp-client.js";
import { buildTbsCertificate, assembleCertificate } from "./cert-builder.js";

// ── Public interface ─────────────────────────────────────────────

export interface RDCleanPathSession {
  /** Handle a binary message from the client */
  handleMessage(data: Buffer): void;
  /** Handle a JSON control message from the browser (signing responses) */
  handleControlMessage(msg: Record<string, unknown>): void;
  /** Close the session */
  close(): void;
}

export interface RDCleanPathSessionOptions {
  /** Virtual WebSocket ID for this session (used for message routing) */
  wsId: string;
  /** Send a binary WS message back to the client */
  sendBinary: (data: Buffer) => void;
  /** Send a JSON control message to the browser (signing requests) */
  sendControl: (msg: Record<string, unknown>) => void;
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

// ── Signing relay: global map of active sessions for CSP → gateway relay ──

interface SigningSession {
  wsId: string;
  sendControl: (msg: Record<string, unknown>) => void;
  /** Resolves when browser sends sc_sign_response */
  pendingSign: Map<string, (signature: Buffer) => void>;
}

const signingRelaySessions = new Map<string, SigningSession>();
let signingRelayServer: Server | null = null;

/**
 * Start the signing relay TCP server (once, shared across sessions).
 * CSP on Windows connects here to relay signing requests to the browser.
 */
export function startSigningRelay(port: number): void {
  if (signingRelayServer) return;

  signingRelayServer = createServer((sock: Socket) => {
    console.log(`[SigningRelay] CSP connected from ${sock.remoteAddress}`);
    let buf: Buffer<ArrayBufferLike> = Buffer.alloc(0);

    sock.on("data", (data: Buffer) => {
      buf = Buffer.concat([buf, data]);
      processRelayMessages(sock, buf);
    });

    sock.on("error", (err) => {
      console.error(`[SigningRelay] Socket error: ${err.message}`);
    });

    sock.on("close", () => {
      console.log("[SigningRelay] CSP disconnected");
    });

    function processRelayMessages(sock: Socket, _buffer: Buffer): void {
      let buffer = _buffer;
      // Wire format: [4 bytes: msg length][1 byte: type][payload]
      while (buffer.length >= 5) {
        const msgLen = buffer.readUInt32LE(0);
        if (buffer.length < 4 + msgLen) break;

        const type = buffer[4];
        const payload = buffer.subarray(5, 4 + msgLen);
        buffer = Buffer.from(buffer.subarray(4 + msgLen));
        buf = buffer;

        if (type === 0x01) {
          // HELLO: [16 bytes session token]
          const token = payload.subarray(0, 16).toString("hex");
          console.log(`[SigningRelay] HELLO from CSP, token=${token}`);
          const session = signingRelaySessions.get(token);
          if (!session) {
            console.warn(`[SigningRelay] No session for token ${token}`);
            sock.destroy();
            return;
          }
          // Store socket reference on the session for sending results back
          (sock as any)._signingSession = session;
          // ACK
          const ack = Buffer.alloc(5);
          ack.writeUInt32LE(1, 0);
          ack[4] = 0x04; // ACK type
          sock.write(ack);
        } else if (type === 0x02) {
          // SIGN: [4 bytes hash length][hash bytes][4 bytes algId]
          const session = (sock as any)._signingSession as SigningSession | undefined;
          if (!session) {
            console.warn("[SigningRelay] SIGN without HELLO");
            sock.destroy();
            return;
          }
          const hashLen = payload.readUInt32LE(0);
          const hash = payload.subarray(4, 4 + hashLen);
          const algId = payload.readUInt32LE(4 + hashLen);
          const requestId = randomBytes(8).toString("hex");
          console.log(`[SigningRelay] SIGN request: hashLen=${hashLen}, algId=${algId}, id=${requestId}`);

          // Send to browser
          session.sendControl({
            type: "sc_sign_request",
            id: requestId,
            wsId: session.wsId,
            hash: hash.toString("base64"),
            algorithm: algId === 0x800c ? "SHA-256" : "SHA-1",
          });

          // Wait for browser response
          session.pendingSign.set(requestId, (signature: Buffer) => {
            // Send RESULT back to CSP: [4 bytes msg length][0x03][4 bytes sig length][sig]
            const result = Buffer.alloc(4 + 1 + 4 + signature.length);
            result.writeUInt32LE(1 + 4 + signature.length, 0);
            result[4] = 0x03; // RESULT type
            result.writeUInt32LE(signature.length, 5);
            signature.copy(result, 9);
            sock.write(result);
            console.log(`[SigningRelay] Sent signature (${signature.length}b) to CSP`);
          });
        }
      }
    }
  });

  signingRelayServer.listen(port, "0.0.0.0", () => {
    console.log(`[SigningRelay] Listening on port ${port}`);
  });
}

export function createRDCleanPathSession(opts: RDCleanPathSessionOptions): RDCleanPathSession {
  let state = State.AWAITING_REQUEST;
  let tcpSocket: Socket | null = null;
  let tlsSocket: TLSSocket | null = null;
  let relayBytesToClient = 0;
  let relayBytesFromClient = 0;
  let mcsPatchProtocol = 0; // eddsa: original selectedProtocol to restore in MCS

  // Pending control message resolvers (keyed by request type + id)
  const pendingControlResponses = new Map<string, (msg: Record<string, unknown>) => void>();
  // Signing relay session (registered when smart card mode is active)
  let signingSessionToken: string | null = null;
  const pendingSignCallbacks = new Map<string, (signature: Buffer) => void>();

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
      // Only set RESTRICTED_ADMIN flag if NOT using smart card mode.
      // Smart card mode uses TSSmartCardCreds (credType=2) for desktop logon,
      // which doesn't require local admin membership.
      if (backend.auth === "eddsa" && !backend.scRelayPort) {
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

        // ── Smart Card: certificate exchange with browser ──
        // Request the browser to generate RSA key pair and sign a certificate.
        let smartCardInfo: SmartCardInfo | undefined;

        const scSessionToken = randomBytes(16);
        const requestId = randomBytes(8).toString("hex");

        // 1. Send cert_sign_request: ask browser to generate RSA key + sign TBSCertificate
        //    We first need the browser's public key, so we ask it to generate and send back.
        console.log(`[RDCleanPath] Requesting browser RSA key + certificate signature (id=${requestId})`);

        // Extract username from JWT for CN in certificate
        const jwtPayload = JSON.parse(Buffer.from(request.proxyAuth.split(".")[1], "base64url").toString());
        const certUsername = jwtPayload.preferred_username || jwtPayload.sub || "user";

        // Ask browser to generate key pair and send public key + sign TBSCertificate
        // We send a two-phase request: first get the public key, then send TBSCert for signing
        const certSignPromise = new Promise<{ signature: Buffer; publicKey: Buffer }>((resolve, reject) => {
          const timeout = setTimeout(() => {
            pendingControlResponses.delete(`cert_sign_response:${requestId}`);
            reject(new Error("Browser certificate signing timeout"));
          }, 15_000);

          pendingControlResponses.set(`cert_sign_response:${requestId}`, (msg) => {
            clearTimeout(timeout);
            resolve({
              signature: Buffer.from(msg.signature as string, "base64"),
              publicKey: Buffer.from(msg.publicKey as string, "base64"),
            });
          });
        });

        // Tell the browser to generate an RSA key pair and send back the public key
        // The browser will generate the key, build the TBSCert client-side,
        // and sign it — but we need to build TBSCert on the gateway side.
        // So we do a two-step: first ask for publicKey, then send tbsCert for signing.
        // Simplification: send username + sessionToken, browser generates key,
        // gateway builds tbsCert from publicKey, sends it back for signing.
        opts.sendControl({
          type: "sc_keygen_request",
          id: requestId,
          wsId: opts.wsId,
          username: certUsername,
        });

        // Wait for browser to send back its public key
        const keygenPromise = new Promise<Buffer>((resolve, reject) => {
          const timeout = setTimeout(() => {
            pendingControlResponses.delete(`sc_keygen_response:${requestId}`);
            reject(new Error("Browser keygen timeout"));
          }, 10_000);

          pendingControlResponses.set(`sc_keygen_response:${requestId}`, (msg) => {
            clearTimeout(timeout);
            resolve(Buffer.from(msg.publicKey as string, "base64"));
          });
        });

        const browserPublicKey = await keygenPromise;
        console.log(`[RDCleanPath] Got browser RSA public key: ${browserPublicKey.length} bytes`);

        // Build TBSCertificate with the browser's public key
        const tbsCert = buildTbsCertificate(certUsername, browserPublicKey);
        console.log(`[RDCleanPath] Built TBSCertificate: ${tbsCert.length} bytes`);

        // Send TBSCertificate to browser for signing
        opts.sendControl({
          type: "cert_sign_request",
          id: requestId,
          wsId: opts.wsId,
          tbsCert: tbsCert.toString("base64"),
        });

        const { signature: certSig, publicKey: _pk } = await certSignPromise;
        console.log(`[RDCleanPath] Got browser certificate signature: ${certSig.length} bytes`);

        // Assemble full X.509 certificate
        const certificate = assembleCertificate(tbsCert, certSig);
        console.log(`[RDCleanPath] Assembled certificate: ${certificate.length} bytes`);

        smartCardInfo = { certificate, sessionToken: scSessionToken };

        // Register signing relay session for CSP connections
        signingSessionToken = scSessionToken.toString("hex");
        signingRelaySessions.set(signingSessionToken, {
          wsId: opts.wsId,
          sendControl: opts.sendControl,
          pendingSign: pendingSignCallbacks,
        });
        console.log(`[RDCleanPath] Registered signing relay session: ${signingSessionToken}`);

        // Send JWT + certificate to TideSSP via NEGOEX
        await performCredSSP(tlsSocket, request.proxyAuth, smartCardInfo);

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

    handleControlMessage(msg: Record<string, unknown>): void {
      const msgType = msg.type as string;
      const msgId = msg.id as string;

      if (msgType === "sc_keygen_response" && msgId) {
        const key = `sc_keygen_response:${msgId}`;
        const resolver = pendingControlResponses.get(key);
        if (resolver) {
          pendingControlResponses.delete(key);
          resolver(msg);
        }
      } else if (msgType === "cert_sign_response" && msgId) {
        const key = `cert_sign_response:${msgId}`;
        const resolver = pendingControlResponses.get(key);
        if (resolver) {
          pendingControlResponses.delete(key);
          resolver(msg);
        }
      } else if (msgType === "sc_sign_response" && msgId) {
        // Route to signing relay callback
        const sigB64 = msg.signature as string;
        const sigBuf = Buffer.from(sigB64, "base64");
        const cb = pendingSignCallbacks.get(msgId);
        if (cb) {
          pendingSignCallbacks.delete(msgId);
          cb(sigBuf);
        }
      }
    },

    close(): void {
      // Unregister signing relay session
      if (signingSessionToken) {
        signingRelaySessions.delete(signingSessionToken);
        signingSessionToken = null;
      }
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
