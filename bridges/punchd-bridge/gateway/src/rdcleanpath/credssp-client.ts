/**
 * CredSSP client for TideSSP JWT authentication via NEGOEX.
 *
 * Performs NLA (Network Level Authentication) with the RDP server using
 * NegoExtender (MS-NEGOEX) to carry TideSSP tokens through SPNEGO.
 *
 * The gateway sends the user's JWT directly — TideSSP verifies the EdDSA
 * signature against its hardcoded JWK public key. No browser interaction
 * needed during CredSSP.
 *
 * Protocol flow:
 * 1. Client → Server: TSRequest with SPNEGO NegTokenInit { NEGOEX OID,
 *    NEGOEX[INITIATOR_NEGO + AP_REQUEST(TOKEN_JWT)] }
 * 2. Server → Client: TSRequest with SPNEGO NegTokenResp { NEGOEX[ACCEPTOR_NEGO
 *    + VERIFY] }  — auth complete in one round
 * 3. Client → Server: TSRequest with SPNEGO NegTokenResp { NEGOEX[VERIFY] }
 * 4. Server → Client: TSRequest confirming SPNEGO complete
 * 5. Client → Server: TSRequest with pubKeyAuth (TLS binding)
 * 6. Server → Client: TSRequest with pubKeyAuth confirmation
 * 7. Client → Server: TSRequest with authInfo (credentials blob)
 */

import type { TLSSocket } from "tls";
import {
  encodeSequence,
  encodeExplicit,
  encodeInteger,
  encodeOctetString,
  encodeTlv,
  DerReader,
  TAG_SEQUENCE,
  contextTag,
} from "./der-codec.js";
import {
  buildNegoMessage,
  buildExchangeMessage,
  buildVerifyMessage,
  parseNegoexMessages,
  deriveSessionKeyFromJwt,
  computeVerifyChecksum,
  generateConversationId,
  NEGOEX_OID,
  TIDESSP_AUTH_SCHEME,
  MSG_INITIATOR_NEGO,
  MSG_AP_REQUEST,
  MSG_VERIFY,
  MSG_CHALLENGE,
} from "./negoex.js";

// ── TideSSP Token Types ─────────────────────────────────────────

const TOKEN_JWT = 0x04;

// ── SPNEGO OIDs ─────────────────────────────────────────────────

// SPNEGO: 1.3.6.1.5.5.2
const SPNEGO_OID = Buffer.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);

// ── CredSSP Constants ───────────────────────────────────────────

const CREDSSP_VERSION = 6; // CredSSP v6

// ── Main entry point ────────────────────────────────────────────

/**
 * Perform CredSSP/NLA authentication with a TLS-wrapped RDP server
 * using NEGOEX to carry TideSSP JWT token through SPNEGO.
 *
 * @param tlsSocket - TLS socket connected to the RDP server
 * @param username - Windows username for the logon session
 * @param jwt - JWT token (EdDSA-signed) to send to TideSSP for verification
 */
export async function performCredSSP(
  tlsSocket: TLSSocket,
  username: string,
  jwt: string,
): Promise<void> {
  // NEGOEX state
  const conversationId = generateConversationId();
  let seqNum = 0;
  const transcript: Buffer[] = []; // all NEGOEX messages for VERIFY checksum

  // ── Step 1: Send INITIATOR_NEGO + optimistic AP_REQUEST(JWT) ──

  const negoMsg = buildNegoMessage(
    MSG_INITIATOR_NEGO,
    conversationId,
    seqNum++,
    [TIDESSP_AUTH_SCHEME],
  );

  // Build JWT token: [0x04][JWT ASCII bytes]
  const jwtBytes = Buffer.from(jwt, "ascii");
  const jwtToken = Buffer.alloc(1 + jwtBytes.length);
  jwtToken[0] = TOKEN_JWT;
  jwtBytes.copy(jwtToken, 1);

  const apReqMsg = buildExchangeMessage(
    MSG_AP_REQUEST,
    conversationId,
    seqNum++,
    TIDESSP_AUTH_SCHEME,
    jwtToken,
  );

  // Concatenate both NEGOEX messages in one SPNEGO mechToken
  const initNegoex = Buffer.concat([negoMsg, apReqMsg]);
  transcript.push(negoMsg, apReqMsg);

  const spnegoInit = buildSpnegoInit(initNegoex);
  console.log(`[CredSSP] NEGOEX INITIATOR_NEGO + AP_REQUEST(JWT): ${initNegoex.length} bytes`);
  const tsReq1 = buildTSRequest(CREDSSP_VERSION, spnegoInit);
  tlsSocket.write(tsReq1);
  console.log("[CredSSP] Sent NEGOEX INITIATOR_NEGO + AP_REQUEST(JWT)");

  // ── Step 2: Read server response ──

  const tsResp1 = await readTSRequest(tlsSocket);
  console.log(`[CredSSP] Server TSRequest: version=${tsResp1.version}, hasNegoToken=${!!tsResp1.negoToken}, errorCode=${tsResp1.errorCode ?? "none"}`);
  if (tsResp1.errorCode) {
    throw new Error(`CredSSP: server error 0x${tsResp1.errorCode.toString(16)} (${tsResp1.errorCode})`);
  }

  const serverSpnego1 = extractNegoToken(tsResp1);
  if (!serverSpnego1) {
    throw new Error("CredSSP: no negoToken in server response");
  }

  const serverNegoex1 = extractSpnegoMechToken(serverSpnego1);
  if (!serverNegoex1 || serverNegoex1.length < 40) {
    throw new Error("CredSSP: invalid NEGOEX response from server");
  }

  // Record server's NEGOEX messages in transcript
  transcript.push(serverNegoex1);

  const serverMsgs1 = parseNegoexMessages(serverNegoex1);
  console.log(`[CredSSP] Server sent ${serverMsgs1.length} NEGOEX message(s): types=[${serverMsgs1.map(m => m.messageType).join(", ")}]`);

  // Use conversation ID from server
  const serverConvId = serverMsgs1[0]?.conversationId;
  if (serverConvId) {
    serverConvId.copy(conversationId);
  }

  // Check if server sent VERIFY (JWT accepted, single round) or CHALLENGE (fallback)
  const serverVerify1 = serverMsgs1.find(m => m.messageType === MSG_VERIFY);
  const serverChallenge = serverMsgs1.find(m => m.messageType === MSG_CHALLENGE);

  if (serverChallenge?.exchange) {
    // Server sent CHALLENGE — this shouldn't happen with JWT flow
    throw new Error("CredSSP: server sent CHALLENGE — expected JWT to be verified in single round");
  }

  // ── Step 3: Derive session key and send client VERIFY ──

  const sessionKey = deriveSessionKeyFromJwt(jwt);

  if (serverVerify1) {
    console.log("[CredSSP] Server sent VERIFY — JWT authentication accepted");
    // Verify server's checksum
    if (serverVerify1.checksum) {
      const serverTranscript = Buffer.concat(transcript);
      // Note: server uses keyUsage=25 (acceptor)
      // We don't strictly need to verify it, but log it
      console.log(`[CredSSP] Server VERIFY checksum: ${serverVerify1.checksum.toString("hex")}`);
    }
  }

  // Send client VERIFY
  const clientTranscript = Buffer.concat(transcript);
  const checksumValue = computeVerifyChecksum(sessionKey, 23, clientTranscript); // 23 = initiator

  const verifyMsg = buildVerifyMessage(
    conversationId,
    seqNum++,
    TIDESSP_AUTH_SCHEME,
    checksumValue,
  );

  transcript.push(verifyMsg);

  const spnegoResp = buildSpnegoResponse(verifyMsg);
  const tsReq2 = buildTSRequest(CREDSSP_VERSION, spnegoResp);
  tlsSocket.write(tsReq2);
  console.log("[CredSSP] Sent NEGOEX VERIFY");

  // ── Step 4: Read final SPNEGO response (may be empty or confirm complete) ──

  const tsResp2 = await readTSRequest(tlsSocket);
  if (tsResp2.errorCode) {
    throw new Error(`CredSSP: VERIFY failed with error code 0x${tsResp2.errorCode.toString(16)}`);
  }
  console.log("[CredSSP] SPNEGO/NEGOEX authentication complete");

  // ── Step 5: Send pubKeyAuth (TLS channel binding) ──

  const serverPubKey = extractTlsPublicKey(tlsSocket);
  const pubKeyAuth = buildPubKeyAuth(serverPubKey);
  const tsReq3 = buildTSRequest(CREDSSP_VERSION, undefined, undefined, pubKeyAuth);
  tlsSocket.write(tsReq3);

  // ── Step 6: Read pubKeyAuth confirmation ──

  const tsResp3 = await readTSRequest(tlsSocket);
  if (!tsResp3.pubKeyAuth) {
    throw new Error("CredSSP: server did not return pubKeyAuth confirmation");
  }

  // ── Step 7: Send authInfo (TSCredentials) ──

  const authInfo = buildAuthInfo(username);
  const tsReq4 = buildTSRequest(CREDSSP_VERSION, undefined, authInfo);
  tlsSocket.write(tsReq4);

  console.log("[CredSSP] NLA authentication completed successfully");
}

// ── SPNEGO Builders ─────────────────────────────────────────────

/**
 * Build a SPNEGO NegTokenInit with NEGOEX OID.
 */
function buildSpnegoInit(mechToken: Buffer): Buffer {
  const mechTypes = encodeExplicit(0, encodeTlv(TAG_SEQUENCE, NEGOEX_OID));
  const mechTokenWrapped = encodeExplicit(2, encodeOctetString(mechToken));
  const negTokenInit = encodeSequence([mechTypes, mechTokenWrapped]);
  const inner = Buffer.concat([SPNEGO_OID, encodeTlv(0xa0, negTokenInit)]);
  return encodeTlv(0x60, inner);
}

/**
 * Build a SPNEGO NegTokenResp (client continuation).
 * Per RFC 4178, client should not set negState.
 */
function buildSpnegoResponse(responseToken: Buffer): Buffer {
  const elements: Buffer[] = [];
  elements.push(encodeExplicit(2, encodeOctetString(responseToken)));
  const negTokenResp = encodeSequence(elements);
  return encodeTlv(0xa1, negTokenResp);
}

/**
 * Extract mechToken from a SPNEGO NegTokenResp.
 */
function extractSpnegoMechToken(spnego: Buffer): Buffer | null {
  try {
    let reader: DerReader;

    if (spnego[0] === 0x60) {
      const appReader = new DerReader(spnego);
      const { value: appContent } = appReader.readTlv();
      const contentReader = new DerReader(appContent);
      contentReader.readTlv();
      const initWrapper = contentReader.readExplicit(0);
      if (!initWrapper) return null;
      reader = initWrapper.readSequence();
    } else if (spnego[0] === 0xa1) {
      const respReader = new DerReader(spnego);
      const { value: respContent } = respReader.readTlv();
      reader = new DerReader(respContent).readSequence();
    } else {
      reader = new DerReader(spnego).readSequence();
    }

    while (reader.hasMore()) {
      const tag = reader.peekTag();
      if (tag === contextTag(2)) {
        const wrapper = reader.readExplicit(2);
        if (!wrapper) return null;
        return wrapper.readOctetString();
      }
      reader.readTlv();
    }
    return null;
  } catch {
    return null;
  }
}

// ── TSRequest (MS-CSSP) ─────────────────────────────────────────

function buildTSRequest(
  version: number,
  negoToken?: Buffer,
  authInfo?: Buffer,
  pubKeyAuth?: Buffer,
): Buffer {
  const elements: Buffer[] = [];
  elements.push(encodeExplicit(0, encodeInteger(version)));

  if (negoToken) {
    const tokenEntry = encodeSequence([
      encodeExplicit(0, encodeOctetString(negoToken)),
    ]);
    elements.push(encodeExplicit(1, encodeSequence([tokenEntry])));
  }

  if (authInfo) {
    elements.push(encodeExplicit(2, encodeOctetString(authInfo)));
  }

  if (pubKeyAuth) {
    elements.push(encodeExplicit(3, encodeOctetString(pubKeyAuth)));
  }

  return encodeSequence(elements);
}

interface TSRequestData {
  version: number;
  negoToken?: Buffer;
  authInfo?: Buffer;
  pubKeyAuth?: Buffer;
  errorCode?: number;
}

function parseTSRequest(data: Buffer): TSRequestData {
  const reader = new DerReader(data).readSequence();
  const result: TSRequestData = { version: 0 };

  const versionWrapper = reader.readExplicit(0);
  if (versionWrapper) {
    result.version = versionWrapper.readInteger();
  }

  while (reader.hasMore()) {
    const tag = reader.peekTag();
    if (tag === contextTag(1)) {
      const wrapper = reader.readExplicit(1);
      if (wrapper) {
        const seq = wrapper.readSequence();
        if (seq.hasMore()) {
          const entry = seq.readSequence();
          const tokenWrapper = entry.readExplicit(0);
          if (tokenWrapper) {
            result.negoToken = tokenWrapper.readOctetString();
          }
        }
      }
    } else if (tag === contextTag(2)) {
      const wrapper = reader.readExplicit(2);
      if (wrapper) result.authInfo = wrapper.readOctetString();
    } else if (tag === contextTag(3)) {
      const wrapper = reader.readExplicit(3);
      if (wrapper) result.pubKeyAuth = wrapper.readOctetString();
    } else if (tag === contextTag(4)) {
      const wrapper = reader.readExplicit(4);
      if (wrapper) result.errorCode = wrapper.readInteger();
    } else {
      reader.readTlv();
    }
  }

  return result;
}

function readTSRequest(tlsSocket: TLSSocket): Promise<TSRequestData> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalLen = 0;
    let expectedLen = -1;
    let headerLen = 0;

    const timer = setTimeout(() => {
      tlsSocket.off("data", onData);
      reject(new Error("CredSSP: TSRequest read timeout"));
    }, 10_000);

    function onData(data: Buffer): void {
      chunks.push(data);
      totalLen += data.length;

      if (expectedLen < 0 && totalLen >= 2) {
        const buf = Buffer.concat(chunks);
        if (buf[0] !== 0x30) {
          clearTimeout(timer);
          tlsSocket.off("data", onData);
          reject(new Error(`CredSSP: expected SEQUENCE (0x30), got 0x${buf[0].toString(16)}`));
          return;
        }

        const lenByte = buf[1];
        if (lenByte < 0x80) {
          expectedLen = lenByte;
          headerLen = 2;
        } else {
          const numBytes = lenByte & 0x7f;
          if (totalLen < 2 + numBytes) return;
          expectedLen = 0;
          for (let i = 0; i < numBytes; i++) {
            expectedLen = (expectedLen << 8) | buf[2 + i];
          }
          headerLen = 2 + numBytes;
        }
      }

      if (expectedLen >= 0 && totalLen >= headerLen + expectedLen) {
        clearTimeout(timer);
        tlsSocket.off("data", onData);
        try {
          const full = Buffer.concat(chunks).subarray(0, headerLen + expectedLen);
          resolve(parseTSRequest(full));
        } catch (err) {
          reject(err);
        }
      }
    }

    tlsSocket.on("data", onData);
    tlsSocket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    tlsSocket.on("close", () => {
      clearTimeout(timer);
      reject(new Error("CredSSP: socket closed during TSRequest read"));
    });
  });
}

function extractNegoToken(tsReq: TSRequestData): Buffer | null {
  return tsReq.negoToken || null;
}

// ── TLS Channel Binding ─────────────────────────────────────────

function extractTlsPublicKey(tlsSocket: TLSSocket): Buffer {
  const cert = tlsSocket.getPeerCertificate();
  if (!cert || !cert.raw) {
    throw new Error("CredSSP: cannot get server TLS certificate");
  }
  return cert.raw;
}

function buildPubKeyAuth(serverPubKey: Buffer): Buffer {
  return serverPubKey;
}

// ── Auth Info ───────────────────────────────────────────────────

function buildAuthInfo(username: string): Buffer {
  const domainName = Buffer.alloc(0);
  const userBytes = Buffer.from(username, "utf-16le");
  const passBytes = Buffer.alloc(0);

  const tsCreds = encodeSequence([
    encodeExplicit(0, encodeOctetString(domainName)),
    encodeExplicit(1, encodeOctetString(userBytes)),
    encodeExplicit(2, encodeOctetString(passBytes)),
  ]);

  const tsCredentials = encodeSequence([
    encodeExplicit(0, encodeInteger(1)),
    encodeExplicit(1, encodeOctetString(tsCreds)),
  ]);

  return tsCredentials;
}
