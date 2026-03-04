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
import { createHash, randomBytes } from "crypto";
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
  computeAes128Checksum,
  computeAes128ChecksumKi,
  buildRfc4121Mic,
  md4,
  generateConversationId,
  NEGOEX_OID,
  TIDESSP_AUTH_SCHEME,
  CHECKSUM_TYPE_HMAC_SHA1_96_AES128,
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

  // CredSSP v5+ requires clientNonce in all TSRequests with negoTokens (CVE-2018-0886)
  const clientNonce = randomBytes(32);
  console.log(`[CredSSP] clientNonce: ${clientNonce.toString("hex")}`);

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
  const tsReq1 = buildTSRequest(CREDSSP_VERSION, spnegoInit, undefined, undefined, clientNonce);
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

  // Debug: log all SPNEGO NegTokenResp fields
  logSpnegoFields("Server SPNEGO", serverSpnego1);

  const serverNegoex1 = extractSpnegoMechToken(serverSpnego1);
  if (!serverNegoex1 || serverNegoex1.length < 40) {
    throw new Error("CredSSP: invalid NEGOEX response from server");
  }

  const serverMsgs1 = parseNegoexMessages(serverNegoex1);
  console.log(`[CredSSP] Server sent ${serverMsgs1.length} NEGOEX message(s): types=[${serverMsgs1.map(m => m.messageType).join(", ")}]`);

  // Debug: dump raw NEGOEX message headers from server
  {
    let dpos = 0;
    while (dpos + 40 <= serverNegoex1.length) {
      const mType = serverNegoex1.readUInt32LE(dpos + 8);
      const mSeq = serverNegoex1.readUInt32LE(dpos + 12);
      const mHdrLen = serverNegoex1.readUInt32LE(dpos + 16);
      const mMsgLen = serverNegoex1.readUInt32LE(dpos + 20);
      console.log(`[CredSSP] Server msg: type=${mType}, seq=${mSeq}, hdrLen=${mHdrLen}, msgLen=${mMsgLen}`);
      dpos += mMsgLen;
    }
  }

  // Record server's NEGOEX messages in transcript — EXCLUDE VERIFY messages.
  // MS-NEGOEX: VERIFY checksum is computed over all messages except VERIFYs.
  // We need to extract only the non-VERIFY message bytes from the server response.
  {
    let pos = 0;
    while (pos + 40 <= serverNegoex1.length) {
      const msgLen = serverNegoex1.readUInt32LE(pos + 20);
      const msgType = serverNegoex1.readUInt32LE(pos + 8);
      if (msgType !== MSG_VERIFY) {
        transcript.push(Buffer.from(serverNegoex1.subarray(pos, pos + msgLen)));
      }
      pos += msgLen;
    }
  }

  // Use conversation ID from server
  const serverConvId = serverMsgs1[0]?.conversationId;
  if (serverConvId) {
    serverConvId.copy(conversationId);
  }

  // Update seqNum to continue after the server's messages (global sequence)
  for (const msg of serverMsgs1) {
    if (msg.sequenceNum >= seqNum) {
      seqNum = msg.sequenceNum + 1;
    }
  }
  console.log(`[CredSSP] Next seqNum: ${seqNum}`);

  // Check if server sent VERIFY (JWT accepted, single round) or CHALLENGE (fallback)
  const serverVerify1 = serverMsgs1.find(m => m.messageType === MSG_VERIFY);
  const serverChallenge = serverMsgs1.find(m => m.messageType === MSG_CHALLENGE);

  if (serverChallenge?.exchange) {
    // Server sent CHALLENGE — this shouldn't happen with JWT flow
    throw new Error("CredSSP: server sent CHALLENGE — expected JWT to be verified in single round");
  }

  // ── Step 3: Verify server's VERIFY and complete SPNEGO ──

  const sessionKey = deriveSessionKeyFromJwt(jwt);
  console.log(`[CredSSP] Gateway session key: ${sessionKey.toString("hex")}`);

  if (!serverVerify1 || !serverVerify1.checksum) {
    throw new Error("CredSSP: server did not send VERIFY — authentication failed");
  }

  console.log("[CredSSP] Server sent VERIFY — JWT authentication accepted");
  const serverCksumType = serverVerify1.checksumType ?? 2;
  console.log(`[CredSSP] VERIFY checksumType=${serverCksumType}, checksum=${serverVerify1.checksum.toString("hex")}`);

  // Validate server's VERIFY checksum
  const transcriptData = Buffer.concat(transcript);
  console.log(`[CredSSP] Transcript: ${transcript.length} parts, total ${transcriptData.length} bytes`);
  for (let ti = 0; ti < transcript.length; ti++) {
    const part = transcript[ti];
    const msgType = part.length >= 12 ? part.readUInt32LE(8) : -1;
    console.log(`[CredSSP]   part[${ti}]: type=${msgType}, len=${part.length}, first8=${part.subarray(0, 8).toString("hex")}`);
  }
  console.log(`[CredSSP] Transcript SHA256: ${createHash("sha256").update(transcriptData).digest().toString("hex")}`);

  // Debug: try multiple transcript compositions to find the correct one
  if (serverCksumType === CHECKSUM_TYPE_HMAC_SHA1_96_AES128) {
    const serverCksum = serverVerify1.checksum;
    const tryChecksum = (label: string, data: Buffer) => {
      const cksum = computeAes128Checksum(sessionKey, 25, data);
      const match = serverCksum.equals(cksum);
      if (match) console.log(`[CredSSP] *** MATCH *** ${label}: ${cksum.toString("hex")}`);
      else console.log(`[CredSSP]   ${label}: ${cksum.toString("hex")}`);
      return match;
    };
    // Full transcript (current)
    tryChecksum("all 3 msgs", transcriptData);
    // Without ACCEPTOR_NEGO
    tryChecksum("INIT+APREQ only", Buffer.concat([transcript[0], transcript[1]]));
    // Without INITIATOR_NEGO
    tryChecksum("APREQ+ACCEPT only", Buffer.concat([transcript[1], transcript[2]]));
    // Only AP_REQUEST
    tryChecksum("APREQ only", transcript[1]);
    // Only INIT_NEGO+ACCEPT_NEGO
    tryChecksum("INIT+ACCEPT only", Buffer.concat([transcript[0], transcript[2]]));
    // All 3 msgs + server VERIFY message
    const verifyBuf = serverNegoex1;
    tryChecksum("all msgs + raw server", verifyBuf);
    // Try with key usage 23 instead of 25
    const cksum23 = computeAes128Checksum(sessionKey, 23, transcriptData);
    console.log(`[CredSSP]   ku=23 all 3: ${cksum23.toString("hex")}${serverCksum.equals(cksum23) ? " *** MATCH ***" : ""}`);
    // Try with Ki (0x55) instead of Kc (0x99) for all transcript combos
    const tryKi = (label: string, data: Buffer, ku: number) => {
      const cksum = computeAes128ChecksumKi(sessionKey, ku, data);
      const match = serverCksum.equals(cksum);
      if (match) console.log(`[CredSSP] *** MATCH *** Ki ${label}: ${cksum.toString("hex")}`);
      return match;
    };
    tryKi("ku=25 all3", transcriptData, 25);
    tryKi("ku=23 all3", transcriptData, 23);
    tryKi("ku=25 INIT+APREQ", Buffer.concat([transcript[0], transcript[1]]), 25);
    tryKi("ku=25 APREQ only", transcript[1], 25);
  }

  let serverChecksumOk = false;

  // Key usage convention (empirically determined):
  //   Both sides use keyUsage = 23 for VERIFY checksums.
  //   The VERIFY covers the same transcript, so both produce identical checksums.
  const KU_ACCEPTOR_VERIFY = 23;

  if (serverCksumType === CHECKSUM_TYPE_HMAC_SHA1_96_AES128) {
    const expected = computeAes128Checksum(sessionKey, KU_ACCEPTOR_VERIFY, transcriptData);
    serverChecksumOk = serverVerify1.checksum.equals(expected);
    console.log(`[CredSSP] Server VERIFY check (ku=${KU_ACCEPTOR_VERIFY}): ${expected.toString("hex")}${serverChecksumOk ? " *** MATCH ***" : ""}`);
  } else if (serverCksumType === 2) {
    const expected = md4(transcriptData);
    serverChecksumOk = serverVerify1.checksum.equals(expected);
    console.log(`[CredSSP] MD4 checksum: ${expected.toString("hex")}${serverChecksumOk ? " *** MATCH ***" : ""}`);
  } else {
    const aes = computeAes128Checksum(sessionKey, KU_ACCEPTOR_VERIFY, transcriptData);
    const md4ck = md4(transcriptData);
    console.log(`[CredSSP] Unknown checksumType=${serverCksumType}, AES128: ${aes.toString("hex")}, MD4: ${md4ck.toString("hex")}`);
    serverChecksumOk = serverVerify1.checksum.equals(aes) || serverVerify1.checksum.equals(md4ck);
  }

  if (!serverChecksumOk) {
    console.log("[CredSSP] WARNING: server VERIFY checksum mismatch — continuing anyway for debugging");
  }

  // ── Step 3: Send client response ──
  //
  // Previous attempts (all SEC_E_MESSAGE_ALTERED = 0x8009030f):
  //   1. VERIFY ku=23, no mechListMIC
  //   2. VERIFY ku=23, 4-msg transcript, RFC4121 mechListMIC (buggy Ki)
  //   3. VERIFY ku=25, no mechListMIC
  //   4. VERIFY ku=23, raw mechListMIC ku=25
  //   5. VERIFY ku=23, RFC4121 mechListMIC Kc ku=25
  //   6. No VERIFY, no mechListMIC → SEC_E_INVALID_TOKEN (0x80090308)
  //
  // Approach 6 proved the server REQUIRES a VERIFY. The SEC_E_MESSAGE_ALTERED
  // in attempts 1-5 may come from SPNEGO's mechListMIC check, not the VERIFY.
  //
  // APPROACH 7: VERIFY ku=25 (initiator sign) + RFC4121 mechListMIC ku=25
  // Per RFC 4121: acceptor uses ku=23, initiator uses ku=25.
  // Server VERIFY confirmed ku=23 (acceptor). Client should use ku=25 (initiator).
  // This is the first time we test VERIFY ku=25 WITH mechListMIC.

  const KU_INITIATOR_SIGN = 25;
  let clientChecksum: Buffer;
  if (serverCksumType === CHECKSUM_TYPE_HMAC_SHA1_96_AES128) {
    clientChecksum = computeAes128Checksum(sessionKey, KU_INITIATOR_SIGN, transcriptData);
  } else {
    clientChecksum = md4(transcriptData);
  }
  console.log(`[CredSSP] Client VERIFY: ku=${KU_INITIATOR_SIGN}, transcript=${transcriptData.length}b, checksum=${clientChecksum.toString("hex")}`);

  // Also log ku=23 for comparison
  const ck23 = computeAes128Checksum(sessionKey, 23, transcriptData);
  console.log(`[CredSSP] Client VERIFY alt ku=23: ${ck23.toString("hex")} (matches server: ${ck23.equals(serverVerify1.checksum)})`);

  const clientVerifyMsg = buildVerifyMessage(
    conversationId,
    seqNum++,
    TIDESSP_AUTH_SCHEME,
    clientChecksum,
    serverCksumType,
  );

  // SPNEGO mechListMIC: RFC 4121 MIC over the MechTypeList, ku=25 (initiator sign)
  const mechTypesList = encodeTlv(TAG_SEQUENCE, NEGOEX_OID);
  const mechListMICToken = buildRfc4121Mic(sessionKey, KU_INITIATOR_SIGN, 0, mechTypesList);
  console.log(`[CredSSP] mechListMIC (RFC4121, ku=${KU_INITIATOR_SIGN}, ${mechListMICToken.length}b): ${mechListMICToken.toString("hex")}`);
  console.log(`[CredSSP] mechTypesList (${mechTypesList.length}b): ${mechTypesList.toString("hex")}`);

  const verifySpnego = buildSpnegoResponse(clientVerifyMsg, mechListMICToken);
  console.log(`[CredSSP] Client NEGOEX VERIFY (${clientVerifyMsg.length}b): ${clientVerifyMsg.toString("hex")}`);
  console.log(`[CredSSP] Client SPNEGO response (${verifySpnego.length}b): ${verifySpnego.toString("hex")}`);

  const tsReqVerify = buildTSRequest(CREDSSP_VERSION, verifySpnego, undefined, undefined, clientNonce);
  tlsSocket.write(tsReqVerify);
  console.log(`[CredSSP] Sent approach 7: VERIFY ku=25 + RFC4121 mechListMIC ku=25`);

  // ── Step 4: Read server's SPNEGO accept-complete ──
  const tsRespComplete = await readTSRequest(tlsSocket);
  console.log(`[CredSSP] Server step4: version=${tsRespComplete.version}, errorCode=${tsRespComplete.errorCode ?? "none"}, hasNegoToken=${!!tsRespComplete.negoToken}, hasPubKeyAuth=${!!tsRespComplete.pubKeyAuth}`);
  if (tsRespComplete.negoToken) {
    logSpnegoFields("Server step4 SPNEGO", tsRespComplete.negoToken);
  }
  if (tsRespComplete.errorCode) {
    console.log(`[CredSSP] FAILED with error 0x${tsRespComplete.errorCode.toString(16)} — approach 7 (VERIFY ku=25 + RFC4121 mechListMIC ku=25)`);
    throw new Error(`CredSSP: server error after step3 0x${tsRespComplete.errorCode.toString(16)}`);
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

// ── SPNEGO Debug ────────────────────────────────────────────────

function logSpnegoFields(label: string, spnego: Buffer): void {
  try {
    let reader: DerReader;
    if (spnego[0] === 0x60) {
      const appReader = new DerReader(spnego);
      const { value: appContent } = appReader.readTlv();
      const contentReader = new DerReader(appContent);
      contentReader.readTlv(); // skip OID
      const initWrapper = contentReader.readExplicit(0);
      if (!initWrapper) return;
      reader = initWrapper.readSequence();
    } else if (spnego[0] === 0xa1) {
      const respReader = new DerReader(spnego);
      const { value: respContent } = respReader.readTlv();
      reader = new DerReader(respContent).readSequence();
    } else {
      reader = new DerReader(spnego).readSequence();
    }
    const fields: string[] = [];
    while (reader.hasMore()) {
      const tag = reader.peekTag();
      const { value } = reader.readTlv();
      if (tag === contextTag(0)) {
        // value is DER ENUMERATED: 0a 01 <val>
        const nsVal = (value.length >= 3 && value[0] === 0x0a) ? value[2] : value[0];
        fields.push(`negState=${nsVal}`);
      }
      else if (tag === contextTag(1)) fields.push(`supportedMech(${value.length}b)`);
      else if (tag === contextTag(2)) fields.push(`responseToken(${value.length}b)`);
      else if (tag === contextTag(3)) fields.push(`mechListMIC(${value.length}b)=${value.toString("hex").substring(0, 40)}`);
      else fields.push(`tag=0x${tag.toString(16)}(${value.length}b)`);
    }
    console.log(`[CredSSP] ${label}: ${fields.join(", ")}`);
  } catch (e) {
    console.log(`[CredSSP] ${label}: parse error: ${e}`);
  }
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
 * Build a SPNEGO NegTokenResp (client continuation) with optional mechListMIC.
 */
function buildSpnegoResponse(responseToken?: Buffer, mechListMIC?: Buffer): Buffer {
  const elements: Buffer[] = [];
  if (responseToken) {
    elements.push(encodeExplicit(2, encodeOctetString(responseToken)));
  }
  if (mechListMIC) {
    elements.push(encodeExplicit(3, encodeOctetString(mechListMIC)));
  }
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
  clientNonce?: Buffer,
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

  // clientNonce [5] OCTET STRING — required for CredSSP v5+ (CVE-2018-0886)
  if (clientNonce) {
    elements.push(encodeExplicit(5, encodeOctetString(clientNonce)));
  }

  return encodeSequence(elements);
}

interface TSRequestData {
  version: number;
  negoToken?: Buffer;
  authInfo?: Buffer;
  pubKeyAuth?: Buffer;
  errorCode?: number;
  clientNonce?: Buffer;
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
    } else if (tag === contextTag(5)) {
      const wrapper = reader.readExplicit(5);
      if (wrapper) result.clientNonce = wrapper.readOctetString();
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
