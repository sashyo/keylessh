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
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
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

  // Verify server's checksum: ku=23 over 3-msg transcript (INIT_NEGO, EXCHANGE, ACCEPT_NEGO)
  if (serverCksumType === CHECKSUM_TYPE_HMAC_SHA1_96_AES128) {
    const ck23 = computeAes128Checksum(sessionKey, 23, transcriptData);
    console.log(`[CredSSP] Server VERIFY ku=23: ${ck23.toString("hex")} (match: ${ck23.equals(serverVerify1.checksum)})`);
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

  // ── Step 3: Send client VERIFY ──
  //
  // Per MIT krb5 source (negoex_ctx.c):
  //   - Transcript includes ALL messages (including server's VERIFY)
  //   - make_checksum() runs AFTER server's input token is appended to transcript
  //   - So client's VERIFY covers: [INIT_NEGO + EXCHANGE + ACCEPT_NEGO + SERVER_VERIFY]
  //   - Key usage: initiator makes with ku=25 (NEGOEX_KEYUSAGE_ACCEPTOR_CHECKSUM)
  //
  // verify_checksum() on server side uses IOV:
  //   iov[0] = existing transcript (all prior messages incl. server's VERIFY)
  //   iov[1] = bytes before VERIFY in client's token (0 bytes, VERIFY is only message)

  // Build 4-msg transcript: all messages including server's VERIFY
  const serverVerifyRaw = (() => {
    let pos = 0;
    while (pos + 40 <= serverNegoex1.length) {
      const msgLen = serverNegoex1.readUInt32LE(pos + 20);
      const msgType = serverNegoex1.readUInt32LE(pos + 8);
      if (msgType === MSG_VERIFY) {
        return Buffer.from(serverNegoex1.subarray(pos, pos + msgLen));
      }
      pos += msgLen;
    }
    return null;
  })();

  if (!serverVerifyRaw) {
    throw new Error("CredSSP: could not extract server's raw VERIFY bytes");
  }

  // Full transcript = client token 1 (INIT_NEGO + EXCHANGE) + server token 1 (ACCEPT_NEGO + VERIFY)
  const fullTranscript = Buffer.concat([transcriptData, serverVerifyRaw]);
  console.log(`[CredSSP] Full transcript: ${fullTranscript.length} bytes (3-msg ${transcriptData.length}b + server VERIFY ${serverVerifyRaw.length}b)`);

  const KU_CLIENT_VERIFY = 25;
  const clientChecksum = computeAes128Checksum(sessionKey, KU_CLIENT_VERIFY, fullTranscript);
  console.log(`[CredSSP] Client VERIFY checksum (ku=${KU_CLIENT_VERIFY}, 4-msg/${fullTranscript.length}b): ${clientChecksum.toString("hex")}`);

  const clientVerify = buildVerifyMessage(
    conversationId,
    seqNum++,
    TIDESSP_AUTH_SCHEME,
    clientChecksum,
    CHECKSUM_TYPE_HMAC_SHA1_96_AES128,
  );
  console.log(`[CredSSP] Client VERIFY (${clientVerify.length}b): ${clientVerify.toString("hex")}`);

  // No mechListMIC — NegoExtender doesn't implement GSS_GetMIC/VerifyMIC,
  // and the server's NegTokenResp also omits mechListMIC.
  const verifySpnego = buildSpnegoResponse(clientVerify);
  const tsReqVerify = buildTSRequest(CREDSSP_VERSION, verifySpnego, undefined, undefined, clientNonce);
  tlsSocket.write(tsReqVerify);
  console.log(`[CredSSP] Sent VERIFY ku=${KU_CLIENT_VERIFY}/4-msg (no mechListMIC)`);

  // ── Step 4: Read server's SPNEGO accept-complete ──
  const tsRespComplete = await readTSRequest(tlsSocket);
  console.log(`[CredSSP] Server step4: version=${tsRespComplete.version}, errorCode=${tsRespComplete.errorCode ?? "none"}, hasNegoToken=${!!tsRespComplete.negoToken}, hasPubKeyAuth=${!!tsRespComplete.pubKeyAuth}`);
  if (tsRespComplete.negoToken) {
    logSpnegoFields("Server step4 SPNEGO", tsRespComplete.negoToken);
  }
  if (tsRespComplete.errorCode) {
    console.log(`[CredSSP] FAILED with error 0x${tsRespComplete.errorCode.toString(16)} — VERIFY ku=25/4-msg`);
    throw new Error(`CredSSP: server error after step3 0x${tsRespComplete.errorCode.toString(16)}`);
  }
  console.log("[CredSSP] SPNEGO/NEGOEX authentication complete");

  // ── Step 5: Send pubKeyAuth (TLS channel binding) ──
  //
  // CredSSP v5/v6 (MS-CSSP §3.1.5):
  //   ClientServerHash = SHA-256("CredSSP Client-To-Server Binding Hash\0" + Nonce + SubjectPublicKey)
  //   pubKeyAuth = EncryptMessage(ClientServerHash)
  //
  // SubjectPublicKey = raw public key bytes from the certificate's SubjectPublicKeyInfo
  //   BIT STRING content (excluding the 0x00 unused-bits prefix).
  //   For RSA, this is the DER-encoded RSAPublicKey { modulus, exponent }.
  //   This matches Windows' CERT_PUBLIC_KEY_INFO.PublicKey.pbData and FreeRDP's i2d_PublicKey().
  // NOTE: There is NO inner SHA-256 hash — the raw key bytes go directly into the outer hash.

  const serverCertRaw = extractTlsServerCert(tlsSocket);
  console.log(`[CredSSP] Server cert raw DER: ${serverCertRaw.length} bytes`);

  // Extract raw SubjectPublicKey from the certificate (BIT STRING content minus unused-bits byte)
  const subjectPublicKey = extractSubjectPublicKeyFromCertDer(serverCertRaw);
  console.log(`[CredSSP] SubjectPublicKey: ${subjectPublicKey.length} bytes, first16=${subjectPublicKey.subarray(0, 16).toString("hex")}`);

  const hashMagic = Buffer.from("CredSSP Client-To-Server Binding Hash\0", "ascii");
  console.log(`[CredSSP] hashMagic: ${hashMagic.length} bytes`);
  console.log(`[CredSSP] clientNonce: ${clientNonce.toString("hex")}`);

  const clientHashInput = Buffer.concat([hashMagic, clientNonce, subjectPublicKey]);
  console.log(`[CredSSP] hashInput: ${clientHashInput.length} bytes (${hashMagic.length}+${clientNonce.length}+${subjectPublicKey.length})`);

  const clientHashEncData = createHash("sha256").update(clientHashInput).digest();
  console.log(`[CredSSP] pubKeyAuth plaintext (${clientHashEncData.length}b): ${clientHashEncData.toString("hex")}`);

  const pubKeyAuth = tideGcmEncrypt(sessionKey, clientHashEncData);
  console.log(`[CredSSP] pubKeyAuth encrypted (${pubKeyAuth.length}b): ${pubKeyAuth.toString("hex").substring(0, 60)}...`);
  const tsReq3 = buildTSRequest(CREDSSP_VERSION, undefined, undefined, pubKeyAuth, clientNonce);
  tlsSocket.write(tsReq3);
  console.log("[CredSSP] Sent pubKeyAuth (CredSSP v6 hash binding)");

  // ── Step 6: Read pubKeyAuth confirmation ──

  const tsResp3 = await readTSRequest(tlsSocket);
  console.log(`[CredSSP] Server step6: version=${tsResp3.version}, errorCode=${tsResp3.errorCode ?? "none"}, hasPubKeyAuth=${!!tsResp3.pubKeyAuth}`);
  if (tsResp3.errorCode) {
    throw new Error(`CredSSP: server error during pubKeyAuth 0x${tsResp3.errorCode.toString(16)}`);
  }
  if (!tsResp3.pubKeyAuth) {
    throw new Error("CredSSP: server did not return pubKeyAuth confirmation");
  }

  // Verify server's pubKeyAuth: SHA-256("CredSSP Server-To-Client Binding Hash\0" + nonce + SubjectPublicKey)
  const serverHashInput = Buffer.concat([
    Buffer.from("CredSSP Server-To-Client Binding Hash\0", "ascii"),
    clientNonce,
    subjectPublicKey,
  ]);
  const expectedServerHash = createHash("sha256").update(serverHashInput).digest();
  const serverPubKeyAuth = tideGcmDecrypt(sessionKey, tsResp3.pubKeyAuth);
  if (!serverPubKeyAuth.equals(expectedServerHash)) {
    console.log(`[CredSSP] Server pubKeyAuth mismatch! expected=${expectedServerHash.toString("hex")}, got=${serverPubKeyAuth.toString("hex")}`);
    throw new Error("CredSSP: server pubKeyAuth hash mismatch");
  }
  console.log("[CredSSP] Server pubKeyAuth verified OK");

  // ── Step 7: Send authInfo (TSCredentials) ──

  // credType=1 (TSPasswordCreds): send hex(sessionKey) as the "password".
  // TideSSP's SubAuth DLL (TideSubAuth) recognizes the NT hash of this
  // hex string against the NLA session map — no real Windows password needed.
  const hexSessionKey = sessionKey.toString("hex");
  // Extract username from JWT for TSCredentials
  const jwtPayload = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
  const username = jwtPayload.preferred_username || jwtPayload.sub || "";
  console.log(`[CredSSP] TSCredentials: credType=1, user="${username}", pass=hex(sessionKey), domain="."`);
  const authInfoPlain = buildAuthInfo(username, hexSessionKey, ".");
  console.log(`[CredSSP] authInfo plaintext: ${authInfoPlain.length} bytes, hex=${authInfoPlain.toString("hex")}`);
  const authInfoEnc = tideGcmEncrypt(sessionKey, authInfoPlain);
  const tsReq4 = buildTSRequest(CREDSSP_VERSION, undefined, authInfoEnc, undefined, clientNonce);
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
 * Build a SPNEGO NegTokenResp (client continuation) with optional fields.
 */
function buildSpnegoResponse(
  responseToken?: Buffer,
  mechListMIC?: Buffer,
  negState?: number,
): Buffer {
  const elements: Buffer[] = [];
  if (negState !== undefined) {
    // ENUMERATED value wrapped in EXPLICIT [0]
    const enumVal = Buffer.from([0x0a, 0x01, negState]);
    elements.push(encodeExplicit(0, enumVal));
  }
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
          const full = Buffer.concat(chunks);
          const needed = headerLen + expectedLen;
          if (full.length > needed) {
            const extra = full.subarray(needed);
            console.log(`[CredSSP] readTSRequest: got ${full.length} bytes, needed ${needed}, pushing back ${extra.length} extra bytes: ${extra.subarray(0, 32).toString("hex")}`);
            tlsSocket.unshift(extra);
          }
          resolve(parseTSRequest(full.subarray(0, needed)));
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

function extractTlsServerCert(tlsSocket: TLSSocket): Buffer {
  const cert = tlsSocket.getPeerCertificate();
  if (!cert || !cert.raw) {
    throw new Error("CredSSP: cannot get server TLS certificate");
  }
  return cert.raw;
}

/**
 * Extract the raw SubjectPublicKey bytes from a DER-encoded X.509 certificate.
 *
 * Returns the BIT STRING content of SubjectPublicKeyInfo.subjectPublicKey,
 * EXCLUDING the unused-bits byte (0x00). For RSA, this is the DER-encoded
 * RSAPublicKey { modulus INTEGER, exponent INTEGER }.
 *
 * This matches Windows' CERT_PUBLIC_KEY_INFO.PublicKey.pbData and
 * FreeRDP's i2d_PublicKey() output used for CredSSP v5/v6 hash computation.
 *
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * TBSCertificate ::= SEQUENCE {
 *   version [0] EXPLICIT INTEGER,  -- optional
 *   serialNumber INTEGER,
 *   signature AlgorithmIdentifier,
 *   issuer Name,
 *   validity Validity,
 *   subject Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo  ← target
 * }
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING     ← extract content minus unused-bits byte
 * }
 */
function extractSubjectPublicKeyFromCertDer(certDer: Buffer): Buffer {
  let pos = 0;

  // Outer SEQUENCE (Certificate) — skip tag + length header
  if (certDer[pos] !== 0x30) throw new Error("extractSPK: expected SEQUENCE");
  pos++;
  pos += derLenBytes(certDer, pos);

  // TBSCertificate SEQUENCE — skip tag + length header to enter contents
  if (certDer[pos] !== 0x30) throw new Error("extractSPK: expected TBS SEQUENCE");
  pos++;
  pos += derLenBytes(certDer, pos);

  // Skip version [0] EXPLICIT if present
  if (certDer[pos] === 0xa0) pos = derSkipTlv(certDer, pos);

  // Skip: serialNumber, signature, issuer, validity, subject (5 fields)
  for (let i = 0; i < 5; i++) pos = derSkipTlv(certDer, pos);

  // Now at SubjectPublicKeyInfo SEQUENCE — enter it
  if (certDer[pos] !== 0x30) throw new Error("extractSPK: expected SPKI SEQUENCE");
  pos++; // skip SEQUENCE tag
  pos += derLenBytes(certDer, pos); // skip SEQUENCE length

  // Skip AlgorithmIdentifier (first field)
  pos = derSkipTlv(certDer, pos);

  // Now at subjectPublicKey BIT STRING
  if (certDer[pos] !== 0x03) throw new Error("extractSPK: expected BIT STRING");
  pos++; // skip BIT STRING tag
  const bitStringLenSize = derLenBytes(certDer, pos);
  const first = certDer[pos];
  let bitStringLen: number;
  if (first < 0x80) {
    bitStringLen = first;
  } else {
    const n = first & 0x7f;
    bitStringLen = 0;
    for (let i = 0; i < n; i++) bitStringLen = (bitStringLen << 8) | certDer[pos + 1 + i];
  }
  pos += bitStringLenSize;

  // Skip unused-bits byte (should be 0x00)
  pos++;
  bitStringLen--;

  // Return the raw public key bytes (RSAPublicKey DER for RSA)
  return certDer.subarray(pos, pos + bitStringLen);
}

/** Read a DER length and return number of bytes consumed (length field only) */
function derLenBytes(buf: Buffer, pos: number): number {
  const first = buf[pos];
  if (first < 0x80) return 1;
  return 1 + (first & 0x7f);
}

/** Skip an entire TLV element starting at pos, return position after it */
function derSkipTlv(buf: Buffer, pos: number): number {
  pos++; // skip tag byte
  const first = buf[pos];
  if (first < 0x80) {
    return pos + 1 + first;
  }
  const n = first & 0x7f;
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | buf[pos + 1 + i];
  return pos + 1 + n + len;
}

// ── TideSSP AES-128-GCM encryption (matches TideSSP SealMessage) ──
//
// Wire format: [12-byte nonce] [16-byte GCM tag] [ciphertext]
// Key: raw 16-byte session key

function tideGcmEncrypt(key: Buffer, plaintext: Buffer): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-128-gcm", key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  return Buffer.concat([nonce, tag, encrypted]);
}

function tideGcmDecrypt(key: Buffer, data: Buffer): Buffer {
  if (data.length < 28) {
    throw new Error("tideGcmDecrypt: data too short");
  }
  const nonce = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = createDecipheriv("aes-128-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ── Auth Info ───────────────────────────────────────────────────

/**
 * Build TSCredentials with credType=1 (TSPasswordCreds).
 *
 * TSCredentials ::= SEQUENCE {
 *   credType    [0] INTEGER (1)
 *   credentials [1] OCTET STRING = DER(TSPasswordCreds)
 * }
 * TSPasswordCreds ::= SEQUENCE {
 *   domainName [0] OCTET STRING  (UTF-16LE)
 *   userName   [1] OCTET STRING  (UTF-16LE)
 *   password   [2] OCTET STRING  (UTF-16LE)
 * }
 */
function buildAuthInfo(username: string, password: string, domain: string): Buffer {
  const domainName = Buffer.from(domain, "utf-16le");
  const userBytes = Buffer.from(username, "utf-16le");
  const passBytes = Buffer.from(password, "utf-16le");

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
