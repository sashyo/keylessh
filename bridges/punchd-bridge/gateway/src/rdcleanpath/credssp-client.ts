/**
 * CredSSP client for TideSSP Ed25519 authentication.
 *
 * Performs NLA (Network Level Authentication) with the RDP server using
 * the custom TideSSP security package instead of NTLM/Kerberos.
 *
 * Protocol flow:
 * 1. Client → Server: TSRequest with SPNEGO NegTokenInit containing TideSSP NEGOTIATE
 * 2. Server → Client: TSRequest with SPNEGO NegTokenResp containing TideSSP CHALLENGE
 * 3. Client → Server: TSRequest with SPNEGO NegTokenResp containing TideSSP AUTHENTICATE
 * 4. Server → Client: TSRequest with empty negoTokens (auth complete)
 * 5. Client → Server: TSRequest with pubKeyAuth (TLS binding)
 * 6. Server → Client: TSRequest with pubKeyAuth confirmation
 * 7. Client → Server: TSRequest with authInfo (credentials blob)
 *
 * The challenge is relayed to the browser for Ed25519 signing via a callback.
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

// ── TideSSP Token Types ─────────────────────────────────────────

const TOKEN_NEGOTIATE = 0x01;
const TOKEN_CHALLENGE = 0x02;
const TOKEN_AUTHENTICATE = 0x03;

const TIDESSP_VERSION = 0x01;
const CHALLENGE_SIZE = 32;

// ── SPNEGO OIDs ─────────────────────────────────────────────────

// SPNEGO: 1.3.6.1.5.5.2
const SPNEGO_OID = Buffer.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);

// TideSSP: 1.3.6.1.4.1.59438.1.1 (private enterprise placeholder)
// Encoded as: 06 0a 2b 06 01 04 01 83 d0 5e 01 01
const TIDESSP_OID = Buffer.from([
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xd0, 0x5e, 0x01, 0x01,
]);

// ── CredSSP Constants ───────────────────────────────────────────

const CREDSSP_VERSION = 6; // CredSSP v6

// ── Callback interface ──────────────────────────────────────────

export interface CredSSPCallbacks {
  /** Called when the server returns a challenge. The browser signs it. */
  onChallenge(challenge: Buffer): Promise<{
    signature: Buffer; // 64 bytes Ed25519 signature
    publicKey: Buffer; // 32 bytes Ed25519 public key
  }>;
}

// ── Main entry point ────────────────────────────────────────────

/**
 * Perform CredSSP/NLA authentication with a TLS-wrapped RDP server
 * using the TideSSP custom security package.
 *
 * @param tlsSocket - TLS socket connected to the RDP server
 * @param username - Windows username for the logon session
 * @param callbacks - Challenge relay callbacks to the browser
 */
export async function performCredSSP(
  tlsSocket: TLSSocket,
  username: string,
  callbacks: CredSSPCallbacks,
): Promise<void> {
  // Step 1: Send NEGOTIATE
  const negotiateToken = buildNegotiateToken(username);
  const spnegoInit = buildSpnegoInit(negotiateToken);
  const tsReq1 = buildTSRequest(CREDSSP_VERSION, spnegoInit);
  tlsSocket.write(tsReq1);

  // Step 2: Read CHALLENGE
  const tsResp1 = await readTSRequest(tlsSocket);
  const challengeSpnego = extractNegoToken(tsResp1);
  if (!challengeSpnego) {
    throw new Error("CredSSP: no negoToken in server response");
  }

  const challengeToken = extractSpnegoMechToken(challengeSpnego);
  if (!challengeToken || challengeToken.length < 1 + CHALLENGE_SIZE) {
    throw new Error("CredSSP: invalid challenge token");
  }
  if (challengeToken[0] !== TOKEN_CHALLENGE) {
    throw new Error(`CredSSP: expected CHALLENGE (0x02), got 0x${challengeToken[0].toString(16)}`);
  }
  const challenge = challengeToken.subarray(1, 1 + CHALLENGE_SIZE);

  // Step 3: Relay challenge to browser, get signature
  console.log("[CredSSP] Relaying challenge to browser for Ed25519 signing");
  const { signature, publicKey } = await callbacks.onChallenge(Buffer.from(challenge));

  if (signature.length !== 64) {
    throw new Error(`CredSSP: expected 64-byte signature, got ${signature.length}`);
  }
  if (publicKey.length !== 32) {
    throw new Error(`CredSSP: expected 32-byte public key, got ${publicKey.length}`);
  }

  // Step 4: Send AUTHENTICATE
  const authToken = buildAuthenticateToken(signature, publicKey);
  const spnegoResp = buildSpnegoResponse(authToken);
  const tsReq2 = buildTSRequest(CREDSSP_VERSION, spnegoResp);
  tlsSocket.write(tsReq2);

  // Step 5: Read auth result
  const tsResp2 = await readTSRequest(tlsSocket);

  // Check for error
  if (tsResp2.errorCode) {
    throw new Error(`CredSSP: authentication failed with error code ${tsResp2.errorCode}`);
  }

  // Step 6: Send pubKeyAuth (TLS channel binding)
  const serverPubKey = extractTlsPublicKey(tlsSocket);
  const pubKeyAuth = buildPubKeyAuth(serverPubKey);
  const tsReq3 = buildTSRequest(CREDSSP_VERSION, undefined, undefined, pubKeyAuth);
  tlsSocket.write(tsReq3);

  // Step 7: Read pubKeyAuth confirmation
  const tsResp3 = await readTSRequest(tlsSocket);
  if (!tsResp3.pubKeyAuth) {
    throw new Error("CredSSP: server did not return pubKeyAuth confirmation");
  }

  // Step 8: Send authInfo (TSCredentials)
  const authInfo = buildAuthInfo(username);
  const tsReq4 = buildTSRequest(CREDSSP_VERSION, undefined, authInfo);
  tlsSocket.write(tsReq4);

  console.log("[CredSSP] NLA authentication completed successfully");
}

// ── TideSSP Token Builders ──────────────────────────────────────

function buildNegotiateToken(username: string): Buffer {
  const usernameBytes = Buffer.from(username, "utf-8");
  const buf = Buffer.alloc(1 + 1 + 2 + usernameBytes.length);
  buf[0] = TOKEN_NEGOTIATE;
  buf[1] = TIDESSP_VERSION;
  buf.writeUInt16LE(usernameBytes.length, 2);
  usernameBytes.copy(buf, 4);
  return buf;
}

function buildAuthenticateToken(signature: Buffer, publicKey: Buffer): Buffer {
  const buf = Buffer.alloc(1 + 64 + 32);
  buf[0] = TOKEN_AUTHENTICATE;
  signature.copy(buf, 1);
  publicKey.copy(buf, 1 + 64);
  return buf;
}

// ── SPNEGO Builders ─────────────────────────────────────────────

/**
 * Build a SPNEGO NegTokenInit (initial token).
 *
 * NegTokenInit ::= SEQUENCE {
 *   mechTypes  [0] MechTypeList,        -- SEQUENCE OF OID
 *   mechToken  [2] OCTET STRING OPTIONAL
 * }
 *
 * Wrapped in an APPLICATION [0] with SPNEGO OID.
 */
function buildSpnegoInit(mechToken: Buffer): Buffer {
  // MechTypeList: SEQUENCE OF { TideSSP OID }
  const mechTypes = encodeExplicit(0, encodeTlv(TAG_SEQUENCE, TIDESSP_OID));
  // mechToken: [2] OCTET STRING
  const mechTokenWrapped = encodeExplicit(2, encodeOctetString(mechToken));

  const negTokenInit = encodeSequence([mechTypes, mechTokenWrapped]);

  // Wrap in SPNEGO context: APPLICATION [0] { SPNEGO OID, NegTokenInit }
  // APPLICATION [0] CONSTRUCTED = 0x60
  const inner = Buffer.concat([SPNEGO_OID, encodeTlv(0xa0, negTokenInit)]);
  return encodeTlv(0x60, inner);
}

/**
 * Build a SPNEGO NegTokenResp (subsequent token).
 *
 * NegTokenResp ::= SEQUENCE {
 *   negState   [0] ENUMERATED OPTIONAL,
 *   supportedMech [1] OID OPTIONAL,
 *   responseToken [2] OCTET STRING OPTIONAL
 * }
 */
function buildSpnegoResponse(responseToken: Buffer): Buffer {
  const elements: Buffer[] = [];
  // negState [0] ENUMERATED accept-incomplete (1)
  elements.push(encodeExplicit(0, encodeTlv(0x0a, Buffer.from([0x01]))));
  // responseToken [2] OCTET STRING
  elements.push(encodeExplicit(2, encodeOctetString(responseToken)));

  const negTokenResp = encodeSequence(elements);
  // Wrap as [1] CONSTRUCTED (NegTokenResp context)
  return encodeTlv(0xa1, negTokenResp);
}

/**
 * Extract mechToken from a SPNEGO NegTokenResp.
 */
function extractSpnegoMechToken(spnego: Buffer): Buffer | null {
  try {
    let reader: DerReader;

    // Could be APPLICATION [0] (NegTokenInit from server) or [1] (NegTokenResp)
    if (spnego[0] === 0x60) {
      // APPLICATION [0] — skip OID, read NegTokenInit
      const appReader = new DerReader(spnego);
      const { value: appContent } = appReader.readTlv();
      const contentReader = new DerReader(appContent);
      // Skip SPNEGO OID
      contentReader.readTlv();
      // Read [0] wrapper
      const initWrapper = contentReader.readExplicit(0);
      if (!initWrapper) return null;
      reader = initWrapper.readSequence();
    } else if (spnego[0] === 0xa1) {
      // [1] NegTokenResp
      const respReader = new DerReader(spnego);
      const { value: respContent } = respReader.readTlv();
      reader = new DerReader(respContent).readSequence();
    } else {
      // Try as raw SEQUENCE
      reader = new DerReader(spnego).readSequence();
    }

    // Scan for [2] (responseToken / mechToken)
    while (reader.hasMore()) {
      const tag = reader.peekTag();
      if (tag === contextTag(2)) {
        const wrapper = reader.readExplicit(2);
        if (!wrapper) return null;
        return wrapper.readOctetString();
      }
      reader.readTlv(); // skip this element
    }
    return null;
  } catch {
    return null;
  }
}

// ── TSRequest (MS-CSSP) ─────────────────────────────────────────

/**
 * TSRequest ::= SEQUENCE {
 *   version    [0] INTEGER,
 *   negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING } OPTIONAL,
 *   authInfo   [2] OCTET STRING OPTIONAL,
 *   pubKeyAuth [3] OCTET STRING OPTIONAL,
 *   errorCode  [4] INTEGER OPTIONAL,
 * }
 */
function buildTSRequest(
  version: number,
  negoToken?: Buffer,
  authInfo?: Buffer,
  pubKeyAuth?: Buffer,
): Buffer {
  const elements: Buffer[] = [];

  // [0] version
  elements.push(encodeExplicit(0, encodeInteger(version)));

  // [1] negoTokens
  if (negoToken) {
    const tokenEntry = encodeSequence([
      encodeExplicit(0, encodeOctetString(negoToken)),
    ]);
    elements.push(encodeExplicit(1, encodeSequence([tokenEntry])));
  }

  // [2] authInfo
  if (authInfo) {
    elements.push(encodeExplicit(2, encodeOctetString(authInfo)));
  }

  // [3] pubKeyAuth
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

  // [0] version
  const versionWrapper = reader.readExplicit(0);
  if (versionWrapper) {
    result.version = versionWrapper.readInteger();
  }

  // Scan remaining fields
  while (reader.hasMore()) {
    const tag = reader.peekTag();
    if (tag === contextTag(1)) {
      // negoTokens
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
      reader.readTlv(); // skip unknown
    }
  }

  return result;
}

/**
 * Read a TSRequest from a TLS socket.
 * TSRequests are ASN.1 DER encoded, starting with SEQUENCE (0x30).
 */
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

        // Parse DER length
        const lenByte = buf[1];
        if (lenByte < 0x80) {
          expectedLen = lenByte;
          headerLen = 2;
        } else {
          const numBytes = lenByte & 0x7f;
          if (totalLen < 2 + numBytes) return; // need more data for length
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

/**
 * Extract the negoToken (SPNEGO) from a TSRequest response.
 */
function extractNegoToken(tsReq: TSRequestData): Buffer | null {
  return tsReq.negoToken || null;
}

// ── TLS Channel Binding ─────────────────────────────────────────

/**
 * Extract the server's TLS public key for channel binding.
 * This is used in the pubKeyAuth step of CredSSP.
 */
function extractTlsPublicKey(tlsSocket: TLSSocket): Buffer {
  const cert = tlsSocket.getPeerCertificate();
  if (!cert || !cert.raw) {
    throw new Error("CredSSP: cannot get server TLS certificate");
  }
  // For CredSSP, we send the full DER-encoded server certificate
  return cert.raw;
}

/**
 * Build the pubKeyAuth value.
 * In our simplified TideSSP flow, this is the server's TLS certificate hash,
 * proving the client is talking to the right TLS endpoint.
 * For simplicity, we send the raw cert — the TideSSP server-side doesn't
 * actually validate this since it trusts the TLS channel.
 */
function buildPubKeyAuth(serverPubKey: Buffer): Buffer {
  return serverPubKey;
}

// ── Auth Info ───────────────────────────────────────────────────

/**
 * Build TSCredentials authInfo blob.
 * TSCredentials ::= SEQUENCE {
 *   credType [0] INTEGER,   -- 1 = TSPasswordCreds
 *   credentials [1] OCTET STRING
 * }
 *
 * For TideSSP, we send the username as the credential (no password needed).
 */
function buildAuthInfo(username: string): Buffer {
  // TSPasswordCreds ::= SEQUENCE {
  //   domainName [0] OCTET STRING,
  //   userName   [1] OCTET STRING,
  //   password   [2] OCTET STRING
  // }
  const domainName = Buffer.alloc(0);
  const userBytes = Buffer.from(username, "utf-16le");
  const passBytes = Buffer.alloc(0); // no password for EdDSA auth

  const tsCreds = encodeSequence([
    encodeExplicit(0, encodeOctetString(domainName)),
    encodeExplicit(1, encodeOctetString(userBytes)),
    encodeExplicit(2, encodeOctetString(passBytes)),
  ]);

  const tsCredentials = encodeSequence([
    encodeExplicit(0, encodeInteger(1)), // credType = TSPasswordCreds
    encodeExplicit(1, encodeOctetString(tsCreds)),
  ]);

  return tsCredentials;
}
