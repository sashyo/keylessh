/**
 * NEGOEX binary message codec (MS-NEGOEX).
 *
 * NEGOEX extends SPNEGO by allowing custom authentication schemes to
 * participate in negotiation. Messages are binary (NOT ASN.1), carried
 * inside SPNEGO mechTokens using the NEGOEX OID.
 *
 * All multi-byte integers are little-endian.
 *
 * Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/
 */

import { randomBytes, createHmac, createHash } from "crypto";

// ── Constants ────────────────────────────────────────────────────

const NEGOEX_SIGNATURE = Buffer.from("NEGOEXTS"); // 8 bytes

export const MSG_INITIATOR_NEGO = 0;
export const MSG_ACCEPTOR_NEGO = 1;
export const MSG_INITIATOR_META_DATA = 2;
export const MSG_ACCEPTOR_META_DATA = 3;
export const MSG_CHALLENGE = 4;
export const MSG_AP_REQUEST = 5;
export const MSG_VERIFY = 6;
export const MSG_ALERT = 7;

/** NEGOEX OID: 1.3.6.1.4.1.311.2.2.30 — used in SPNEGO mechTypes */
export const NEGOEX_OID = Buffer.from([
  0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e,
]);

/**
 * TideSSP AuthScheme GUID: {7A4E8B2C-1F3D-4A5E-9C6B-8D7E0F1A2B3C}
 * Must match the GUID in tide-ssp/src/ssp.c.
 * GUIDs are stored in mixed-endian (Microsoft) format.
 */
export const TIDESSP_AUTH_SCHEME = Buffer.from([
  0x2c, 0x8b, 0x4e, 0x7a, // Data1 LE
  0x3d, 0x1f,             // Data2 LE
  0x5e, 0x4a,             // Data3 LE
  0x9c, 0x6b,             // Data4[0..1] BE
  0x8d, 0x7e, 0x0f, 0x1a, 0x2b, 0x3c, // Data4[2..7] BE
]);

const CHECKSUM_SCHEME_RFC3961 = 1;
/** rc4-hmac checksum type (Microsoft HMAC-MD5) */
const CHECKSUM_TYPE_HMAC_MD5 = -138 & 0xffffffff; // unsigned representation

// ── Types ────────────────────────────────────────────────────────

export interface NegoexMessage {
  messageType: number;
  sequenceNum: number;
  conversationId: Buffer; // 16-byte GUID
  // Type-specific fields:
  authSchemes?: Buffer[]; // NEGO_MESSAGE: array of 16-byte GUIDs
  authScheme?: Buffer;    // EXCHANGE/VERIFY: single 16-byte GUID
  exchange?: Buffer;      // EXCHANGE: payload bytes
  checksum?: Buffer;      // VERIFY: checksum value
  checksumType?: number;  // VERIFY: checksum type
  random?: Buffer;        // NEGO: 32-byte random
}

// ── Message header layout (40 bytes) ─────────────────────────────
//
// Offset  Size  Field
// 0       8     Signature "NEGOEXTS"
// 8       4     MessageType
// 12      4     SequenceNum
// 16      4     cbHeaderLength
// 20      4     cbMessageLength
// 24      16    ConversationId (GUID)
//
const HEADER_SIZE = 40;

// ── Builders ─────────────────────────────────────────────────────

function writeHeader(
  buf: Buffer, offset: number,
  type: number, seqNum: number, headerLen: number, totalLen: number,
  conversationId: Buffer,
): void {
  NEGOEX_SIGNATURE.copy(buf, offset);
  buf.writeUInt32LE(type, offset + 8);
  buf.writeUInt32LE(seqNum, offset + 12);
  buf.writeUInt32LE(headerLen, offset + 16);
  buf.writeUInt32LE(totalLen, offset + 20);
  conversationId.copy(buf, offset + 24);
}

/**
 * Build NEGOEX NEGO_MESSAGE (initiator or acceptor).
 *
 * Layout after header (40 bytes):
 *   40: Random[32]
 *   72: ProtocolVersion (u64 LE) = 0
 *   80: AuthSchemes.ArrayOffset (u32)
 *   84: AuthSchemes.ArrayCount (u16)
 *   86: padding (u16) = 0
 *   88: Extensions.ArrayOffset (u32)
 *   92: Extensions.ArrayCount (u16)
 *   94: padding (u16) = 0
 *   96: AuthScheme GUIDs (16 bytes each)
 */
export function buildNegoMessage(
  type: typeof MSG_INITIATOR_NEGO | typeof MSG_ACCEPTOR_NEGO,
  conversationId: Buffer,
  seqNum: number,
  authSchemes: Buffer[],
): Buffer {
  const headerLen = 96; // fixed header portion
  const schemesSize = authSchemes.length * 16;
  const totalLen = headerLen + schemesSize;
  const buf = Buffer.alloc(totalLen);

  writeHeader(buf, 0, type, seqNum, headerLen, totalLen, conversationId);

  // Random[32]
  randomBytes(32).copy(buf, 40);

  // ProtocolVersion = 0 (u64 LE)
  buf.writeBigUInt64LE(0n, 72);

  // AuthSchemes vector
  buf.writeUInt32LE(headerLen, 80);      // offset to scheme array
  buf.writeUInt16LE(authSchemes.length, 84); // count
  buf.writeUInt16LE(0, 86);             // padding

  // Extensions vector (empty)
  buf.writeUInt32LE(0, 88);
  buf.writeUInt16LE(0, 92);
  buf.writeUInt16LE(0, 94);

  // Write auth scheme GUIDs
  let off = headerLen;
  for (const scheme of authSchemes) {
    scheme.copy(buf, off);
    off += 16;
  }

  return buf;
}

/**
 * Build NEGOEX EXCHANGE_MESSAGE (AP_REQUEST, CHALLENGE, META_DATA).
 *
 * Layout after header (40 bytes):
 *   40: AuthScheme (16 bytes GUID)
 *   56: Exchange.ByteArrayOffset (u32)
 *   60: Exchange.ByteArrayLength (u32)
 *   64: Exchange payload
 */
export function buildExchangeMessage(
  type: number, // MSG_AP_REQUEST, MSG_CHALLENGE, MSG_INITIATOR_META_DATA, etc.
  conversationId: Buffer,
  seqNum: number,
  authScheme: Buffer,
  payload: Buffer,
): Buffer {
  const headerLen = 64;
  const totalLen = headerLen + payload.length;
  const buf = Buffer.alloc(totalLen);

  writeHeader(buf, 0, type, seqNum, headerLen, totalLen, conversationId);

  // AuthScheme GUID
  authScheme.copy(buf, 40);

  // Exchange vector
  buf.writeUInt32LE(headerLen, 56);      // offset
  buf.writeUInt32LE(payload.length, 60); // length

  // Payload
  payload.copy(buf, headerLen);

  return buf;
}

/**
 * Build NEGOEX VERIFY_MESSAGE.
 *
 * Layout after header (40 bytes):
 *   40: AuthScheme (16 bytes GUID)
 *   56: Checksum.cbHeaderLength (u32) = 20
 *   60: Checksum.ChecksumScheme (u32)
 *   64: Checksum.ChecksumType (u32)
 *   68: Checksum.ChecksumValue.ByteArrayOffset (u32)
 *   72: Checksum.ChecksumValue.ByteArrayLength (u32)
 *   76: Checksum bytes
 */
export function buildVerifyMessage(
  conversationId: Buffer,
  seqNum: number,
  authScheme: Buffer,
  checksumValue: Buffer,
): Buffer {
  const headerLen = 76;
  const totalLen = headerLen + checksumValue.length;
  const buf = Buffer.alloc(totalLen);

  writeHeader(buf, 0, MSG_VERIFY, seqNum, headerLen, totalLen, conversationId);

  authScheme.copy(buf, 40);

  // Checksum structure
  buf.writeUInt32LE(20, 56);                     // cbHeaderLength
  buf.writeUInt32LE(CHECKSUM_SCHEME_RFC3961, 60); // ChecksumScheme
  buf.writeInt32LE(-138, 64);                     // ChecksumType (HMAC-MD5)
  buf.writeUInt32LE(headerLen, 68);               // value offset
  buf.writeUInt32LE(checksumValue.length, 72);    // value length

  checksumValue.copy(buf, headerLen);

  return buf;
}

// ── Parsers ──────────────────────────────────────────────────────

/**
 * Parse concatenated NEGOEX messages from a buffer.
 * Multiple messages can be concatenated in a single SPNEGO mechToken.
 */
export function parseNegoexMessages(data: Buffer): NegoexMessage[] {
  const messages: NegoexMessage[] = [];
  let pos = 0;

  while (pos + HEADER_SIZE <= data.length) {
    // Verify signature
    const sig = data.subarray(pos, pos + 8);
    if (!sig.equals(NEGOEX_SIGNATURE)) {
      throw new Error(`NEGOEX: invalid signature at offset ${pos}`);
    }

    const messageType = data.readUInt32LE(pos + 8);
    const sequenceNum = data.readUInt32LE(pos + 12);
    // const cbHeaderLength = data.readUInt32LE(pos + 16);
    const cbMessageLength = data.readUInt32LE(pos + 20);
    const conversationId = Buffer.from(data.subarray(pos + 24, pos + 40));

    if (pos + cbMessageLength > data.length) {
      throw new Error(`NEGOEX: message overflows buffer`);
    }

    const msg: NegoexMessage = { messageType, sequenceNum, conversationId };

    if (messageType === MSG_INITIATOR_NEGO || messageType === MSG_ACCEPTOR_NEGO) {
      // NEGO_MESSAGE
      if (cbMessageLength >= 96) {
        msg.random = Buffer.from(data.subarray(pos + 40, pos + 72));
        const schemesOffset = data.readUInt32LE(pos + 80);
        const schemesCount = data.readUInt16LE(pos + 84);
        msg.authSchemes = [];
        for (let i = 0; i < schemesCount; i++) {
          const schemePos = pos + schemesOffset + i * 16;
          if (schemePos + 16 <= pos + cbMessageLength) {
            msg.authSchemes.push(Buffer.from(data.subarray(schemePos, schemePos + 16)));
          }
        }
      }
    } else if (
      messageType === MSG_CHALLENGE ||
      messageType === MSG_AP_REQUEST ||
      messageType === MSG_INITIATOR_META_DATA ||
      messageType === MSG_ACCEPTOR_META_DATA
    ) {
      // EXCHANGE_MESSAGE
      if (cbMessageLength >= 64) {
        msg.authScheme = Buffer.from(data.subarray(pos + 40, pos + 56));
        const exchangeOffset = data.readUInt32LE(pos + 56);
        const exchangeLength = data.readUInt32LE(pos + 60);
        if (exchangeOffset + exchangeLength <= cbMessageLength) {
          msg.exchange = Buffer.from(data.subarray(pos + exchangeOffset, pos + exchangeOffset + exchangeLength));
        }
      }
    } else if (messageType === MSG_VERIFY) {
      // VERIFY_MESSAGE
      if (cbMessageLength >= 76) {
        msg.authScheme = Buffer.from(data.subarray(pos + 40, pos + 56));
        msg.checksumType = data.readInt32LE(pos + 64);
        const checksumOffset = data.readUInt32LE(pos + 68);
        const checksumLength = data.readUInt32LE(pos + 72);
        if (checksumOffset + checksumLength <= cbMessageLength) {
          msg.checksum = Buffer.from(data.subarray(pos + checksumOffset, pos + checksumOffset + checksumLength));
        }
      }
    }
    // MSG_ALERT: skip for now

    messages.push(msg);
    pos += cbMessageLength;
  }

  return messages;
}

// ── Session Key & Checksum ───────────────────────────────────────

/**
 * Derive the NEGOEX session key from JWT signature bytes.
 * Must match the derivation in tide-ssp/src/ssp.c deriveSessionKeyFromSig().
 *
 * sessionKey = SHA-256(jwt_signature_bytes)[0..15]
 */
export function deriveSessionKeyFromJwt(jwt: string): Buffer {
  const lastDot = jwt.lastIndexOf(".");
  if (lastDot < 0) throw new Error("Invalid JWT");
  const sigB64 = jwt.substring(lastDot + 1);
  const sigBytes = Buffer.from(sigB64, "base64url");
  return createHash("sha256")
    .update(sigBytes)
    .digest()
    .subarray(0, 16);
}

/**
 * Compute NEGOEX VERIFY checksum using rc4-hmac style HMAC-MD5.
 *
 * This follows the RFC 3961 checksum for rc4-hmac (enctype 23):
 *   Ksign = HMAC-MD5(key, "signaturekey\0")
 *   tmp = MD5(int32le(keyUsage) || data)
 *   checksum = HMAC-MD5(Ksign, tmp)
 *
 * @param sessionKey - 16-byte session key
 * @param keyUsage - 23 for initiator, 25 for acceptor
 * @param transcript - all prior NEGOEX messages concatenated
 */
export function computeVerifyChecksum(
  sessionKey: Buffer,
  keyUsage: number,
  transcript: Buffer,
): Buffer {
  // Ksign = HMAC-MD5(key, "signaturekey\0")
  const ksign = createHmac("md5", sessionKey)
    .update(Buffer.from("signaturekey\0", "ascii"))
    .digest();

  // tmp = MD5(int32le(keyUsage) || data)
  const usageBuf = Buffer.alloc(4);
  usageBuf.writeInt32LE(keyUsage, 0);
  const tmp = createHash("md5")
    .update(usageBuf)
    .update(transcript)
    .digest();

  // checksum = HMAC-MD5(Ksign, tmp)
  return createHmac("md5", ksign).update(tmp).digest();
}

/**
 * Generate a random NEGOEX conversation ID (GUID).
 */
export function generateConversationId(): Buffer {
  return randomBytes(16);
}
