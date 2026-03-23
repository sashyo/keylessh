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

import { randomBytes, createHmac, createHash, createCipheriv } from "crypto";

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
 *   76: (4 bytes padding for 8-byte alignment)
 *   80: Checksum bytes
 *
 * Windows NegoExtender uses headerLen=80 (with 4-byte alignment pad).
 */
export function buildVerifyMessage(
  conversationId: Buffer,
  seqNum: number,
  authScheme: Buffer,
  checksumValue: Buffer,
  checksumType: number,
): Buffer {
  const headerLen = 80; // matches Windows NegoExtender layout
  const totalLen = headerLen + checksumValue.length;
  const buf = Buffer.alloc(totalLen);

  writeHeader(buf, 0, MSG_VERIFY, seqNum, headerLen, totalLen, conversationId);

  authScheme.copy(buf, 40);

  // Checksum structure
  buf.writeUInt32LE(20, 56);                     // cbHeaderLength
  buf.writeUInt32LE(CHECKSUM_SCHEME_RFC3961, 60); // ChecksumScheme
  buf.writeInt32LE(checksumType, 64);             // ChecksumType
  buf.writeUInt32LE(headerLen, 68);               // value offset (80)
  buf.writeUInt32LE(checksumValue.length, 72);    // value length
  // bytes 76-79: zero padding (Buffer.alloc fills with 0)

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
        // Raw hex dump of CHECKSUM structure (offset 56-76 from message start)
        console.log(`[NEGOEX] VERIFY raw bytes [56..76]: ${data.subarray(pos + 56, pos + 76).toString("hex")}`);
        const cksumHeaderLen = data.readUInt32LE(pos + 56);
        const cksumScheme = data.readUInt32LE(pos + 60);
        msg.checksumType = data.readInt32LE(pos + 64);
        const checksumOffset = data.readUInt32LE(pos + 68);
        const checksumLength = data.readUInt32LE(pos + 72);
        console.log(`[NEGOEX] VERIFY checksum: hdrLen=${cksumHeaderLen}, scheme=${cksumScheme}, type=${msg.checksumType}, valueOffset=${checksumOffset}, valueLen=${checksumLength}`);
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
  console.log(`[NEGOEX] JWT sig bytes (${sigBytes.length}): ${sigBytes.subarray(0, 8).toString("hex")}...${sigBytes.subarray(60, 64).toString("hex")}`);
  const key = createHash("sha256")
    .update(sigBytes)
    .digest()
    .subarray(0, 16);
  return key;
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
 * Pure JS MD4 (RFC 1320) — needed because OpenSSL 3.x removed MD4.
 * checksumType=2 in NEGOEX VERIFY is rsa-md4.
 */
export function md4(data: Buffer): Buffer {
  const F = (x: number, y: number, z: number) => (x & y) | (~x & z);
  const G = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
  const H = (x: number, y: number, z: number) => x ^ y ^ z;
  const rotl = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0;

  // Padding
  const bitLen = data.length * 8;
  const padLen = (data.length % 64 < 56) ? 56 - (data.length % 64) : 120 - (data.length % 64);
  const padded = Buffer.alloc(data.length + padLen + 8);
  data.copy(padded);
  padded[data.length] = 0x80;
  padded.writeUInt32LE(bitLen >>> 0, padded.length - 8);
  padded.writeUInt32LE(Math.floor(bitLen / 0x100000000), padded.length - 4);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  for (let i = 0; i < padded.length; i += 64) {
    const X: number[] = [];
    for (let j = 0; j < 16; j++) X[j] = padded.readUInt32LE(i + j * 4);

    let a = a0, b = b0, c = c0, d = d0;

    // Round 1
    for (const [k, s] of [[0,3],[1,7],[2,11],[3,19],[4,3],[5,7],[6,11],[7,19],[8,3],[9,7],[10,11],[11,19],[12,3],[13,7],[14,11],[15,19]]) {
      const t = ((a + F(b, c, d) + X[k]) & 0xffffffff) >>> 0;
      a = d; d = c; c = b; b = rotl(t, s);
    }
    // Round 2
    for (const [k, s] of [[0,3],[4,5],[8,9],[12,13],[1,3],[5,5],[9,9],[13,13],[2,3],[6,5],[10,9],[14,13],[3,3],[7,5],[11,9],[15,13]]) {
      const t = ((a + G(b, c, d) + X[k] + 0x5A827999) & 0xffffffff) >>> 0;
      a = d; d = c; c = b; b = rotl(t, s);
    }
    // Round 3
    for (const [k, s] of [[0,3],[8,9],[4,11],[12,15],[2,3],[10,9],[6,11],[14,15],[1,3],[9,9],[5,11],[13,15],[3,3],[11,9],[7,11],[15,15]]) {
      const t = ((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xffffffff) >>> 0;
      a = d; d = c; c = b; b = rotl(t, s);
    }

    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }

  const out = Buffer.alloc(16);
  out.writeUInt32LE(a0, 0); out.writeUInt32LE(b0, 4); out.writeUInt32LE(c0, 8); out.writeUInt32LE(d0, 12);
  return out;
}

// ── RFC 3961 AES-128 Key Derivation & Checksum ──────────────────

function gcd(a: number, b: number): number {
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

/**
 * RFC 3961 n-fold: fold input bytes to outBits bits.
 * Replicates input with 13-bit RIGHT rotation per copy, then ones-complement
 * sums successive output-sized chunks.
 */
function nfold(input: Buffer, outBits: number): Buffer {
  const inLen = input.length;
  const inBits = inLen * 8;
  const outLen = outBits / 8;
  const lcmBytes = (inLen * outLen) / gcd(inLen, outLen);

  const out = Buffer.alloc(outLen, 0);
  let carry = 0;

  for (let i = lcmBytes - 1; i >= 0; i--) {
    const copy = Math.floor(i / inLen);
    const offset = i % inLen;
    const rotation = (13 * copy) % inBits;

    // RIGHT rotation: output bit q comes from input bit (q - rotation) mod inBits
    const srcStart = ((offset * 8 - rotation) % inBits + inBits) % inBits;
    const srcByte = Math.floor(srcStart / 8);
    const srcBit = srcStart % 8;

    const b1 = input[srcByte % inLen];
    const b2 = input[(srcByte + 1) % inLen];
    const val = srcBit === 0
      ? b1
      : ((b1 << srcBit) | (b2 >>> (8 - srcBit))) & 0xff;

    carry += val + out[i % outLen];
    out[i % outLen] = carry & 0xff;
    carry >>>= 8;
  }

  // Propagate remaining carry (ones-complement end-around)
  if (carry) {
    for (let i = outLen - 1; i >= 0; i--) {
      carry += out[i];
      out[i] = carry & 0xff;
      carry >>>= 8;
    }
  }

  return out;
}

/**
 * RFC 3961 DK(base_key, constant) for AES-128.
 * DR: AES-ECB iterations until enough key material.
 * For AES-128: key_size = block_size = 16, so one AES-ECB block suffices.
 */
function dk(baseKey: Buffer, constant: Buffer): Buffer {
  const folded = nfold(constant, 128);
  const cipher = createCipheriv("aes-128-ecb", baseKey, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(folded), cipher.final()]);
}

/** Checksum type 15: hmac-sha1-96-aes128 */
export const CHECKSUM_TYPE_HMAC_SHA1_96_AES128 = 15;

/**
 * Compute hmac-sha1-96-aes128 checksum (RFC 3962, type 15).
 * 1. Kc = DK(base_key, pack_be32(keyUsage) || 0x99)
 * 2. checksum = HMAC-SHA1(Kc, data)[0:12]
 *
 * RFC 3961 Section 3: standalone checksums use Kc (0x99),
 * NOT Ki (0x55) which is for integrity inside encryption.
 *
 * @param sessionKey - 16-byte AES-128 session key
 * @param keyUsage - 23 for initiator, 25 for acceptor
 * @param data - transcript data to checksum
 */
export function computeAes128Checksum(
  sessionKey: Buffer,
  keyUsage: number,
  data: Buffer,
): Buffer {
  const constant = Buffer.alloc(5);
  constant.writeUInt32BE(keyUsage, 0);
  constant[4] = 0x99; // 0x99 = checksum key derivation (Kc)

  const kc = dk(sessionKey, constant);
  return createHmac("sha1", kc).update(data).digest().subarray(0, 12);
}

/** Debug variant using Ki (0x55) instead of Kc (0x99) */
export function computeAes128ChecksumKi(
  sessionKey: Buffer,
  keyUsage: number,
  data: Buffer,
): Buffer {
  const constant = Buffer.alloc(5);
  constant.writeUInt32BE(keyUsage, 0);
  constant[4] = 0x55;
  const ki = dk(sessionKey, constant);
  return createHmac("sha1", ki).update(data).digest().subarray(0, 12);
}

/**
 * Build an RFC 4121 GSS_GetMIC token for SPNEGO mechListMIC.
 *
 * RFC 4121 section 4.2.6.1 MIC token format:
 *   Byte 0-1:  TOK_ID    = 04 04
 *   Byte 2:    Flags     (0x00 for initiator, 0x01 for acceptor)
 *   Byte 3-7:  Filler    = FF FF FF FF FF
 *   Byte 8-15: SND_SEQ   (big-endian sequence number)
 *   Byte 16+:  SGN_CKSUM = HMAC-SHA1(Kc, header[0..15] || message)[0:12]
 *
 * Kc = DK(base_key, usage || 0x99)  (RFC 3961: Kc for checksums, NOT Ki)
 *
 * @param sessionKey - 16-byte AES-128 session key
 * @param keyUsage - key usage (25 for initiator sign, 26 for acceptor sign)
 * @param seqNum - sequence number (0 for first MIC)
 * @param message - data to compute MIC over
 */
export function buildRfc4121Mic(
  sessionKey: Buffer,
  keyUsage: number,
  seqNum: number,
  message: Buffer,
): Buffer {
  // Build 16-byte header
  const header = Buffer.alloc(16);
  header.writeUInt16BE(0x0404, 0);    // TOK_ID
  header[2] = 0x00;                    // Flags: sent by initiator
  header.fill(0xff, 3, 8);            // Filler
  // SND_SEQ at bytes 8-15 (big-endian)
  header.writeUInt32BE(0, 8);          // high 32 bits
  header.writeUInt32BE(seqNum, 12);    // low 32 bits

  // Kc = DK(sessionKey, usage || 0x99) — RFC 3961 checksum key
  const constant = Buffer.alloc(5);
  constant.writeUInt32BE(keyUsage, 0);
  constant[4] = 0x99;
  const kc = dk(sessionKey, constant);

  // SGN_CKSUM = HMAC-SHA1(Kc, header || message)[0:12]
  const sgn = createHmac("sha1", kc)
    .update(header)
    .update(message)
    .digest()
    .subarray(0, 12);

  return Buffer.concat([header, sgn]);
}

/**
 * Generate a random NEGOEX conversation ID (GUID).
 */
export function generateConversationId(): Buffer {
  return randomBytes(16);
}
