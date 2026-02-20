/**
 * STUN FINGERPRINT (CRC-32) and MESSAGE-INTEGRITY (HMAC-SHA1).
 *
 * FINGERPRINT = CRC-32(message) XOR 0x5354554e
 * MESSAGE-INTEGRITY = HMAC-SHA1(key, message)
 */

import { createHmac, createHash } from "crypto";
import { FINGERPRINT_XOR, ATTR_FINGERPRINT, ATTR_MESSAGE_INTEGRITY } from "./constants.js";

// ── CRC-32 lookup table ──────────────────────────────────────────

const crc32Table = new Uint32Array(256);

(function buildTable() {
  for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let j = 0; j < 8; j++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
    crc32Table[i] = crc >>> 0;
  }
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crc32Table[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ── FINGERPRINT ──────────────────────────────────────────────────

/**
 * Compute FINGERPRINT value for a STUN message.
 * The message buffer should include everything up to (but not including)
 * the FINGERPRINT attribute, with the header length adjusted to include
 * the FINGERPRINT (8 bytes: 4 header + 4 value).
 */
export function computeFingerprint(messageUpToFingerprint: Buffer): number {
  return (crc32(messageUpToFingerprint) ^ FINGERPRINT_XOR) >>> 0;
}

/**
 * Build a FINGERPRINT attribute and append it to a message.
 * Adjusts the header length field to include the fingerprint.
 */
export function appendFingerprint(message: Buffer): Buffer {
  const fpOffset = message.length;

  // Adjust header length to include FINGERPRINT (8 bytes)
  const workBuf = Buffer.from(message);
  const adjustedLen = fpOffset + 8 - 20; // 20 = STUN header size
  workBuf.writeUInt16BE(adjustedLen, 2);

  const fpValue = computeFingerprint(workBuf);

  const fpAttr = Buffer.alloc(8);
  fpAttr.writeUInt16BE(ATTR_FINGERPRINT, 0);
  fpAttr.writeUInt16BE(4, 2);
  fpAttr.writeUInt32BE(fpValue, 4);

  const result = Buffer.concat([message, fpAttr]);
  // Update final header length
  result.writeUInt16BE(result.length - 20, 2);
  return result;
}

/**
 * Validate the FINGERPRINT attribute on a received message.
 */
export function validateFingerprint(
  message: Buffer,
  fpOffset: number
): boolean {
  if (fpOffset + 8 > message.length) return false;

  const receivedFp = message.readUInt32BE(fpOffset + 4);

  const workBuf = Buffer.from(message);
  const adjustedLen = fpOffset + 8 - 20;
  workBuf.writeUInt16BE(adjustedLen, 2);

  const expectedFp = computeFingerprint(workBuf.subarray(0, fpOffset));
  return receivedFp === expectedFp;
}

// ── MESSAGE-INTEGRITY (HMAC-SHA1) ───────────────────────────────

/**
 * Derive the long-term credential key: MD5(username:realm:password).
 */
export function deriveLongTermKey(
  username: string,
  realm: string,
  password: string
): Buffer {
  return createHash("md5")
    .update(`${username}:${realm}:${password}`)
    .digest();
}

/**
 * Compute MESSAGE-INTEGRITY HMAC-SHA1 over a STUN message.
 *
 * The HMAC is computed over the message bytes up to (but not including)
 * the MESSAGE-INTEGRITY attribute, with the header length adjusted to
 * include the MESSAGE-INTEGRITY attribute (24 bytes: 4 header + 20 value).
 */
export function computeMessageIntegrity(
  messageUpToMI: Buffer,
  key: Buffer
): Buffer {
  // Adjust header length to include MESSAGE-INTEGRITY (24 bytes)
  const workBuf = Buffer.from(messageUpToMI);
  const adjustedLen = messageUpToMI.length + 24 - 20; // +24 for MI attr, -20 for STUN header
  workBuf.writeUInt16BE(adjustedLen, 2);

  return createHmac("sha1", key).update(workBuf).digest();
}

/**
 * Validate MESSAGE-INTEGRITY on a received STUN message.
 *
 * @param raw - The complete raw message buffer
 * @param miOffset - Byte offset where MESSAGE-INTEGRITY attribute starts
 * @param key - The HMAC key (from deriveLongTermKey)
 */
export function validateMessageIntegrity(
  raw: Buffer,
  miOffset: number,
  key: Buffer
): boolean {
  if (miOffset + 24 > raw.length) return false;

  // Extract the received HMAC (20 bytes after 4-byte TLV header)
  const receivedHmac = raw.subarray(miOffset + 4, miOffset + 24);

  // Compute expected HMAC over bytes before MESSAGE-INTEGRITY
  const expectedHmac = computeMessageIntegrity(
    raw.subarray(0, miOffset),
    key
  );

  return receivedHmac.equals(expectedHmac);
}

/**
 * Build a MESSAGE-INTEGRITY attribute and append it to a message.
 */
export function appendMessageIntegrity(message: Buffer, key: Buffer): Buffer {
  const hmac = computeMessageIntegrity(message, key);

  const miAttr = Buffer.alloc(24);
  miAttr.writeUInt16BE(ATTR_MESSAGE_INTEGRITY, 0);
  miAttr.writeUInt16BE(20, 2); // HMAC-SHA1 is always 20 bytes
  hmac.copy(miAttr, 4);

  const result = Buffer.concat([message, miAttr]);
  // Update header length to include MI
  result.writeUInt16BE(result.length - 20, 2);
  return result;
}
