/**
 * STUN message header (20 bytes) parse/build.
 *
 * Header format:
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |0 0|     STUN Message Type     |         Message Length        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Magic Cookie                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Transaction ID (96 bits)                  |
 *  |                                                               |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

import { randomBytes } from "crypto";
import {
  MAGIC_COOKIE,
  MAGIC_COOKIE_BUF,
  HEADER_LENGTH,
  encodeMessageType,
  decodeMessageType,
} from "./constants.js";

export interface StunHeader {
  method: number;
  msgClass: number;
  length: number; // payload length (excludes 20-byte header)
  transactionId: Buffer; // 12 bytes
}

/**
 * Parse the first 20 bytes of a buffer into a StunHeader.
 * Returns null if the buffer is not a valid STUN header.
 */
export function parseHeader(buf: Buffer): StunHeader | null {
  if (buf.length < HEADER_LENGTH) return null;

  // First two bits must be 00
  if ((buf[0] & 0xc0) !== 0) return null;

  const type = buf.readUInt16BE(0);
  const length = buf.readUInt16BE(2);
  const cookie = buf.readUInt32BE(4);

  if (cookie !== MAGIC_COOKIE) return null;

  // Length must be a multiple of 4
  if (length % 4 !== 0) return null;

  const transactionId = Buffer.alloc(12);
  buf.copy(transactionId, 0, 8, 20);

  const { method, msgClass } = decodeMessageType(type);

  return { method, msgClass, length, transactionId };
}

/**
 * Build a 20-byte STUN header.
 */
export function buildHeader(
  method: number,
  msgClass: number,
  transactionId: Buffer,
  length: number
): Buffer {
  const header = Buffer.alloc(HEADER_LENGTH);
  header.writeUInt16BE(encodeMessageType(method, msgClass), 0);
  header.writeUInt16BE(length, 2);
  MAGIC_COOKIE_BUF.copy(header, 4);
  transactionId.copy(header, 8);
  return header;
}

/**
 * Generate a cryptographically random 12-byte transaction ID.
 */
export function generateTransactionId(): Buffer {
  return randomBytes(12);
}
