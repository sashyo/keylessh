/**
 * Full STUN message parse/build.
 */

import { HEADER_LENGTH, CLASS_ERROR, SOFTWARE_NAME } from "./constants.js";
import { StunHeader, parseHeader, buildHeader } from "./header.js";
import {
  StunAttribute,
  parseAttributes,
  findAttribute,
  buildErrorCode,
  buildSoftware,
} from "./attributes.js";
import { appendFingerprint, appendMessageIntegrity } from "./integrity.js";

export interface StunMessage {
  header: StunHeader;
  attributes: StunAttribute[];
  raw: Buffer; // original raw bytes
}

/**
 * Parse a complete STUN message from a raw buffer.
 */
export function parseMessage(buf: Buffer): StunMessage | null {
  const header = parseHeader(buf);
  if (!header) return null;

  const totalLength = HEADER_LENGTH + header.length;
  if (buf.length < totalLength) return null;

  const attrBuf = buf.subarray(HEADER_LENGTH, totalLength);
  const attributes = parseAttributes(attrBuf, header.length);

  return {
    header,
    attributes,
    raw: buf.subarray(0, totalLength),
  };
}

/**
 * Build a complete STUN message buffer.
 *
 * @param method - STUN method
 * @param msgClass - STUN class (request, indication, success, error)
 * @param transactionId - 12-byte transaction ID
 * @param attrBuffers - Pre-built attribute buffers (from buildXxx functions)
 * @param options - addFingerprint (default true), integrityKey (optional HMAC key for MESSAGE-INTEGRITY)
 */
export function buildMessage(
  method: number,
  msgClass: number,
  transactionId: Buffer,
  attrBuffers: Buffer[],
  options?: boolean | { addFingerprint?: boolean; integrityKey?: Buffer }
): Buffer {
  const opts =
    typeof options === "boolean"
      ? { addFingerprint: options }
      : options ?? {};
  const addFp = opts.addFingerprint !== false;
  const integrityKey = opts.integrityKey;

  const body = Buffer.concat(attrBuffers);
  const header = buildHeader(method, msgClass, transactionId, body.length);
  let message = Buffer.from(Buffer.concat([header, body]));

  // MESSAGE-INTEGRITY must come before FINGERPRINT (RFC 5389 §15.4)
  if (integrityKey) {
    message = Buffer.from(appendMessageIntegrity(message, integrityKey));
  }

  if (addFp) {
    message = Buffer.from(appendFingerprint(message));
  }

  return message;
}

/**
 * Build an error response for a given request.
 */
export function buildErrorResponse(
  request: StunMessage,
  errorCode: number,
  reason: string,
  extraAttributes: Buffer[] = []
): Buffer {
  const attrs = [
    buildErrorCode(errorCode, reason),
    ...extraAttributes,
    buildSoftware(SOFTWARE_NAME),
  ];

  return buildMessage(
    request.header.method,
    CLASS_ERROR,
    request.header.transactionId,
    attrs
  );
}

/**
 * Convenience: find an attribute by type in a StunMessage.
 */
export function getAttribute(
  msg: StunMessage,
  type: number
): StunAttribute | undefined {
  return findAttribute(msg.attributes, type);
}
