/**
 * TURN REST API ephemeral credential validation.
 *
 * Implements the coturn-compatible "use-auth-secret" mechanism:
 *   - Username format: "{expiry_unix_timestamp}:{arbitrary}"
 *   - Password: base64(HMAC-SHA1(username, shared_secret))
 *   - Server validates by recomputing the password from the username + secret
 *
 * This ties into the STUN long-term credential mechanism (RFC 5389 §10.2):
 *   - key = MD5(username:realm:password)
 *   - MESSAGE-INTEGRITY = HMAC-SHA1(key, message)
 */

import { createHmac } from "crypto";
import type { StunMessage } from "../stun/message.js";
import { getAttribute } from "../stun/message.js";
import {
  ATTR_USERNAME,
  ATTR_REALM,
  ATTR_NONCE,
  ATTR_MESSAGE_INTEGRITY,
} from "../stun/constants.js";
import { parseUsername } from "../stun/attributes.js";
import {
  deriveLongTermKey,
  validateMessageIntegrity,
} from "../stun/integrity.js";

export interface TurnAuthResult {
  authenticated: boolean;
  /** If false, indicates reason for rejection */
  reason?: string;
  /** The validated username, if authenticated */
  username?: string;
}

/**
 * Generate the password for a given username using the shared secret.
 * This is the same computation the WAF uses when generating credentials.
 */
export function generatePassword(
  username: string,
  secret: string
): string {
  return createHmac("sha1", secret).update(username).digest("base64");
}

/**
 * Validate TURN credentials on a STUN message using the REST API approach.
 *
 * @param msg - Parsed STUN message
 * @param realm - Server realm
 * @param secret - Shared secret
 * @returns Authentication result
 */
export function validateTurnCredentials(
  msg: StunMessage,
  realm: string,
  secret: string
): TurnAuthResult {
  // Check for USERNAME attribute
  const usernameAttr = getAttribute(msg, ATTR_USERNAME);
  if (!usernameAttr) {
    return { authenticated: false, reason: "missing_credentials" };
  }

  const username = parseUsername(usernameAttr.value);

  // Check for MESSAGE-INTEGRITY attribute
  const miAttr = getAttribute(msg, ATTR_MESSAGE_INTEGRITY);
  if (!miAttr) {
    return { authenticated: false, reason: "missing_integrity" };
  }

  // Validate timestamp in username (format: "expiry:arbitrary")
  const colonIdx = username.indexOf(":");
  if (colonIdx > 0) {
    const expiry = parseInt(username.slice(0, colonIdx), 10);
    if (!isNaN(expiry) && expiry < Math.floor(Date.now() / 1000)) {
      return { authenticated: false, reason: "expired" };
    }
  }

  // Derive password from username + secret
  const password = generatePassword(username, secret);

  // Derive long-term credential key: MD5(username:realm:password)
  const key = deriveLongTermKey(username, realm, password);

  // Find MESSAGE-INTEGRITY offset in the raw message
  const miOffset = findAttributeOffset(msg.raw, ATTR_MESSAGE_INTEGRITY);
  if (miOffset < 0) {
    return { authenticated: false, reason: "integrity_not_found" };
  }

  // Validate MESSAGE-INTEGRITY
  if (!validateMessageIntegrity(msg.raw, miOffset, key)) {
    return { authenticated: false, reason: "integrity_mismatch" };
  }

  return { authenticated: true, username };
}

/**
 * Find the byte offset of an attribute in a raw STUN message.
 */
function findAttributeOffset(raw: Buffer, attrType: number): number {
  let offset = 20; // Skip STUN header
  const totalLen = raw.readUInt16BE(2) + 20;

  while (offset + 4 <= totalLen) {
    const type = raw.readUInt16BE(offset);
    const len = raw.readUInt16BE(offset + 2);

    if (type === attrType) {
      return offset;
    }

    // Advance past value + padding to 4-byte boundary
    offset += 4 + len + ((4 - (len % 4)) % 4);
  }

  return -1;
}
