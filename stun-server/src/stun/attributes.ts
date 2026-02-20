/**
 * STUN attribute TLV parse/build.
 *
 * Each attribute:
 *   Type (16 bits) | Length (16 bits) | Value (variable, padded to 4 bytes)
 */

import {
  MAGIC_COOKIE,
  MAGIC_COOKIE_BUF,
  FAMILY_IPV4,
  FAMILY_IPV6,
  ATTR_MAPPED_ADDRESS,
  ATTR_XOR_MAPPED_ADDRESS,
  ATTR_XOR_RELAYED_ADDRESS,
  ATTR_XOR_PEER_ADDRESS,
  ATTR_ERROR_CODE,
  ATTR_LIFETIME,
  ATTR_REALM,
  ATTR_NONCE,
  ATTR_SOFTWARE,
  ATTR_USERNAME,
  ATTR_CHANNEL_NUMBER,
  ATTR_DATA,
  ATTR_REQUESTED_TRANSPORT,
  ATTR_UNKNOWN_ATTRIBUTES,
} from "./constants.js";

export interface StunAttribute {
  type: number;
  value: Buffer;
}

export interface AddressInfo {
  family: number; // FAMILY_IPV4 or FAMILY_IPV6
  address: string;
  port: number;
}

// ── Attribute parsing ────────────────────────────────────────────

/**
 * Parse all TLV attributes from a buffer (starting after the 20-byte header).
 */
export function parseAttributes(buf: Buffer, length: number): StunAttribute[] {
  const attrs: StunAttribute[] = [];
  let offset = 0;

  while (offset + 4 <= length) {
    const type = buf.readUInt16BE(offset);
    const attrLen = buf.readUInt16BE(offset + 2);
    const value = buf.subarray(offset + 4, offset + 4 + attrLen);
    attrs.push({ type, value });
    // Advance past value + padding to 4-byte boundary
    offset += 4 + attrLen + ((4 - (attrLen % 4)) % 4);
  }

  return attrs;
}

/**
 * Find an attribute by type.
 */
export function findAttribute(
  attrs: StunAttribute[],
  type: number
): StunAttribute | undefined {
  return attrs.find((a) => a.type === type);
}

// ── XOR address decode ───────────────────────────────────────────

/**
 * Decode an XOR-MAPPED-ADDRESS, XOR-RELAYED-ADDRESS, or XOR-PEER-ADDRESS.
 */
export function decodeXorAddress(
  value: Buffer,
  transactionId: Buffer
): AddressInfo | null {
  if (value.length < 8) return null;

  const family = value.readUInt8(1);
  const xPort = value.readUInt16BE(2);
  const port = xPort ^ 0x2112;

  if (family === FAMILY_IPV4) {
    const xAddr = value.readUInt32BE(4);
    const addr = (xAddr ^ MAGIC_COOKIE) >>> 0;
    const address = [
      (addr >> 24) & 0xff,
      (addr >> 16) & 0xff,
      (addr >> 8) & 0xff,
      addr & 0xff,
    ].join(".");
    return { family, address, port };
  } else if (family === FAMILY_IPV6) {
    if (value.length < 20) return null;
    const xorMask = Buffer.concat([MAGIC_COOKIE_BUF, transactionId]);
    const addrBytes: number[] = [];
    for (let i = 0; i < 16; i++) {
      addrBytes.push(value[4 + i] ^ xorMask[i]);
    }
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((addrBytes[i] << 8) | addrBytes[i + 1]).toString(16));
    }
    return { family, address: parts.join(":"), port };
  }

  return null;
}

/**
 * Decode a MAPPED-ADDRESS (not XOR'd).
 */
export function decodeMappedAddress(value: Buffer): AddressInfo | null {
  if (value.length < 8) return null;

  const family = value.readUInt8(1);
  const port = value.readUInt16BE(2);

  if (family === FAMILY_IPV4) {
    const address = [value[4], value[5], value[6], value[7]].join(".");
    return { family, address, port };
  }

  return null;
}

// ── Attribute builders ───────────────────────────────────────────

/**
 * Build a single TLV attribute with 4-byte padding.
 */
export function buildAttribute(type: number, value: Buffer): Buffer {
  const padLen = (4 - (value.length % 4)) % 4;
  const buf = Buffer.alloc(4 + value.length + padLen);
  buf.writeUInt16BE(type, 0);
  buf.writeUInt16BE(value.length, 2);
  value.copy(buf, 4);
  return buf;
}

/**
 * Build an XOR-encoded address attribute (IPv4).
 */
function buildXorAddressValue(
  address: string,
  port: number,
  transactionId: Buffer,
  family: number = FAMILY_IPV4
): Buffer {
  if (family === FAMILY_IPV4) {
    const buf = Buffer.alloc(8);
    buf.writeUInt8(0, 0); // reserved
    buf.writeUInt8(FAMILY_IPV4, 1);
    buf.writeUInt16BE(port ^ 0x2112, 2);

    const parts = address.split(".").map(Number);
    const ipNum =
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>>
      0;
    buf.writeUInt32BE((ipNum ^ MAGIC_COOKIE) >>> 0, 4);
    return buf;
  } else {
    // IPv6
    const buf = Buffer.alloc(20);
    buf.writeUInt8(0, 0);
    buf.writeUInt8(FAMILY_IPV6, 1);
    buf.writeUInt16BE(port ^ 0x2112, 2);

    const xorMask = Buffer.concat([MAGIC_COOKIE_BUF, transactionId]);
    const segments = address.split(":").map((s) => parseInt(s, 16));
    for (let i = 0; i < 8; i++) {
      const hi = (segments[i] >> 8) & 0xff;
      const lo = segments[i] & 0xff;
      buf[4 + i * 2] = hi ^ xorMask[i * 2];
      buf[4 + i * 2 + 1] = lo ^ xorMask[i * 2 + 1];
    }
    return buf;
  }
}

export function buildXorMappedAddress(
  address: string,
  port: number,
  transactionId: Buffer
): Buffer {
  return buildAttribute(
    ATTR_XOR_MAPPED_ADDRESS,
    buildXorAddressValue(address, port, transactionId)
  );
}

export function buildXorRelayedAddress(
  address: string,
  port: number,
  transactionId: Buffer
): Buffer {
  return buildAttribute(
    ATTR_XOR_RELAYED_ADDRESS,
    buildXorAddressValue(address, port, transactionId)
  );
}

export function buildXorPeerAddress(
  address: string,
  port: number,
  transactionId: Buffer
): Buffer {
  return buildAttribute(
    ATTR_XOR_PEER_ADDRESS,
    buildXorAddressValue(address, port, transactionId)
  );
}

export function buildErrorCode(code: number, reason: string): Buffer {
  const reasonBuf = Buffer.from(reason, "utf8");
  const val = Buffer.alloc(4 + reasonBuf.length);
  val.writeUInt16BE(0, 0); // reserved
  val.writeUInt8(Math.floor(code / 100) & 0x07, 2); // class
  val.writeUInt8(code % 100, 3); // number
  reasonBuf.copy(val, 4);
  return buildAttribute(ATTR_ERROR_CODE, val);
}

export function buildLifetime(seconds: number): Buffer {
  const val = Buffer.alloc(4);
  val.writeUInt32BE(seconds, 0);
  return buildAttribute(ATTR_LIFETIME, val);
}

export function buildRealm(realm: string): Buffer {
  return buildAttribute(ATTR_REALM, Buffer.from(realm, "utf8"));
}

export function buildNonce(nonce: string): Buffer {
  return buildAttribute(ATTR_NONCE, Buffer.from(nonce, "utf8"));
}

export function buildSoftware(name: string): Buffer {
  return buildAttribute(ATTR_SOFTWARE, Buffer.from(name, "utf8"));
}

export function buildUsername(username: string): Buffer {
  return buildAttribute(ATTR_USERNAME, Buffer.from(username, "utf8"));
}

export function buildChannelNumber(channel: number): Buffer {
  const val = Buffer.alloc(4);
  val.writeUInt16BE(channel, 0);
  // bytes 2-3 reserved
  return buildAttribute(ATTR_CHANNEL_NUMBER, val);
}

export function buildData(data: Buffer): Buffer {
  return buildAttribute(ATTR_DATA, data);
}

export function buildRequestedTransport(protocol: number): Buffer {
  const val = Buffer.alloc(4);
  val.writeUInt8(protocol, 0);
  // bytes 1-3 reserved
  return buildAttribute(ATTR_REQUESTED_TRANSPORT, val);
}

export function buildUnknownAttributes(types: number[]): Buffer {
  const val = Buffer.alloc(types.length * 2);
  for (let i = 0; i < types.length; i++) {
    val.writeUInt16BE(types[i], i * 2);
  }
  return buildAttribute(ATTR_UNKNOWN_ATTRIBUTES, val);
}

// ── Attribute value parsers ──────────────────────────────────────

export function parseLifetime(value: Buffer): number {
  return value.readUInt32BE(0);
}

export function parseChannelNumber(value: Buffer): number {
  return value.readUInt16BE(0);
}

export function parseUsername(value: Buffer): string {
  return value.toString("utf8");
}

export function parseRealm(value: Buffer): string {
  return value.toString("utf8");
}

export function parseNonce(value: Buffer): string {
  return value.toString("utf8");
}

export function parseRequestedTransport(value: Buffer): number {
  return value.readUInt8(0);
}

export function parseErrorCode(value: Buffer): {
  code: number;
  reason: string;
} {
  const cls = value[2] & 0x07;
  const number = value[3];
  const code = cls * 100 + number;
  const reason = value.subarray(4).toString("utf8");
  return { code, reason };
}
