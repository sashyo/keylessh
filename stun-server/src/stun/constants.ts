/**
 * STUN/TURN protocol constants (RFC 5389, RFC 5766)
 */

// STUN header
export const MAGIC_COOKIE = 0x2112a442;
export const MAGIC_COOKIE_BUF = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
export const HEADER_LENGTH = 20;

// Message classes (2-bit, interleaved into message type)
export const CLASS_REQUEST = 0x00;
export const CLASS_INDICATION = 0x01;
export const CLASS_SUCCESS = 0x02;
export const CLASS_ERROR = 0x03;

// STUN methods
export const METHOD_BINDING = 0x001;

// TURN methods
export const METHOD_ALLOCATE = 0x003;
export const METHOD_REFRESH = 0x004;
export const METHOD_SEND = 0x006;
export const METHOD_DATA = 0x007;
export const METHOD_CREATE_PERMISSION = 0x008;
export const METHOD_CHANNEL_BIND = 0x009;

// STUN attribute types
export const ATTR_MAPPED_ADDRESS = 0x0001;
export const ATTR_USERNAME = 0x0006;
export const ATTR_MESSAGE_INTEGRITY = 0x0008;
export const ATTR_ERROR_CODE = 0x0009;
export const ATTR_UNKNOWN_ATTRIBUTES = 0x000a;
export const ATTR_REALM = 0x0014;
export const ATTR_NONCE = 0x0015;
export const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
export const ATTR_SOFTWARE = 0x8022;
export const ATTR_FINGERPRINT = 0x8028;

// TURN attribute types
export const ATTR_CHANNEL_NUMBER = 0x000c;
export const ATTR_LIFETIME = 0x000d;
export const ATTR_XOR_PEER_ADDRESS = 0x0012;
export const ATTR_DATA = 0x0013;
export const ATTR_XOR_RELAYED_ADDRESS = 0x0016;
export const ATTR_REQUESTED_ADDRESS_FAMILY = 0x0017;
export const ATTR_EVEN_PORT = 0x0018;
export const ATTR_REQUESTED_TRANSPORT = 0x0019;
export const ATTR_DONT_FRAGMENT = 0x001a;

// Transport protocol numbers
export const TRANSPORT_UDP = 17;
export const TRANSPORT_TCP = 6;

// Address families
export const FAMILY_IPV4 = 0x01;
export const FAMILY_IPV6 = 0x02;

// Error codes
export const ERR_TRY_ALTERNATE = 300;
export const ERR_BAD_REQUEST = 400;
export const ERR_UNAUTHORIZED = 401;
export const ERR_FORBIDDEN = 403;
export const ERR_UNKNOWN_ATTRIBUTE = 420;
export const ERR_ALLOCATION_MISMATCH = 437;
export const ERR_STALE_NONCE = 438;
export const ERR_WRONG_CREDENTIALS = 441;
export const ERR_UNSUPPORTED_TRANSPORT = 442;
export const ERR_ALLOCATION_QUOTA = 486;
export const ERR_INSUFFICIENT_CAPACITY = 508;

// Channel number range for TURN ChannelData
export const CHANNEL_MIN = 0x4000;
export const CHANNEL_MAX = 0x7fff;

// Fingerprint XOR constant
export const FINGERPRINT_XOR = 0x5354554e;

// Software name
export const SOFTWARE_NAME = "KeyleSSH-STUN/1.0";

/**
 * Encode method + class into 16-bit message type.
 * Bits are interleaved per RFC 5389 Section 6:
 *   M11-M7 | C1 | M6-M4 | C0 | M3-M0
 */
export function encodeMessageType(method: number, msgClass: number): number {
  return (
    (method & 0x000f) |
    ((msgClass & 0x1) << 4) |
    ((method & 0x0070) << 1) |
    ((msgClass & 0x2) << 7) |
    ((method & 0x0f80) << 2)
  );
}

/**
 * Decode 16-bit message type into method + class.
 */
export function decodeMessageType(type: number): {
  method: number;
  msgClass: number;
} {
  const C0 = (type >> 4) & 0x1;
  const C1 = (type >> 8) & 0x1;
  const msgClass = (C1 << 1) | C0;
  const method =
    (type & 0x000f) | ((type >> 1) & 0x0070) | ((type >> 2) & 0x0f80);
  return { method, msgClass };
}
