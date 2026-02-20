/**
 * Packet type detection.
 *
 * STUN messages and ChannelData share the same port and are
 * distinguished by the first two bits of the first byte:
 *   00 = STUN message
 *   01 = ChannelData (0x4000-0x7FFF)
 */

/**
 * Check if a buffer is a STUN message (first two bits are 00).
 */
export function isStunMessage(buf: Buffer): boolean {
  return buf.length >= 20 && (buf[0] & 0xc0) === 0x00;
}

/**
 * Check if a buffer is ChannelData (first byte 0x40-0x7F).
 */
export function isChannelData(buf: Buffer): boolean {
  return buf.length >= 4 && (buf[0] & 0xc0) === 0x40;
}
