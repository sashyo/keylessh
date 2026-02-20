/**
 * TURN relay logic.
 *
 * Two relay mechanisms:
 *   1. Send/Data indications (36+ byte overhead per packet)
 *   2. ChannelData messages (4 byte overhead per packet)
 */

import type { Allocation } from "./types.js";
import { getChannelByNumber, getChannelByPeer } from "./channel-manager.js";
import { hasPermission } from "./permission-manager.js";
import {
  METHOD_DATA,
  CLASS_INDICATION,
  ATTR_XOR_PEER_ADDRESS,
  ATTR_DATA,
} from "../stun/constants.js";
import { buildXorPeerAddress, buildData } from "../stun/attributes.js";
import { buildMessage } from "../stun/message.js";
import { generateTransactionId } from "../stun/header.js";

// ── ChannelData parse/build ──────────────────────────────────────

/**
 * Parse a ChannelData frame.
 * Format: channelNumber (2 bytes) | length (2 bytes) | data
 */
export function parseChannelData(
  buf: Buffer
): { channelNumber: number; data: Buffer } | null {
  if (buf.length < 4) return null;
  const channelNumber = buf.readUInt16BE(0);
  if (channelNumber < 0x4000 || channelNumber > 0x7fff) return null;
  const length = buf.readUInt16BE(2);
  if (buf.length < 4 + length) return null;
  return { channelNumber, data: buf.subarray(4, 4 + length) };
}

/**
 * Build a ChannelData frame.
 */
export function buildChannelData(
  channelNumber: number,
  data: Buffer
): Buffer {
  const padLen = (4 - (data.length % 4)) % 4;
  const frame = Buffer.alloc(4 + data.length + padLen);
  frame.writeUInt16BE(channelNumber, 0);
  frame.writeUInt16BE(data.length, 2);
  data.copy(frame, 4);
  return frame;
}

// ── Relay: peer → client ─────────────────────────────────────────

/**
 * Called when the relay socket receives data from a peer.
 * Routes to client via ChannelData (if bound) or Data indication.
 */
export function handleRelayData(
  allocation: Allocation,
  peerAddress: string,
  peerPort: number,
  data: Buffer,
  sendToClient: (buf: Buffer) => void
): void {
  // Try ChannelData first (more efficient)
  const channel = getChannelByPeer(allocation, peerAddress, peerPort);
  if (channel) {
    sendToClient(buildChannelData(channel.channelNumber, data));
    return;
  }

  // Fall back to Data indication
  const txnId = generateTransactionId();
  const attrs = [
    buildXorPeerAddress(peerAddress, peerPort, txnId),
    buildData(data),
  ];
  const indication = buildMessage(
    METHOD_DATA,
    CLASS_INDICATION,
    txnId,
    attrs,
    false // no fingerprint on indications
  );
  sendToClient(indication);
}

// ── Relay: client → peer (Send indication) ───────────────────────

/**
 * Forward data from client to a peer via the relay socket.
 * Used by Send indication handler.
 */
export function sendToRelay(
  allocation: Allocation,
  peerAddress: string,
  peerPort: number,
  data: Buffer
): void {
  if (!hasPermission(allocation, peerAddress)) {
    return; // No permission — drop
  }
  allocation.relaySocket.send(data, 0, data.length, peerPort, peerAddress);
}

// ── Relay: client → peer (ChannelData) ───────────────────────────

/**
 * Forward ChannelData from client to the bound peer.
 */
export function handleChannelDataFromClient(
  allocation: Allocation,
  channelNumber: number,
  data: Buffer
): void {
  const binding = getChannelByNumber(allocation, channelNumber);
  if (!binding) return; // No binding — drop

  allocation.relaySocket.send(
    data,
    0,
    data.length,
    binding.peerPort,
    binding.peerAddress
  );
}
