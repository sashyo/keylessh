/**
 * TURN channel binding management.
 *
 * Channel numbers 0x4000-0x7FFF. Bindings expire after 600 seconds.
 * A channel binding also implicitly installs/refreshes a permission.
 */

import type { Allocation, ChannelBinding } from "./types.js";
import { CHANNEL_MIN, CHANNEL_MAX } from "../stun/constants.js";
import { installPermission } from "./permission-manager.js";

const CHANNEL_LIFETIME = 600; // seconds

/**
 * Bind a channel number to a peer address:port.
 * Returns false if the channel number is out of range.
 */
export function bindChannel(
  allocation: Allocation,
  channelNumber: number,
  peerAddress: string,
  peerPort: number
): boolean {
  if (channelNumber < CHANNEL_MIN || channelNumber > CHANNEL_MAX) {
    return false;
  }

  // Check for existing binding to a different peer
  const existing = allocation.channels.get(channelNumber);
  if (
    existing &&
    (existing.peerAddress !== peerAddress || existing.peerPort !== peerPort)
  ) {
    return false; // Channel already bound to a different peer
  }

  // Check if this peer is already bound to a different channel
  const peerKey = `${peerAddress}:${peerPort}`;
  const existingByPeer = allocation.channelsByPeer.get(peerKey);
  if (existingByPeer && existingByPeer.channelNumber !== channelNumber) {
    return false; // Peer already bound to a different channel
  }

  // Clear old timer if refreshing
  if (existing) {
    clearTimeout(existing.refreshTimer);
  }

  const binding: ChannelBinding = {
    channelNumber,
    peerAddress,
    peerPort,
    expiresAt: Date.now() + CHANNEL_LIFETIME * 1000,
    refreshTimer: setTimeout(() => {
      allocation.channels.delete(channelNumber);
      allocation.channelsByPeer.delete(peerKey);
    }, CHANNEL_LIFETIME * 1000),
  };

  allocation.channels.set(channelNumber, binding);
  allocation.channelsByPeer.set(peerKey, binding);

  // Channel binding implicitly installs a permission
  installPermission(allocation, peerAddress);

  return true;
}

/**
 * Look up a channel binding by channel number.
 */
export function getChannelByNumber(
  allocation: Allocation,
  channelNumber: number
): ChannelBinding | undefined {
  const binding = allocation.channels.get(channelNumber);
  if (!binding) return undefined;
  if (Date.now() > binding.expiresAt) {
    allocation.channels.delete(channelNumber);
    allocation.channelsByPeer.delete(
      `${binding.peerAddress}:${binding.peerPort}`
    );
    return undefined;
  }
  return binding;
}

/**
 * Look up a channel binding by peer address:port (for incoming relay data).
 */
export function getChannelByPeer(
  allocation: Allocation,
  peerAddress: string,
  peerPort: number
): ChannelBinding | undefined {
  const binding = allocation.channelsByPeer.get(`${peerAddress}:${peerPort}`);
  if (!binding) return undefined;
  if (Date.now() > binding.expiresAt) {
    allocation.channels.delete(binding.channelNumber);
    allocation.channelsByPeer.delete(`${peerAddress}:${peerPort}`);
    return undefined;
  }
  return binding;
}
