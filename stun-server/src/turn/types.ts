/**
 * TURN data structures.
 */

import type { Socket as DgramSocket } from "dgram";

export interface Allocation {
  key: string; // FiveTupleKey
  clientAddress: string;
  clientPort: number;
  protocol: "udp" | "tcp";
  relaySocket: DgramSocket;
  relayAddress: string;
  relayPort: number;
  lifetime: number; // seconds
  expiresAt: number; // Date.now() + lifetime*1000
  refreshTimer: ReturnType<typeof setTimeout>;
  permissions: Map<string, Permission>; // keyed by peer IP
  channels: Map<number, ChannelBinding>; // keyed by channel number
  channelsByPeer: Map<string, ChannelBinding>; // keyed by "ip:port"
}

export interface Permission {
  peerAddress: string;
  expiresAt: number;
  refreshTimer: ReturnType<typeof setTimeout>;
}

export interface ChannelBinding {
  channelNumber: number;
  peerAddress: string;
  peerPort: number;
  expiresAt: number;
  refreshTimer: ReturnType<typeof setTimeout>;
}

/**
 * Build a 5-tuple key for allocation lookup.
 */
export function makeFiveTupleKey(
  protocol: string,
  clientAddr: string,
  clientPort: number
): string {
  return `${protocol}:${clientAddr}:${clientPort}`;
}
