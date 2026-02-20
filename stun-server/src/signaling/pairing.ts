/**
 * Pairing logic: matches clients with WAF instances
 * and exchanges their addresses.
 */

import type { Registry } from "./registry.js";

/**
 * Attempt to pair a client with an available WAF.
 * Sends pairing messages to both parties via WebSocket.
 */
export function pairClient(
  registry: Registry,
  clientId: string
): boolean {
  const client = registry.getClient(clientId);
  if (!client) return false;

  const waf = registry.getAvailableWaf();
  if (!waf) {
    // No WAFs available — notify client
    safeSend(client.ws, {
      type: "error",
      message: "No WAF instances available",
    });
    return false;
  }

  // Link them
  client.pairedWafId = waf.id;
  waf.pairedClients.add(clientId);

  // Notify client of their paired WAF
  safeSend(client.ws, {
    type: "paired",
    waf: {
      id: waf.id,
      addresses: waf.addresses,
    },
  });

  // Notify WAF of their new client
  safeSend(waf.ws, {
    type: "paired",
    client: {
      id: clientId,
      reflexiveAddress: client.reflexiveAddress || null,
    },
  });

  console.log(`[Signal] Paired client ${clientId} with WAF ${waf.id}`);
  return true;
}

/**
 * Pair a client with a specific WAF by ID (explicit selection from portal).
 */
export function pairClientWithWaf(
  registry: Registry,
  clientId: string,
  wafId: string
): boolean {
  const client = registry.getClient(clientId);
  if (!client) return false;

  const waf = registry.getWaf(wafId);
  if (!waf) {
    safeSend(client.ws, {
      type: "error",
      message: `WAF ${wafId} not found or offline`,
    });
    return false;
  }

  client.pairedWafId = waf.id;
  waf.pairedClients.add(clientId);

  safeSend(client.ws, {
    type: "paired",
    waf: { id: waf.id, addresses: waf.addresses },
  });

  safeSend(waf.ws, {
    type: "paired",
    client: { id: clientId, reflexiveAddress: client.reflexiveAddress || null },
  });

  console.log(`[Signal] Paired client ${clientId} with WAF ${wafId} (explicit)`);
  return true;
}

/**
 * Forward an SDP offer or answer between paired peers.
 */
export function forwardSdp(
  registry: Registry,
  fromId: string,
  targetId: string,
  type: string,
  sdp: string,
  sdpType?: string
): void {
  const waf = registry.getWaf(targetId);
  if (waf) {
    safeSend(waf.ws, { type, fromId, sdp, sdpType });
    return;
  }

  const client = registry.getClient(targetId);
  if (client) {
    safeSend(client.ws, { type, fromId, sdp, sdpType });
  }
}

/**
 * Forward an ICE candidate between paired peers.
 */
export function forwardCandidate(
  registry: Registry,
  fromId: string,
  targetId: string,
  candidate: unknown
): void {
  // Try to find target as WAF first, then as client
  const waf = registry.getWaf(targetId);
  if (waf) {
    safeSend(waf.ws, {
      type: "candidate",
      fromId,
      candidate,
    });
    return;
  }

  const client = registry.getClient(targetId);
  if (client) {
    safeSend(client.ws, {
      type: "candidate",
      fromId,
      candidate,
    });
  }
}

function safeSend(ws: import("ws").WebSocket, data: unknown): void {
  try {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(data));
    }
  } catch {
    // Connection lost
  }
}
