/**
 * Pairing logic: matches clients with gateway instances
 * and exchanges their addresses.
 */

import type { Registry } from "./registry.js";

/**
 * Attempt to pair a client with an available gateway.
 * Sends pairing messages to both parties via WebSocket.
 */
export function pairClient(
  registry: Registry,
  clientId: string
): boolean {
  const client = registry.getClient(clientId);
  if (!client) return false;

  const gateway = registry.getAvailableGateway();
  if (!gateway) {
    // No gateways available — notify client
    safeSend(client.ws, {
      type: "error",
      message: "No gateway instances available",
    });
    return false;
  }

  // Link them
  client.pairedGatewayId = gateway.id;
  gateway.pairedClients.add(clientId);

  // Notify client of their paired gateway
  safeSend(client.ws, {
    type: "paired",
    gateway: {
      id: gateway.id,
      addresses: gateway.addresses,
    },
  });

  // Notify gateway of their new client (include JWT for hop-by-hop auth)
  safeSend(gateway.ws, {
    type: "paired",
    client: {
      id: clientId,
      reflexiveAddress: client.reflexiveAddress || null,
      token: client.token || null,
    },
  });

  console.log(`[Signal] Paired client ${clientId} with gateway ${gateway.id}`);
  return true;
}

/**
 * Pair a client with a specific gateway by ID (explicit selection).
 */
export function pairClientWithGateway(
  registry: Registry,
  clientId: string,
  gatewayId: string
): boolean {
  const client = registry.getClient(clientId);
  if (!client) return false;

  const gateway = registry.getGateway(gatewayId);
  if (!gateway) {
    safeSend(client.ws, {
      type: "error",
      message: `Gateway ${gatewayId} not found or offline`,
    });
    return false;
  }

  client.pairedGatewayId = gateway.id;
  gateway.pairedClients.add(clientId);

  safeSend(client.ws, {
    type: "paired",
    gateway: { id: gateway.id, addresses: gateway.addresses },
  });

  // Include JWT for hop-by-hop auth
  safeSend(gateway.ws, {
    type: "paired",
    client: { id: clientId, reflexiveAddress: client.reflexiveAddress || null, token: client.token || null },
  });

  console.log(`[Signal] Paired client ${clientId} with gateway ${gatewayId} (explicit)`);
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
  const gateway = registry.getGateway(targetId);
  if (gateway) {
    safeSend(gateway.ws, { type, fromId, sdp, sdpType });
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
  // Try to find target as gateway first, then as client
  const gateway = registry.getGateway(targetId);
  if (gateway) {
    safeSend(gateway.ws, {
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
