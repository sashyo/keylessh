/**
 * In-memory registry of gateway instances and clients.
 */

import type { WebSocket } from "ws";

export interface GatewayMetadata {
  displayName?: string;
  description?: string;
  backends?: { name: string; protocol?: string }[];
  realm?: string;
}

export interface RegisteredGateway {
  id: string;
  addresses: string[]; // public addresses (e.g., "203.0.113.5:443")
  ws: WebSocket;
  registeredAt: number;
  pairedClients: Set<string>; // client IDs
  metadata: GatewayMetadata;
}

export type ConnectionType = "relay" | "p2p" | "turn";

export interface RegisteredClient {
  id: string;
  reflexiveAddress?: string; // client's public IP
  connectionType: ConnectionType; // how the client is connected
  ws: WebSocket;
  registeredAt: number;
  pairedGatewayId?: string;
  token?: string; // JWT from KeyleSSH auth — forwarded to gateway on pairing
}

export interface DetailedStats {
  gateways: Array<{
    id: string;
    displayName: string;
    description: string;
    backends: { name: string }[];
    addresses: string[];
    clientCount: number;
    registeredAt: number;
    online: boolean;
  }>;
  clients: Array<{
    id: string;
    reflexiveAddress?: string;
    connectionType: ConnectionType;
    pairedGatewayId?: string;
    registeredAt: number;
  }>;
}

export interface Registry {
  registerGateway(id: string, addresses: string[], ws: WebSocket, metadata?: GatewayMetadata): void;
  registerClient(id: string, ws: WebSocket, token?: string): void;
  removeByWs(ws: WebSocket): void;
  getGateway(id: string): RegisteredGateway | undefined;
  getClient(id: string): RegisteredClient | undefined;
  getAvailableGateway(): RegisteredGateway | undefined;
  getGatewayByRealm(realm: string): RegisteredGateway | undefined;
  getGatewayByBackend(backendName: string): RegisteredGateway | undefined;
  getAllGateways(): RegisteredGateway[];
  updateClientReflexive(id: string, address: string): void;
  updateClientConnection(id: string, connectionType: ConnectionType): void;
  getStats(): { gateways: number; clients: number };
  getDetailedStats(): DetailedStats;
  forceDisconnectClient(clientId: string): boolean;
  drainGateway(gatewayId: string): boolean;
  getInfoByWs(ws: WebSocket): { type: "gateway" | "client"; id: string } | undefined;
}

export function createRegistry(): Registry {
  const MAX_GATEWAYS = 100;
  const MAX_CLIENTS = 10000;
  const gateways = new Map<string, RegisteredGateway>();
  const clients = new Map<string, RegisteredClient>();
  const wsByWs = new Map<WebSocket, { type: "gateway" | "client"; id: string }>();

  return {
    registerGateway(id, addresses, ws, metadata) {
      if (gateways.size >= MAX_GATEWAYS && !gateways.has(id)) {
        console.warn(`[Signal] Gateway registration rejected: max gateways (${MAX_GATEWAYS}) reached`);
        ws.close(1013, "Too many gateways registered");
        return;
      }
      // Clean up stale WS entry if this gateway is re-registering (e.g. after reconnect)
      const existing = gateways.get(id);
      if (existing && existing.ws !== ws) {
        wsByWs.delete(existing.ws);
        try { existing.ws.terminate(); } catch {}
      }
      const gateway: RegisteredGateway = {
        id,
        addresses,
        ws,
        registeredAt: Date.now(),
        pairedClients: existing?.pairedClients || new Set(),
        metadata: metadata || {},
      };
      gateways.set(id, gateway);
      wsByWs.set(ws, { type: "gateway", id });
      console.log(
        `[Signal] Gateway registered: ${metadata?.displayName || id} (${id}) at ${addresses.join(", ")}`
      );
    },

    registerClient(id, ws, token?) {
      if (clients.size >= MAX_CLIENTS && !clients.has(id)) {
        console.warn(`[Signal] Client registration rejected: max clients (${MAX_CLIENTS}) reached`);
        ws.close(1013, "Too many clients registered");
        return;
      }
      const client: RegisteredClient = {
        id,
        ws,
        connectionType: "relay",
        registeredAt: Date.now(),
        token,
      };
      clients.set(id, client);
      wsByWs.set(ws, { type: "client", id });
      console.log(`[Signal] Client registered: ${id}`);
    },

    removeByWs(ws) {
      const entry = wsByWs.get(ws);
      if (!entry) return;
      wsByWs.delete(ws);

      if (entry.type === "gateway") {
        const gateway = gateways.get(entry.id);
        if (gateway) {
          // Notify paired clients that gateway is gone
          for (const clientId of gateway.pairedClients) {
            const client = clients.get(clientId);
            if (client) {
              client.pairedGatewayId = undefined;
            }
          }
          gateways.delete(entry.id);
        }
        console.log(`[Signal] Gateway unregistered: ${entry.id}`);
      } else {
        const client = clients.get(entry.id);
        if (client?.pairedGatewayId) {
          const gateway = gateways.get(client.pairedGatewayId);
          gateway?.pairedClients.delete(entry.id);
        }
        clients.delete(entry.id);
        console.log(`[Signal] Client unregistered: ${entry.id}`);
      }
    },

    getGateway(id) {
      return gateways.get(id);
    },

    getClient(id) {
      return clients.get(id);
    },

    getAvailableGateway() {
      // Simple strategy: return gateway with fewest paired clients
      let best: RegisteredGateway | undefined;
      let minClients = Infinity;
      for (const gateway of gateways.values()) {
        if (gateway.pairedClients.size < minClients) {
          minClients = gateway.pairedClients.size;
          best = gateway;
        }
      }
      return best;
    },

    getGatewayByRealm(realm) {
      // Find gateway that serves the given TideCloak realm.
      // If multiple gateways serve the same realm, pick the one with fewest clients.
      let best: RegisteredGateway | undefined;
      let minClients = Infinity;
      for (const gateway of gateways.values()) {
        if (gateway.metadata.realm === realm && gateway.pairedClients.size < minClients) {
          minClients = gateway.pairedClients.size;
          best = gateway;
        }
      }
      return best;
    },

    getGatewayByBackend(backendName) {
      // Find gateway that has the given backend registered.
      let best: RegisteredGateway | undefined;
      let minClients = Infinity;
      for (const gateway of gateways.values()) {
        const hasBackend = gateway.metadata.backends?.some(b => b.name === backendName);
        if (hasBackend && gateway.pairedClients.size < minClients) {
          minClients = gateway.pairedClients.size;
          best = gateway;
        }
      }
      return best;
    },

    getAllGateways() {
      return Array.from(gateways.values());
    },

    updateClientReflexive(id, address) {
      const client = clients.get(id);
      if (client) {
        client.reflexiveAddress = address;
      }
    },

    updateClientConnection(id, connectionType) {
      const client = clients.get(id);
      if (client) {
        client.connectionType = connectionType;
        console.log(`[Signal] Client ${id} connection: ${connectionType}`);
      }
    },

    getStats() {
      return { gateways: gateways.size, clients: clients.size };
    },

    getDetailedStats() {
      return {
        gateways: Array.from(gateways.values()).map((w) => ({
          id: w.id,
          displayName: w.metadata.displayName || w.id,
          description: w.metadata.description || "",
          backends: w.metadata.backends || [],
          addresses: w.addresses,
          clientCount: w.pairedClients.size,
          registeredAt: w.registeredAt,
          online: w.ws.readyState === w.ws.OPEN,
        })),
        clients: Array.from(clients.values()).map((c) => ({
          id: c.id,
          reflexiveAddress: c.reflexiveAddress,
          connectionType: c.connectionType,
          pairedGatewayId: c.pairedGatewayId,
          registeredAt: c.registeredAt,
        })),
      };
    },

    forceDisconnectClient(clientId) {
      const client = clients.get(clientId);
      if (!client) return false;
      client.ws.close(1000, "Disconnected by admin");
      return true;
    },

    drainGateway(gatewayId) {
      const gateway = gateways.get(gatewayId);
      if (!gateway) return false;
      for (const clientId of gateway.pairedClients) {
        const client = clients.get(clientId);
        if (client) {
          client.pairedGatewayId = undefined;
        }
      }
      gateway.pairedClients.clear();
      gateway.ws.close(1000, "Drained by admin");
      return true;
    },

    getInfoByWs(ws) {
      return wsByWs.get(ws);
    },
  };
}
