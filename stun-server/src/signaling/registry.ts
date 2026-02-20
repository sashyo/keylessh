/**
 * In-memory registry of WAF instances and clients.
 */

import type { WebSocket } from "ws";

export interface WafMetadata {
  displayName?: string;
  description?: string;
  backends?: { name: string }[];
}

export interface RegisteredWaf {
  id: string;
  addresses: string[]; // public addresses (e.g., "203.0.113.5:443")
  ws: WebSocket;
  registeredAt: number;
  pairedClients: Set<string>; // client IDs
  metadata: WafMetadata;
}

export type ConnectionType = "relay" | "p2p" | "turn";

export interface RegisteredClient {
  id: string;
  reflexiveAddress?: string; // client's public IP
  connectionType: ConnectionType; // how the client is connected
  ws: WebSocket;
  registeredAt: number;
  pairedWafId?: string;
}

export interface DetailedStats {
  wafs: Array<{
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
    pairedWafId?: string;
    registeredAt: number;
  }>;
}

export interface Registry {
  registerWaf(id: string, addresses: string[], ws: WebSocket, metadata?: WafMetadata): void;
  registerClient(id: string, ws: WebSocket): void;
  removeByWs(ws: WebSocket): void;
  getWaf(id: string): RegisteredWaf | undefined;
  getClient(id: string): RegisteredClient | undefined;
  getAvailableWaf(): RegisteredWaf | undefined;
  getAllWafs(): RegisteredWaf[];
  updateClientReflexive(id: string, address: string): void;
  updateClientConnection(id: string, connectionType: ConnectionType): void;
  getStats(): { wafs: number; clients: number };
  getDetailedStats(): DetailedStats;
  forceDisconnectClient(clientId: string): boolean;
  drainWaf(wafId: string): boolean;
}

export function createRegistry(): Registry {
  const wafs = new Map<string, RegisteredWaf>();
  const clients = new Map<string, RegisteredClient>();
  const wsByWs = new Map<WebSocket, { type: "waf" | "client"; id: string }>();

  return {
    registerWaf(id, addresses, ws, metadata) {
      const waf: RegisteredWaf = {
        id,
        addresses,
        ws,
        registeredAt: Date.now(),
        pairedClients: new Set(),
        metadata: metadata || {},
      };
      wafs.set(id, waf);
      wsByWs.set(ws, { type: "waf", id });
      console.log(
        `[Signal] WAF registered: ${metadata?.displayName || id} (${id}) at ${addresses.join(", ")}`
      );
    },

    registerClient(id, ws) {
      const client: RegisteredClient = {
        id,
        ws,
        connectionType: "relay",
        registeredAt: Date.now(),
      };
      clients.set(id, client);
      wsByWs.set(ws, { type: "client", id });
      console.log(`[Signal] Client registered: ${id}`);
    },

    removeByWs(ws) {
      const entry = wsByWs.get(ws);
      if (!entry) return;
      wsByWs.delete(ws);

      if (entry.type === "waf") {
        const waf = wafs.get(entry.id);
        if (waf) {
          // Notify paired clients that WAF is gone
          for (const clientId of waf.pairedClients) {
            const client = clients.get(clientId);
            if (client) {
              client.pairedWafId = undefined;
            }
          }
          wafs.delete(entry.id);
        }
        console.log(`[Signal] WAF unregistered: ${entry.id}`);
      } else {
        const client = clients.get(entry.id);
        if (client?.pairedWafId) {
          const waf = wafs.get(client.pairedWafId);
          waf?.pairedClients.delete(entry.id);
        }
        clients.delete(entry.id);
        console.log(`[Signal] Client unregistered: ${entry.id}`);
      }
    },

    getWaf(id) {
      return wafs.get(id);
    },

    getClient(id) {
      return clients.get(id);
    },

    getAvailableWaf() {
      // Simple strategy: return WAF with fewest paired clients
      let best: RegisteredWaf | undefined;
      let minClients = Infinity;
      for (const waf of wafs.values()) {
        if (waf.pairedClients.size < minClients) {
          minClients = waf.pairedClients.size;
          best = waf;
        }
      }
      return best;
    },

    getAllWafs() {
      return Array.from(wafs.values());
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
      return { wafs: wafs.size, clients: clients.size };
    },

    getDetailedStats() {
      return {
        wafs: Array.from(wafs.values()).map((w) => ({
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
          pairedWafId: c.pairedWafId,
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

    drainWaf(wafId) {
      const waf = wafs.get(wafId);
      if (!waf) return false;
      for (const clientId of waf.pairedClients) {
        const client = clients.get(clientId);
        if (client) {
          client.pairedWafId = undefined;
        }
      }
      waf.pairedClients.clear();
      waf.ws.close(1000, "Drained by admin");
      return true;
    },
  };
}
