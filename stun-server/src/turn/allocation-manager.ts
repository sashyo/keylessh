/**
 * TURN allocation lifecycle management.
 *
 * Each allocation creates a dedicated UDP relay socket. Allocations
 * expire after their lifetime and are cleaned up automatically.
 */

import { createSocket, Socket as DgramSocket } from "dgram";
import { Allocation, makeFiveTupleKey } from "./types.js";
import { hasPermission } from "./permission-manager.js";
import { getChannelByPeer } from "./channel-manager.js";

export type RelayDataCallback = (
  allocation: Allocation,
  peerAddress: string,
  peerPort: number,
  data: Buffer
) => void;

export interface AllocationManager {
  create(
    clientAddr: string,
    clientPort: number,
    protocol: "udp" | "tcp",
    lifetime: number
  ): Promise<Allocation>;
  get(key: string): Allocation | undefined;
  refresh(key: string, lifetime: number): number | null;
  delete(key: string): void;
  getStats(): { allocations: number; channels: number };
  shutdownAll(): void;
}

export function createAllocationManager(
  externalIp: string,
  portMin: number,
  portMax: number,
  onRelayData: RelayDataCallback
): AllocationManager {
  const allocations = new Map<string, Allocation>();

  async function bindRelaySocket(): Promise<{
    socket: DgramSocket;
    port: number;
  }> {
    // Try random ports until one works
    const maxAttempts = 100;
    for (let i = 0; i < maxAttempts; i++) {
      const port =
        portMin + Math.floor(Math.random() * (portMax - portMin + 1));
      try {
        const socket = createSocket("udp4");
        await new Promise<void>((resolve, reject) => {
          socket.once("error", reject);
          socket.bind(port, () => {
            socket.removeListener("error", reject);
            resolve();
          });
        });
        return { socket, port };
      } catch {
        // Port in use, try another
      }
    }
    throw new Error("No available relay ports");
  }

  function scheduleExpiry(alloc: Allocation) {
    clearTimeout(alloc.refreshTimer);
    alloc.refreshTimer = setTimeout(() => {
      console.log(
        `[TURN] Allocation expired: ${alloc.clientAddress}:${alloc.clientPort} -> relay :${alloc.relayPort}`
      );
      deleteAllocation(alloc.key);
    }, alloc.lifetime * 1000);
  }

  function deleteAllocation(key: string) {
    const alloc = allocations.get(key);
    if (!alloc) return;

    clearTimeout(alloc.refreshTimer);

    // Clear permission timers
    for (const perm of alloc.permissions.values()) {
      clearTimeout(perm.refreshTimer);
    }

    // Clear channel timers
    for (const chan of alloc.channels.values()) {
      clearTimeout(chan.refreshTimer);
    }

    // Close relay socket
    try {
      alloc.relaySocket.close();
    } catch {
      // Already closed
    }

    allocations.delete(key);
  }

  return {
    async create(clientAddr, clientPort, protocol, lifetime) {
      const key = makeFiveTupleKey(protocol, clientAddr, clientPort);

      if (allocations.has(key)) {
        throw new Error("Allocation already exists for this 5-tuple");
      }

      const { socket, port } = await bindRelaySocket();

      const alloc: Allocation = {
        key,
        clientAddress: clientAddr,
        clientPort: clientPort,
        protocol,
        relaySocket: socket,
        relayAddress: externalIp,
        relayPort: port,
        lifetime,
        expiresAt: Date.now() + lifetime * 1000,
        refreshTimer: null as unknown as ReturnType<typeof setTimeout>,
        permissions: new Map(),
        channels: new Map(),
        channelsByPeer: new Map(),
      };

      // Listen for incoming relay data from peers
      socket.on("message", (data: Buffer, rinfo) => {
        // Check permission
        if (!hasPermission(alloc, rinfo.address)) {
          return; // Drop — no permission for this peer
        }
        onRelayData(alloc, rinfo.address, rinfo.port, data);
      });

      socket.on("error", (err) => {
        console.error(
          `[TURN] Relay socket error on port ${port}:`,
          err.message
        );
      });

      scheduleExpiry(alloc);
      allocations.set(key, alloc);

      console.log(
        `[TURN] Allocation created: ${clientAddr}:${clientPort} -> relay ${externalIp}:${port} (${lifetime}s)`
      );

      return alloc;
    },

    get(key) {
      return allocations.get(key);
    },

    refresh(key, lifetime) {
      const alloc = allocations.get(key);
      if (!alloc) return null;

      if (lifetime === 0) {
        deleteAllocation(key);
        return 0;
      }

      alloc.lifetime = lifetime;
      alloc.expiresAt = Date.now() + lifetime * 1000;
      scheduleExpiry(alloc);

      console.log(
        `[TURN] Allocation refreshed: ${alloc.clientAddress}:${alloc.clientPort} (${lifetime}s)`
      );

      return lifetime;
    },

    delete: deleteAllocation,

    getStats() {
      let channels = 0;
      for (const alloc of allocations.values()) {
        channels += alloc.channels.size;
      }
      return { allocations: allocations.size, channels };
    },

    shutdownAll() {
      for (const key of [...allocations.keys()]) {
        deleteAllocation(key);
      }
    },
  };
}
