/**
 * @fileoverview Tests for the signal server's in-memory registry.
 *
 * Tests gateway/client registration, pairing, removal, capacity limits,
 * load balancing (fewest-clients strategy), realm-based lookup,
 * admin operations (drain, force disconnect), and stats reporting.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { createRegistry, type Registry } from "../../signal-server/src/signaling/registry";
import type { WebSocket } from "ws";

/** Create a mock WebSocket with configurable readyState */
function mockWs(readyState = 1 /* OPEN */): WebSocket {
  return {
    readyState,
    OPEN: 1,
    send: vi.fn(),
    close: vi.fn(),
    terminate: vi.fn(),
  } as unknown as WebSocket;
}

describe("Signal Server Registry", () => {
  let registry: Registry;

  beforeEach(() => {
    registry = createRegistry();
  });

  // ── Gateway registration ────────────────────────────────────────

  describe("registerGateway", () => {
    it("should register a gateway", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], ws, { displayName: "Gateway 1" });
      expect(registry.getGateway("gw-1")).toBeDefined();
      expect(registry.getGateway("gw-1")!.id).toBe("gw-1");
    });

    it("should store metadata", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], ws, {
        displayName: "My Gateway",
        description: "Test gateway",
        backends: [{ name: "App", protocol: "http" }],
        realm: "keylessh",
      });
      const gw = registry.getGateway("gw-1")!;
      expect(gw.metadata.displayName).toBe("My Gateway");
      expect(gw.metadata.description).toBe("Test gateway");
      expect(gw.metadata.backends).toHaveLength(1);
      expect(gw.metadata.realm).toBe("keylessh");
    });

    it("should re-register gateway with new WebSocket", () => {
      const ws1 = mockWs();
      const ws2 = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], ws1);
      registry.registerGateway("gw-1", ["5.6.7.8:443"], ws2);

      const gw = registry.getGateway("gw-1")!;
      expect(gw.ws).toBe(ws2);
      expect(gw.addresses).toEqual(["5.6.7.8:443"]);
      // Old WS should be terminated
      expect(ws1.terminate).toHaveBeenCalled();
    });

    it("should preserve paired clients on re-registration", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], gwWs);
      registry.registerClient("client-1", clientWs);

      // Manually pair
      const gw = registry.getGateway("gw-1")!;
      gw.pairedClients.add("client-1");

      // Re-register with new WS
      const gwWs2 = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], gwWs2);
      expect(registry.getGateway("gw-1")!.pairedClients.has("client-1")).toBe(true);
    });
  });

  // ── Client registration ─────────────────────────────────────────

  describe("registerClient", () => {
    it("should register a client", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      expect(registry.getClient("client-1")).toBeDefined();
      expect(registry.getClient("client-1")!.connectionType).toBe("relay");
    });

    it("should store JWT token", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws, "my-jwt-token");
      expect(registry.getClient("client-1")!.token).toBe("my-jwt-token");
    });
  });

  // ── Removal ─────────────────────────────────────────────────────

  describe("removeByWs", () => {
    it("should remove gateway by WebSocket", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], ws);
      registry.removeByWs(ws);
      expect(registry.getGateway("gw-1")).toBeUndefined();
    });

    it("should remove client by WebSocket", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      registry.removeByWs(ws);
      expect(registry.getClient("client-1")).toBeUndefined();
    });

    it("should unpair clients when gateway is removed", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-1", [], gwWs);
      registry.registerClient("client-1", clientWs);
      const client = registry.getClient("client-1")!;
      client.pairedGatewayId = "gw-1";
      registry.getGateway("gw-1")!.pairedClients.add("client-1");

      registry.removeByWs(gwWs);
      expect(registry.getClient("client-1")!.pairedGatewayId).toBeUndefined();
    });

    it("should remove client from gateway's paired set when client disconnects", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-1", [], gwWs);
      registry.registerClient("client-1", clientWs);
      const gw = registry.getGateway("gw-1")!;
      gw.pairedClients.add("client-1");
      const client = registry.getClient("client-1")!;
      client.pairedGatewayId = "gw-1";

      registry.removeByWs(clientWs);
      expect(gw.pairedClients.has("client-1")).toBe(false);
    });

    it("should be a no-op for unknown WebSocket", () => {
      const ws = mockWs();
      expect(() => registry.removeByWs(ws)).not.toThrow();
    });
  });

  // ── Load balancing ──────────────────────────────────────────────

  describe("getAvailableGateway", () => {
    it("should return undefined when no gateways", () => {
      expect(registry.getAvailableGateway()).toBeUndefined();
    });

    it("should return the only gateway", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", [], ws);
      expect(registry.getAvailableGateway()!.id).toBe("gw-1");
    });

    it("should return gateway with fewest clients", () => {
      const ws1 = mockWs();
      const ws2 = mockWs();
      registry.registerGateway("gw-1", [], ws1);
      registry.registerGateway("gw-2", [], ws2);

      // Add 3 clients to gw-1
      registry.getGateway("gw-1")!.pairedClients.add("c1");
      registry.getGateway("gw-1")!.pairedClients.add("c2");
      registry.getGateway("gw-1")!.pairedClients.add("c3");
      // Add 1 client to gw-2
      registry.getGateway("gw-2")!.pairedClients.add("c4");

      expect(registry.getAvailableGateway()!.id).toBe("gw-2");
    });
  });

  describe("getGatewayByRealm", () => {
    it("should find gateway by realm", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", [], ws, { realm: "keylessh" });
      expect(registry.getGatewayByRealm("keylessh")!.id).toBe("gw-1");
    });

    it("should return undefined for unknown realm", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", [], ws, { realm: "keylessh" });
      expect(registry.getGatewayByRealm("other")).toBeUndefined();
    });

    it("should prefer gateway with fewer clients for same realm", () => {
      const ws1 = mockWs();
      const ws2 = mockWs();
      registry.registerGateway("gw-1", [], ws1, { realm: "keylessh" });
      registry.registerGateway("gw-2", [], ws2, { realm: "keylessh" });
      registry.getGateway("gw-1")!.pairedClients.add("c1");
      registry.getGateway("gw-1")!.pairedClients.add("c2");

      expect(registry.getGatewayByRealm("keylessh")!.id).toBe("gw-2");
    });
  });

  // ── Client state updates ────────────────────────────────────────

  describe("updateClientReflexive", () => {
    it("should update client reflexive address", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      registry.updateClientReflexive("client-1", "203.0.113.5:12345");
      expect(registry.getClient("client-1")!.reflexiveAddress).toBe("203.0.113.5:12345");
    });

    it("should be a no-op for unknown client", () => {
      expect(() => registry.updateClientReflexive("unknown", "1.2.3.4")).not.toThrow();
    });
  });

  describe("updateClientConnection", () => {
    it("should update connection type to p2p", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      registry.updateClientConnection("client-1", "p2p");
      expect(registry.getClient("client-1")!.connectionType).toBe("p2p");
    });

    it("should update connection type to turn", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      registry.updateClientConnection("client-1", "turn");
      expect(registry.getClient("client-1")!.connectionType).toBe("turn");
    });
  });

  // ── Stats ───────────────────────────────────────────────────────

  describe("getStats", () => {
    it("should return zero counts initially", () => {
      expect(registry.getStats()).toEqual({ gateways: 0, clients: 0 });
    });

    it("should count registered gateways and clients", () => {
      registry.registerGateway("gw-1", [], mockWs());
      registry.registerGateway("gw-2", [], mockWs());
      registry.registerClient("client-1", mockWs());
      expect(registry.getStats()).toEqual({ gateways: 2, clients: 1 });
    });
  });

  describe("getDetailedStats", () => {
    it("should return detailed gateway info", () => {
      registry.registerGateway("gw-1", ["1.2.3.4:443"], mockWs(), {
        displayName: "Test GW",
        description: "A gateway",
        backends: [{ name: "App" }],
      });
      const stats = registry.getDetailedStats();
      expect(stats.gateways).toHaveLength(1);
      expect(stats.gateways[0].displayName).toBe("Test GW");
      expect(stats.gateways[0].addresses).toEqual(["1.2.3.4:443"]);
      expect(stats.gateways[0].online).toBe(true);
    });

    it("should return detailed client info", () => {
      registry.registerClient("client-1", mockWs());
      registry.updateClientReflexive("client-1", "203.0.113.5");
      registry.updateClientConnection("client-1", "p2p");

      const stats = registry.getDetailedStats();
      expect(stats.clients).toHaveLength(1);
      expect(stats.clients[0].reflexiveAddress).toBe("203.0.113.5");
      expect(stats.clients[0].connectionType).toBe("p2p");
    });
  });

  // ── Admin operations ────────────────────────────────────────────

  describe("forceDisconnectClient", () => {
    it("should close the client WebSocket", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      expect(registry.forceDisconnectClient("client-1")).toBe(true);
      expect(ws.close).toHaveBeenCalledWith(1000, "Disconnected by admin");
    });

    it("should return false for unknown client", () => {
      expect(registry.forceDisconnectClient("unknown")).toBe(false);
    });
  });

  describe("drainGateway", () => {
    it("should close gateway and clear its clients", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-1", [], gwWs);
      registry.registerClient("client-1", clientWs);
      const gw = registry.getGateway("gw-1")!;
      gw.pairedClients.add("client-1");
      registry.getClient("client-1")!.pairedGatewayId = "gw-1";

      expect(registry.drainGateway("gw-1")).toBe(true);
      expect(gwWs.close).toHaveBeenCalledWith(1000, "Drained by admin");
      expect(gw.pairedClients.size).toBe(0);
      expect(registry.getClient("client-1")!.pairedGatewayId).toBeUndefined();
    });

    it("should return false for unknown gateway", () => {
      expect(registry.drainGateway("unknown")).toBe(false);
    });
  });

  // ── Lookup by WebSocket ─────────────────────────────────────────

  describe("getInfoByWs", () => {
    it("should return gateway info for gateway WebSocket", () => {
      const ws = mockWs();
      registry.registerGateway("gw-1", [], ws);
      expect(registry.getInfoByWs(ws)).toEqual({ type: "gateway", id: "gw-1" });
    });

    it("should return client info for client WebSocket", () => {
      const ws = mockWs();
      registry.registerClient("client-1", ws);
      expect(registry.getInfoByWs(ws)).toEqual({ type: "client", id: "client-1" });
    });

    it("should return undefined for unknown WebSocket", () => {
      expect(registry.getInfoByWs(mockWs())).toBeUndefined();
    });
  });

  // ── getAllGateways ──────────────────────────────────────────────

  describe("getAllGateways", () => {
    it("should return all registered gateways", () => {
      registry.registerGateway("gw-1", [], mockWs());
      registry.registerGateway("gw-2", [], mockWs());
      const all = registry.getAllGateways();
      expect(all).toHaveLength(2);
      expect(all.map((g) => g.id).sort()).toEqual(["gw-1", "gw-2"]);
    });

    it("should return empty array when no gateways", () => {
      expect(registry.getAllGateways()).toEqual([]);
    });
  });
});
