/**
 * @fileoverview Tests for the signal server's client-gateway pairing logic.
 *
 * Tests pairClient() (automatic load-balanced pairing),
 * pairClientWithGateway() (explicit gateway selection),
 * forwardSdp() and forwardCandidate() (WebRTC signaling relay).
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { createRegistry, type Registry } from "../../signal-server/src/signaling/registry";
import {
  pairClient,
  pairClientWithGateway,
  forwardSdp,
  forwardCandidate,
} from "../../signal-server/src/signaling/pairing";
import type { WebSocket } from "ws";

function mockWs(): WebSocket {
  return {
    readyState: 1,
    OPEN: 1,
    send: vi.fn(),
    close: vi.fn(),
    terminate: vi.fn(),
  } as unknown as WebSocket;
}

describe("Pairing", () => {
  let registry: Registry;

  beforeEach(() => {
    registry = createRegistry();
  });

  describe("pairClient (automatic)", () => {
    it("should pair client with available gateway", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-1", ["1.2.3.4:443"], gwWs);
      registry.registerClient("client-1", clientWs, "my-jwt");

      const result = pairClient(registry, "client-1");
      expect(result).toBe(true);

      // Client should be notified with gateway info
      expect(clientWs.send).toHaveBeenCalledWith(
        expect.stringContaining('"type":"paired"')
      );
      const clientMsg = JSON.parse((clientWs.send as any).mock.calls[0][0]);
      expect(clientMsg.gateway.id).toBe("gw-1");

      // Gateway should be notified with client info
      expect(gwWs.send).toHaveBeenCalledWith(
        expect.stringContaining('"type":"paired"')
      );
      const gwMsg = JSON.parse((gwWs.send as any).mock.calls[0][0]);
      expect(gwMsg.client.id).toBe("client-1");
      expect(gwMsg.client.token).toBe("my-jwt");
    });

    it("should return false and notify when no gateways available", () => {
      const clientWs = mockWs();
      registry.registerClient("client-1", clientWs);

      const result = pairClient(registry, "client-1");
      expect(result).toBe(false);

      const msg = JSON.parse((clientWs.send as any).mock.calls[0][0]);
      expect(msg.type).toBe("error");
      expect(msg.message).toContain("No gateway");
    });

    it("should return false for unknown client", () => {
      expect(pairClient(registry, "unknown")).toBe(false);
    });

    it("should forward reflexive address to gateway", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-1", [], gwWs);
      registry.registerClient("client-1", clientWs);
      registry.updateClientReflexive("client-1", "203.0.113.5:9999");

      pairClient(registry, "client-1");

      const gwMsg = JSON.parse((gwWs.send as any).mock.calls[0][0]);
      expect(gwMsg.client.reflexiveAddress).toBe("203.0.113.5:9999");
    });
  });

  describe("pairClientWithGateway (explicit)", () => {
    it("should pair with specified gateway", () => {
      const gwWs = mockWs();
      const clientWs = mockWs();
      registry.registerGateway("gw-target", ["5.6.7.8:443"], gwWs);
      registry.registerGateway("gw-other", [], mockWs());
      registry.registerClient("client-1", clientWs);

      const result = pairClientWithGateway(registry, "client-1", "gw-target");
      expect(result).toBe(true);

      const clientMsg = JSON.parse((clientWs.send as any).mock.calls[0][0]);
      expect(clientMsg.gateway.id).toBe("gw-target");
    });

    it("should return false for unknown gateway", () => {
      const clientWs = mockWs();
      registry.registerClient("client-1", clientWs);

      const result = pairClientWithGateway(registry, "client-1", "gw-nonexistent");
      expect(result).toBe(false);

      const msg = JSON.parse((clientWs.send as any).mock.calls[0][0]);
      expect(msg.type).toBe("error");
      expect(msg.message).toContain("not found");
    });

    it("should return false for unknown client", () => {
      registry.registerGateway("gw-1", [], mockWs());
      expect(pairClientWithGateway(registry, "unknown", "gw-1")).toBe(false);
    });
  });

  describe("forwardSdp", () => {
    it("should forward SDP to gateway", () => {
      const gwWs = mockWs();
      registry.registerGateway("gw-1", [], gwWs);

      forwardSdp(registry, "client-1", "gw-1", "sdp_offer", "v=0\r\n...", "offer");

      expect(gwWs.send).toHaveBeenCalled();
      const msg = JSON.parse((gwWs.send as any).mock.calls[0][0]);
      expect(msg.type).toBe("sdp_offer");
      expect(msg.fromId).toBe("client-1");
      expect(msg.sdp).toBe("v=0\r\n...");
      expect(msg.sdpType).toBe("offer");
    });

    it("should forward SDP to client", () => {
      const clientWs = mockWs();
      registry.registerClient("client-1", clientWs);

      forwardSdp(registry, "gw-1", "client-1", "sdp_answer", "v=0\r\n...", "answer");

      expect(clientWs.send).toHaveBeenCalled();
      const msg = JSON.parse((clientWs.send as any).mock.calls[0][0]);
      expect(msg.type).toBe("sdp_answer");
    });

    it("should not throw for unknown target", () => {
      expect(() => forwardSdp(registry, "from", "unknown", "sdp_offer", "data")).not.toThrow();
    });
  });

  describe("forwardCandidate", () => {
    it("should forward ICE candidate to gateway", () => {
      const gwWs = mockWs();
      registry.registerGateway("gw-1", [], gwWs);

      const candidate = { candidate: "candidate:1 1 UDP ...", sdpMid: "0" };
      forwardCandidate(registry, "client-1", "gw-1", candidate);

      const msg = JSON.parse((gwWs.send as any).mock.calls[0][0]);
      expect(msg.type).toBe("candidate");
      expect(msg.fromId).toBe("client-1");
      expect(msg.candidate).toEqual(candidate);
    });

    it("should forward ICE candidate to client", () => {
      const clientWs = mockWs();
      registry.registerClient("client-1", clientWs);

      const candidate = { candidate: "candidate:2 1 UDP ..." };
      forwardCandidate(registry, "gw-1", "client-1", candidate);

      const msg = JSON.parse((clientWs.send as any).mock.calls[0][0]);
      expect(msg.type).toBe("candidate");
    });

    it("should not throw for unknown target", () => {
      expect(() => forwardCandidate(registry, "from", "unknown", {})).not.toThrow();
    });
  });
});
