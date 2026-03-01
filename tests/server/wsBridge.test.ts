/**
 * @fileoverview Tests for the WebSocket-to-TCP bridge utility functions.
 *
 * Tests the exported functions getActiveConnections() and terminateSession()
 * from the wsBridge module. The core WebSocket event loop is tested indirectly
 * through these observable APIs.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the dependencies before importing
vi.mock("../../server/lib/auth/tideJWT", () => ({
  verifyTideCloakToken: vi.fn(),
}));

vi.mock("../../server/storage", () => ({
  storage: {
    endSession: vi.fn().mockResolvedValue(true),
  },
}));

import { getActiveConnections, terminateSession } from "../../server/wsBridge";

describe("wsBridge utility functions", () => {
  describe("getActiveConnections", () => {
    it("should return a number", () => {
      const count = getActiveConnections();
      expect(typeof count).toBe("number");
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  describe("terminateSession", () => {
    it("should return false for unknown session ID", () => {
      expect(terminateSession("nonexistent-session-123")).toBe(false);
    });

    it("should return false for empty session ID", () => {
      expect(terminateSession("")).toBe(false);
    });
  });
});
