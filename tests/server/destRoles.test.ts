/**
 * @fileoverview Tests for destination/endpoint role parsing from JWT tokens.
 *
 * Tests parseDestRolesFromToken() and hasDestAccess() which handle
 * role patterns for gateway backend access control:
 *   dest:<gatewayId>:<backendName>      — catch-all (any protocol)
 *   endpoint:<gatewayId>:<backendName>  — HTTP/web proxy only
 *   rdp:<gatewayId>:<backendName>       — RDP only
 *   vnc:<gatewayId>:<backendName>       — VNC only
 */

import { describe, it, expect } from "vitest";
import {
  parseDestRolesFromToken,
  hasDestAccess,
  type DestPermission,
} from "../../server/lib/auth/destRoles";
import type { TokenPayload } from "../../server/lib/auth/tideJWT";

describe("parseDestRolesFromToken", () => {
  it("should return empty array for null payload", () => {
    expect(parseDestRolesFromToken(null)).toEqual([]);
  });

  it("should return empty array for undefined payload", () => {
    expect(parseDestRolesFromToken(undefined)).toEqual([]);
  });

  it("should return empty array when no dest roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["user", "ssh:root"] },
      resource_access: {},
    };
    expect(parseDestRolesFromToken(payload)).toEqual([]);
  });

  it("should parse dest role from realm_access", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-abc:WebApp"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-abc", backendName: "WebApp", protocol: null }]);
  });

  it("should parse dest role from resource_access", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {
        keylessh: { roles: ["dest:gw-123:MyApp"] },
      },
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-123", backendName: "MyApp", protocol: null }]);
  });

  it("should parse multiple dest roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-1:App1"] },
      resource_access: {
        keylessh: { roles: ["dest:gw-2:App2"] },
      },
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toHaveLength(2);
    expect(result).toContainEqual({ gatewayId: "gw-1", backendName: "App1", protocol: null });
    expect(result).toContainEqual({ gatewayId: "gw-2", backendName: "App2", protocol: null });
  });

  it("should handle gateway IDs with dashes", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gateway-abc-def-123:Backend"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gateway-abc-def-123", backendName: "Backend", protocol: null }]);
  });

  it("should handle backend names with colons", () => {
    // Third colon onwards is part of the backend name
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-1:My:Backend:Name"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-1", backendName: "My:Backend:Name", protocol: null }]);
  });

  it("should reject dest role with missing backend name", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-1:"] },
      resource_access: {},
    };
    expect(parseDestRolesFromToken(payload)).toEqual([]);
  });

  it("should reject dest role with only one colon", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-1"] },
      resource_access: {},
    };
    expect(parseDestRolesFromToken(payload)).toEqual([]);
  });

  it("should reject dest role with missing gateway ID", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest::Backend"] },
      resource_access: {},
    };
    expect(parseDestRolesFromToken(payload)).toEqual([]);
  });

  it("should ignore non-dest roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["admin", "ssh:root", "dest:gw-1:App"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ gatewayId: "gw-1", backendName: "App", protocol: null });
  });

  // ── Protocol-specific role prefixes ────────────────────────────

  it("should parse rdp: role with protocol 'rdp'", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["rdp:gw-1:RemoteDesktop"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-1", backendName: "RemoteDesktop", protocol: "rdp" }]);
  });

  it("should parse vnc: role with protocol 'vnc'", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["vnc:gw-1:MyVNC"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-1", backendName: "MyVNC", protocol: "vnc" }]);
  });

  it("should parse endpoint: role with protocol 'http'", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["endpoint:gw-1:WebApp"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-1", backendName: "WebApp", protocol: "http" }]);
  });

  it("should parse mixed role prefixes", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-1:App", "rdp:gw-1:RDP", "vnc:gw-2:VNC", "endpoint:gw-2:Web"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toHaveLength(4);
    expect(result).toContainEqual({ gatewayId: "gw-1", backendName: "App", protocol: null });
    expect(result).toContainEqual({ gatewayId: "gw-1", backendName: "RDP", protocol: "rdp" });
    expect(result).toContainEqual({ gatewayId: "gw-2", backendName: "VNC", protocol: "vnc" });
    expect(result).toContainEqual({ gatewayId: "gw-2", backendName: "Web", protocol: "http" });
  });

  it("should be case-insensitive for prefixes", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["RDP:gw-1:App", "VNC:gw-2:App", "ENDPOINT:gw-3:App", "DEST:gw-4:App"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toHaveLength(4);
  });

  it("should reject rdp: role with missing backend", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["rdp:gw-1:"] },
      resource_access: {},
    };
    expect(parseDestRolesFromToken(payload)).toEqual([]);
  });

  it("should reject vnc: role with only one colon", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["vnc:gw-1"] },
      resource_access: {},
    };
    expect(parseDestRolesFromToken(payload)).toEqual([]);
  });
});

describe("hasDestAccess", () => {
  // Legacy dest: (catch-all) permissions
  const permissions: DestPermission[] = [
    { gatewayId: "gw-abc", backendName: "WebApp", protocol: null },
    { gatewayId: "gw-xyz", backendName: "AdminPanel", protocol: null },
  ];

  it("should return true for matching permission", () => {
    expect(hasDestAccess(permissions, "gw-abc", "WebApp")).toBe(true);
  });

  it("should be case-insensitive for gateway ID", () => {
    expect(hasDestAccess(permissions, "GW-ABC", "WebApp")).toBe(true);
  });

  it("should be case-insensitive for backend name", () => {
    expect(hasDestAccess(permissions, "gw-abc", "webapp")).toBe(true);
  });

  it("should return false for non-matching gateway", () => {
    expect(hasDestAccess(permissions, "gw-unknown", "WebApp")).toBe(false);
  });

  it("should return false for non-matching backend", () => {
    expect(hasDestAccess(permissions, "gw-abc", "UnknownApp")).toBe(false);
  });

  it("should return false for empty permissions", () => {
    expect(hasDestAccess([], "gw-abc", "WebApp")).toBe(false);
  });

  it("should match second permission in list", () => {
    expect(hasDestAccess(permissions, "gw-xyz", "AdminPanel")).toBe(true);
  });

  // ── dest: catch-all matches any protocol ─────────────────────

  it("dest: should match when protocol is 'rdp'", () => {
    expect(hasDestAccess(permissions, "gw-abc", "WebApp", "rdp")).toBe(true);
  });

  it("dest: should match when protocol is 'vnc'", () => {
    expect(hasDestAccess(permissions, "gw-abc", "WebApp", "vnc")).toBe(true);
  });

  it("dest: should match when protocol is 'http'", () => {
    expect(hasDestAccess(permissions, "gw-abc", "WebApp", "http")).toBe(true);
  });

  it("dest: should match when no protocol specified", () => {
    expect(hasDestAccess(permissions, "gw-abc", "WebApp")).toBe(true);
  });

  // ── Protocol-specific access checks ──────────────────────────

  describe("protocol-specific roles", () => {
    const mixed: DestPermission[] = [
      { gatewayId: "gw-1", backendName: "Server", protocol: "rdp" },
      { gatewayId: "gw-1", backendName: "Server", protocol: "vnc" },
      { gatewayId: "gw-1", backendName: "WebApp", protocol: "http" },
      { gatewayId: "gw-2", backendName: "App", protocol: null }, // catch-all
    ];

    it("rdp: role should match rdp protocol", () => {
      expect(hasDestAccess(mixed, "gw-1", "Server", "rdp")).toBe(true);
    });

    it("vnc: role should match vnc protocol", () => {
      expect(hasDestAccess(mixed, "gw-1", "Server", "vnc")).toBe(true);
    });

    it("rdp: role should NOT match vnc protocol", () => {
      // Only rdp: and vnc: for "Server" — if we request http, neither matches
      const rdpOnly: DestPermission[] = [
        { gatewayId: "gw-1", backendName: "Server", protocol: "rdp" },
      ];
      expect(hasDestAccess(rdpOnly, "gw-1", "Server", "vnc")).toBe(false);
    });

    it("vnc: role should NOT match rdp protocol", () => {
      const vncOnly: DestPermission[] = [
        { gatewayId: "gw-1", backendName: "Server", protocol: "vnc" },
      ];
      expect(hasDestAccess(vncOnly, "gw-1", "Server", "rdp")).toBe(false);
    });

    it("endpoint: (http) role should match http protocol", () => {
      expect(hasDestAccess(mixed, "gw-1", "WebApp", "http")).toBe(true);
    });

    it("endpoint: (http) role should NOT match rdp protocol", () => {
      const httpOnly: DestPermission[] = [
        { gatewayId: "gw-1", backendName: "WebApp", protocol: "http" },
      ];
      expect(hasDestAccess(httpOnly, "gw-1", "WebApp", "rdp")).toBe(false);
    });

    it("catch-all (dest:) should match any protocol in mixed set", () => {
      expect(hasDestAccess(mixed, "gw-2", "App", "rdp")).toBe(true);
      expect(hasDestAccess(mixed, "gw-2", "App", "vnc")).toBe(true);
      expect(hasDestAccess(mixed, "gw-2", "App", "http")).toBe(true);
    });

    it("protocol-specific role should NOT match without protocol arg", () => {
      const rdpOnly: DestPermission[] = [
        { gatewayId: "gw-1", backendName: "Server", protocol: "rdp" },
      ];
      // No protocol specified — only catch-all (null) would match
      expect(hasDestAccess(rdpOnly, "gw-1", "Server")).toBe(false);
    });

    it("same backend name with different protocol roles", () => {
      // User has rdp: but not vnc: for the same backend
      const perms: DestPermission[] = [
        { gatewayId: "gw-1", backendName: "Desktop", protocol: "rdp" },
      ];
      expect(hasDestAccess(perms, "gw-1", "Desktop", "rdp")).toBe(true);
      expect(hasDestAccess(perms, "gw-1", "Desktop", "vnc")).toBe(false);
    });
  });
});
