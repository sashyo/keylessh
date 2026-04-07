/**
 * @fileoverview Tests for destination/endpoint role parsing from JWT tokens.
 *
 * Tests parseDestRolesFromToken() and hasDestAccess() which handle
 * dest:<gatewayId>:<backendName> role patterns for gateway backend
 * access control.
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
      realm_access: { roles: ["user"] },
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
    expect(result).toEqual([{ gatewayId: "gw-abc", backendName: "WebApp", prefix: "dest" }]);
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
    expect(result).toEqual([{ gatewayId: "gw-123", backendName: "MyApp", prefix: "dest" }]);
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
    expect(result).toContainEqual({ gatewayId: "gw-1", backendName: "App1", prefix: "dest" });
    expect(result).toContainEqual({ gatewayId: "gw-2", backendName: "App2", prefix: "dest" });
  });

  it("should handle gateway IDs with dashes", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gateway-abc-def-123:Backend"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gateway-abc-def-123", backendName: "Backend", prefix: "dest" }]);
  });

  it("should parse 4-segment format with username", () => {
    // dest:<gateway>:<backend>:<username> for passwordless RDP
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["dest:gw-1:sashaspc:Administrator"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-1", backendName: "sashaspc", username: "Administrator", prefix: "dest" }]);
  });

  it("should also parse ssh: prefixed roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["ssh:gw-1:myserver"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toEqual([{ gatewayId: "gw-1", backendName: "myserver", prefix: "ssh" }]);
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

  it("should ignore non-dest and non-ssh roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["admin", "user", "dest:gw-1:App"] },
      resource_access: {},
    };
    const result = parseDestRolesFromToken(payload);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ gatewayId: "gw-1", backendName: "App", prefix: "dest" });
  });
});

describe("hasDestAccess", () => {
  const permissions: DestPermission[] = [
    { gatewayId: "gw-abc", backendName: "WebApp", prefix: "dest" },
    { gatewayId: "gw-xyz", backendName: "AdminPanel", prefix: "dest" },
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
});
