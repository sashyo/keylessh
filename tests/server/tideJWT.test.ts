/**
 * @fileoverview Tests for JWT token utility functions.
 *
 * Tests hasRole() from tideJWT which checks if a token payload
 * contains a specific role across realm and client role sources.
 */

import { describe, it, expect } from "vitest";
import { hasRole } from "../../server/lib/auth/tideJWT";
import type { TokenPayload } from "../../server/lib/auth/tideJWT";

describe("hasRole", () => {
  it("should find role in realm_access", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["admin", "user"] },
      resource_access: {},
    };
    expect(hasRole(payload, "admin")).toBe(true);
  });

  it("should find role in resource_access", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {
        keylessh: { roles: ["policy-creator"] },
      },
    };
    expect(hasRole(payload, "policy-creator")).toBe(true);
  });

  it("should find role across multiple resource clients", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {
        keylessh: { roles: ["viewer"] },
        "realm-management": { roles: ["tide-realm-admin"] },
      },
    };
    expect(hasRole(payload, "tide-realm-admin")).toBe(true);
  });

  it("should return false when role is not present", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["user"] },
      resource_access: {
        keylessh: { roles: ["viewer"] },
      },
    };
    expect(hasRole(payload, "admin")).toBe(false);
  });

  it("should return false with empty roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
    };
    expect(hasRole(payload, "admin")).toBe(false);
  });

  it("should handle missing realm_access", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      resource_access: {
        keylessh: { roles: ["ssh:root"] },
      },
    };
    expect(hasRole(payload, "ssh:root")).toBe(true);
  });

  it("should handle missing resource_access", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["admin"] },
    };
    expect(hasRole(payload, "admin")).toBe(true);
  });
});
