/**
 * @fileoverview Tests for the role configuration module.
 *
 * This file tests:
 * - Roles enum values (Admin, User)
 * - ADMIN_ROLE_NAMES constant array
 * - ADMIN_ROLE_SET for O(1) admin role lookups
 *
 * The role configuration is used throughout the app to determine
 * user permissions and access control. The admin role check is
 * critical for protecting admin-only features.
 */

import { describe, it, expect } from "vitest";
import { Roles, ADMIN_ROLE_NAMES, ADMIN_ROLE_SET } from "@shared/config/roles";

/**
 * Tests for the Roles enum and admin role configuration.
 * These constants define role identifiers used in TideCloak.
 */
describe("Roles Configuration", () => {
  /**
   * Roles enum defines the two role types in the system.
   * These map to TideCloak role names.
   */
  describe("Roles enum", () => {
    // Admin role uses TideCloak's tide-realm-admin identifier
    it("should have Admin role defined", () => {
      expect(Roles.Admin).toBe("tide-realm-admin");
    });

    // Regular user role uses appUser identifier
    it("should have User role defined", () => {
      expect(Roles.User).toBe("appUser");
    });

    // Ensure only Admin and User roles exist
    it("should have exactly 2 roles", () => {
      const roleValues = Object.values(Roles);
      expect(roleValues).toHaveLength(2);
    });
  });

  /**
   * ADMIN_ROLE_NAMES is an array of role names that grant admin access.
   * Multiple role names are supported for backwards compatibility.
   */
  describe("ADMIN_ROLE_NAMES", () => {
    // Primary admin role from TideCloak
    it("should contain tide-realm-admin", () => {
      expect(ADMIN_ROLE_NAMES).toContain("tide-realm-admin");
    });

    // Legacy/alternate admin role name
    it("should contain realm-admin", () => {
      expect(ADMIN_ROLE_NAMES).toContain("realm-admin");
    });

    // Only two admin role variations should exist
    it("should have exactly 2 admin role names", () => {
      expect(ADMIN_ROLE_NAMES).toHaveLength(2);
    });

    // The Roles.Admin enum value should be in the admin names list
    it("should include Roles.Admin", () => {
      expect(ADMIN_ROLE_NAMES).toContain(Roles.Admin);
    });
  });

  /**
   * ADMIN_ROLE_SET is a Set for O(1) lookup of admin roles.
   * Used to quickly check if any of a user's roles grants admin access.
   */
  describe("ADMIN_ROLE_SET", () => {
    // Should be a Set data structure for fast lookups
    it("should be a Set", () => {
      expect(ADMIN_ROLE_SET).toBeInstanceOf(Set);
    });

    // Can check for tide-realm-admin
    it("should have tide-realm-admin", () => {
      expect(ADMIN_ROLE_SET.has("tide-realm-admin")).toBe(true);
    });

    // Can check for realm-admin
    it("should have realm-admin", () => {
      expect(ADMIN_ROLE_SET.has("realm-admin")).toBe(true);
    });

    // Common non-admin role names should not be in the set
    it("should not have arbitrary roles", () => {
      expect(ADMIN_ROLE_SET.has("user")).toBe(false);
      expect(ADMIN_ROLE_SET.has("admin")).toBe(false); // Note: "admin" != "tide-realm-admin"
      expect(ADMIN_ROLE_SET.has("appUser")).toBe(false);
    });

    // Set should contain exactly the 2 admin role names
    it("should have size of 2", () => {
      expect(ADMIN_ROLE_SET.size).toBe(2);
    });

    // Real-world usage: check if user has any admin role
    it("should be usable for role checking", () => {
      const userRoles = ["user", "viewer", "tide-realm-admin"];
      const isAdmin = userRoles.some((role) => ADMIN_ROLE_SET.has(role));
      expect(isAdmin).toBe(true);
    });

    // Non-admin users should not match
    it("should return false for non-admin users", () => {
      const userRoles = ["user", "viewer", "appUser"];
      const isAdmin = userRoles.some((role) => ADMIN_ROLE_SET.has(role));
      expect(isAdmin).toBe(false);
    });
  });
});
