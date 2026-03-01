/**
 * @fileoverview Tests for SSH username extraction from JWT tokens.
 *
 * Tests getAllowedSshUsersFromToken() which extracts permitted SSH
 * usernames from both role-based (ssh:user, ssh-user) and claim-based
 * (ssh_users, sshUsers, allowed_ssh_users, allowedSshUsers) sources.
 */

import { describe, it, expect } from "vitest";
import { getAllowedSshUsersFromToken } from "../../server/lib/auth/sshUsers";
import type { TokenPayload } from "../../server/lib/auth/tideJWT";

describe("getAllowedSshUsersFromToken", () => {
  it("should return empty array for null payload", () => {
    expect(getAllowedSshUsersFromToken(null)).toEqual([]);
  });

  it("should return empty array for undefined payload", () => {
    expect(getAllowedSshUsersFromToken(undefined)).toEqual([]);
  });

  it("should return empty array when no SSH roles or claims", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["user"] },
      resource_access: {},
    };
    expect(getAllowedSshUsersFromToken(payload)).toEqual([]);
  });

  // ── Role-based extraction ──────────────────────────────────────

  it("should extract SSH user from ssh:username realm role", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["ssh:root"] },
      resource_access: {},
    };
    expect(getAllowedSshUsersFromToken(payload)).toEqual(["root"]);
  });

  it("should extract SSH user from ssh-username realm role", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["ssh-deploy"] },
      resource_access: {},
    };
    expect(getAllowedSshUsersFromToken(payload)).toEqual(["deploy"]);
  });

  it("should extract SSH users from client roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {
        keylessh: { roles: ["ssh:admin", "ssh:deploy"] },
      },
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toContain("admin");
    expect(result).toContain("deploy");
  });

  it("should combine realm and client SSH roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["ssh:root"] },
      resource_access: {
        keylessh: { roles: ["ssh:deploy"] },
      },
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toContain("root");
    expect(result).toContain("deploy");
  });

  it("should ignore non-SSH roles", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["admin", "user", "ssh:root"] },
      resource_access: {},
    };
    expect(getAllowedSshUsersFromToken(payload)).toEqual(["root"]);
  });

  it("should be case-insensitive for ssh prefix", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["SSH:root", "Ssh-deploy"] },
      resource_access: {},
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toContain("root");
    expect(result).toContain("deploy");
  });

  // ── Claim-based extraction ─────────────────────────────────────

  it("should extract from ssh_users claim (array)", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      ssh_users: ["root", "deploy"],
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toContain("root");
    expect(result).toContain("deploy");
  });

  it("should extract from ssh_users claim (comma-separated string)", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      ssh_users: "root, deploy",
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toContain("root");
    expect(result).toContain("deploy");
  });

  it("should extract from sshUsers claim", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      sshUsers: ["ubuntu"],
    };
    expect(getAllowedSshUsersFromToken(payload)).toContain("ubuntu");
  });

  it("should extract from allowed_ssh_users claim", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      allowed_ssh_users: ["ec2-user"],
    };
    expect(getAllowedSshUsersFromToken(payload)).toContain("ec2-user");
  });

  it("should extract from allowedSshUsers claim", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      allowedSshUsers: ["admin"],
    };
    expect(getAllowedSshUsersFromToken(payload)).toContain("admin");
  });

  // ── Deduplication ──────────────────────────────────────────────

  it("should deduplicate across roles and claims", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["ssh:root"] },
      resource_access: {},
      ssh_users: ["root"],
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toEqual(["root"]);
  });

  // ── Edge cases ─────────────────────────────────────────────────

  it("should handle empty claims gracefully", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      ssh_users: [],
    };
    expect(getAllowedSshUsersFromToken(payload)).toEqual([]);
  });

  it("should trim whitespace from claim values", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      ssh_users: "  root , deploy  ",
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toContain("root");
    expect(result).toContain("deploy");
  });

  it("should filter out empty strings from claims", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: [] },
      resource_access: {},
      ssh_users: ["root", "", " ", "deploy"],
    };
    const result = getAllowedSshUsersFromToken(payload);
    expect(result).toEqual(["root", "deploy"]);
  });

  it("should handle missing realm_access gracefully", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      ssh_users: ["root"],
    };
    expect(getAllowedSshUsersFromToken(payload)).toContain("root");
  });

  it("should handle missing resource_access gracefully", () => {
    const payload: TokenPayload = {
      sub: "user-1",
      realm_access: { roles: ["ssh:root"] },
    };
    expect(getAllowedSshUsersFromToken(payload)).toContain("root");
  });
});
