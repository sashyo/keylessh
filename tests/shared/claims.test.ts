/**
 * @fileoverview Tests for SSH claim name constants.
 *
 * Verifies the set of claim names that can carry SSH username
 * authorization in JWT tokens.
 */

import { describe, it, expect } from "vitest";
import { SSH_USERS_CLAIM_NAMES } from "@shared/config/claims";

describe("SSH_USERS_CLAIM_NAMES", () => {
  it("should include all expected claim names", () => {
    expect(SSH_USERS_CLAIM_NAMES).toContain("ssh_users");
    expect(SSH_USERS_CLAIM_NAMES).toContain("sshUsers");
    expect(SSH_USERS_CLAIM_NAMES).toContain("allowed_ssh_users");
    expect(SSH_USERS_CLAIM_NAMES).toContain("allowedSshUsers");
  });

  it("should have exactly 4 claim names", () => {
    expect(SSH_USERS_CLAIM_NAMES).toHaveLength(4);
  });

  it("should be a readonly tuple", () => {
    // TypeScript enforces readonly at compile time; runtime check that it's an array
    expect(Array.isArray(SSH_USERS_CLAIM_NAMES)).toBe(true);
  });

  it("should support both snake_case and camelCase conventions", () => {
    const snakeCase = SSH_USERS_CLAIM_NAMES.filter((n) => n.includes("_"));
    const camelCase = SSH_USERS_CLAIM_NAMES.filter((n) => !n.includes("_"));
    expect(snakeCase).toHaveLength(2);
    expect(camelCase).toHaveLength(2);
  });
});
