/**
 * @fileoverview Tests for the API client module.
 *
 * This file tests:
 * - api.servers - Server management endpoints (list, get)
 * - api.sessions - SSH session management (list, create, end)
 * - api.forseti - Forseti contract compilation
 * - api.sshPolicies - SSH policy retrieval
 * - api.admin.users - Admin user management (list, add, delete, setEnabled)
 * - api.admin.roles - Admin role management (list, create, delete)
 * - api.admin.recordings - Session recording management
 * - api.admin.license - License information and limit checking
 * - Type definitions for API responses
 *
 * The API client provides a typed interface to the KeyleSSH backend,
 * handling authentication headers and request/response serialization.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  api,
  type SshPolicyConfig,
  type SshPolicyResponse,
  type PendingSshPolicy,
  type SshPolicyDecision,
  type SshPolicyLog,
  type SshPolicyStatus,
  type ApprovalType,
  type ApprovalStatus,
  type PendingApproval,
  type SubscriptionTier,
  type SubscriptionStatus,
  type OverLimitStatus,
  type LicenseInfo,
  type LimitCheck,
  type ChangeSetRequest,
  type AccessApproval,
  type RoleApproval,
  type FileOperationLog,
  type RecordingSummary,
  type RecordingDetails,
  type RecordingsListResponse,
  type RecordingStats,
} from "@/lib/api";

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock localStorage for token storage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(global, "localStorage", { value: localStorageMock });

/**
 * Tests for the API client methods.
 * Verifies correct endpoint URLs, HTTP methods, and request bodies.
 */
describe("API Client", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorageMock.getItem.mockReturnValue("test-token");
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    });
  });

  /**
   * Tests for api.servers namespace.
   * Manages registered SSH servers.
   */
  describe("api.servers", () => {
    // GET /api/servers - list all registered servers
    it("should list servers", async () => {
      const servers = [{ id: "1", name: "Server 1" }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(servers),
      });

      const result = await api.servers.list();
      expect(result).toEqual(servers);
      expect(mockFetch).toHaveBeenCalledWith(
        "/api/servers",
        expect.any(Object)
      );
    });

    // GET /api/servers/:id - get single server details
    it("should get a single server", async () => {
      const server = { id: "123", name: "Test Server" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(server),
      });

      const result = await api.servers.get("123");
      expect(result).toEqual(server);
      expect(mockFetch).toHaveBeenCalledWith(
        "/api/servers/123",
        expect.any(Object)
      );
    });
  });

  /**
   * Tests for api.sessions namespace.
   * Manages active SSH sessions.
   */
  describe("api.sessions", () => {
    // GET /api/sessions - list all active sessions
    it("should list sessions", async () => {
      const sessions = [{ id: "1", status: "active" }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(sessions),
      });

      const result = await api.sessions.list();
      expect(result).toEqual(sessions);
    });

    // POST /api/sessions - create new SSH session
    it("should create a session", async () => {
      const session = { id: "new-1", status: "active" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(session),
      });

      const result = await api.sessions.create({
        serverId: "server-1",
        sshUser: "ubuntu",
      });

      expect(result).toEqual(session);
      expect(mockFetch).toHaveBeenCalledWith(
        "/api/sessions",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ serverId: "server-1", sshUser: "ubuntu" }),
        })
      );
    });

    // DELETE /api/sessions/:id - terminate session
    it("should end a session", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(),
      });

      await api.sessions.end("session-123");

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/sessions/session-123",
        expect.objectContaining({ method: "DELETE" })
      );
    });
  });

  /**
   * Tests for api.forseti namespace.
   * Handles Forseti contract compilation.
   */
  describe("api.forseti", () => {
    // POST /api/forseti/compile - compile C# contract source
    it("should compile contract source", async () => {
      const result = { success: true, contractId: "abc123" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(result),
      });

      const response = await api.forseti.compile("public class Test {}");

      expect(response).toEqual(result);
      expect(mockFetch).toHaveBeenCalledWith(
        "/api/forseti/compile",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ source: "public class Test {}" }),
        })
      );
    });
  });

  /**
   * Tests for api.sshPolicies namespace.
   * Retrieves SSH policy configurations.
   */
  describe("api.sshPolicies", () => {
    // GET /api/ssh-policies/for-ssh-user/:user - get policy by SSH username
    it("should get policy for SSH user", async () => {
      const policy = { roleId: "ssh:ubuntu", policyData: "base64data" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(policy),
      });

      const result = await api.sshPolicies.getForSshUser("ubuntu");

      expect(result).toEqual(policy);
      expect(mockFetch).toHaveBeenCalledWith(
        "/api/ssh-policies/for-ssh-user/ubuntu",
        expect.any(Object)
      );
    });

    // Special characters in username must be URL encoded
    it("should URL encode SSH user", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await api.sshPolicies.getForSshUser("user/with/slashes");

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/ssh-policies/for-ssh-user/user%2Fwith%2Fslashes",
        expect.any(Object)
      );
    });
  });

  /**
   * Tests for api.admin.users namespace.
   * Admin endpoints for user management.
   */
  describe("api.admin.users", () => {
    // GET /api/admin/users - list all users in realm
    it("should list users", async () => {
      const users = [{ id: "1", email: "test@example.com" }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(users),
      });

      const result = await api.admin.users.list();
      expect(result).toEqual(users);
    });

    // POST /api/admin/users/add - create new user
    it("should add a user", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ message: "User created" }),
      });

      await api.admin.users.add({
        username: "newuser",
        firstName: "New",
        lastName: "User",
        email: "new@example.com",
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/users/add",
        expect.objectContaining({
          method: "POST",
        })
      );
    });

    // DELETE /api/admin/users?userId=xxx - delete user
    it("should delete a user", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      await api.admin.users.delete("user-123");

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/users?userId=user-123",
        expect.objectContaining({ method: "DELETE" })
      );
    });

    // PUT /api/admin/users/:id/enabled - enable/disable user
    it("should set user enabled status", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true, enabled: false }),
      });

      await api.admin.users.setEnabled("user-123", false);

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/users/user-123/enabled",
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({ enabled: false }),
        })
      );
    });
  });

  /**
   * Tests for api.admin.roles namespace.
   * Admin endpoints for role management.
   */
  describe("api.admin.roles", () => {
    // GET /api/admin/roles - list all realm roles
    it("should list roles", async () => {
      const roles = { roles: [{ id: "1", name: "admin" }] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(roles),
      });

      const result = await api.admin.roles.list();
      expect(result).toEqual(roles);
    });

    // POST /api/admin/roles - create new role
    it("should create a role", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: "Role created" }),
      });

      await api.admin.roles.create({ name: "new-role", description: "A new role" });

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/roles",
        expect.objectContaining({
          method: "POST",
        })
      );
    });

    // DELETE /api/admin/roles?roleName=xxx - delete role
    it("should delete a role", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: "Role deleted" }),
      });

      await api.admin.roles.delete("my-role");

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/roles?roleName=my-role",
        expect.objectContaining({ method: "DELETE" })
      );
    });
  });

  /**
   * Tests for api.admin.recordings namespace.
   * Admin endpoints for session recording management.
   */
  describe("api.admin.recordings", () => {
    // GET /api/admin/recordings with query params
    it("should list recordings with params", async () => {
      const response = { recordings: [], totalCount: 0, totalStorage: 0 };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(response),
      });

      await api.admin.recordings.list({
        limit: 10,
        offset: 5,
        serverId: "server-1",
        search: "test",
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/recordings?limit=10&offset=5&serverId=server-1&search=test",
        expect.any(Object)
      );
    });

    // GET /api/admin/recordings without params
    it("should list recordings without params", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ recordings: [] }),
      });

      await api.admin.recordings.list();

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/recordings",
        expect.any(Object)
      );
    });

    // GET /api/admin/recordings/stats - aggregate statistics
    it("should get recording stats", async () => {
      const stats = { totalCount: 100, totalStorage: 1024000 };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(stats),
      });

      const result = await api.admin.recordings.getStats();
      expect(result).toEqual(stats);
    });

    // DELETE /api/admin/recordings/:id - delete recording
    it("should delete a recording", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      await api.admin.recordings.delete("rec-123");

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/admin/recordings/rec-123",
        expect.objectContaining({ method: "DELETE" })
      );
    });
  });

  /**
   * Tests for api.admin.license namespace.
   * License and subscription management.
   */
  describe("api.admin.license", () => {
    // GET /api/admin/license - get current license info
    it("should get license info", async () => {
      const license = { tier: "pro", tierName: "Pro" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(license),
      });

      const result = await api.admin.license.get();
      expect(result).toEqual(license);
    });

    // GET /api/admin/license/check/:resource - check resource limits
    it("should check resource limit", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ allowed: true, current: 3, limit: 5 }),
      });

      const result = await api.admin.license.checkLimit("user");
      expect(result.allowed).toBe(true);
    });
  });
});

/**
 * Tests for API type definitions.
 * Ensures TypeScript interfaces match expected shapes.
 */
describe("API Type Definitions", () => {
  /**
   * SshPolicyConfig: Configuration for SSH access policies.
   */
  describe("SshPolicyConfig", () => {
    // All required fields should be type-safe
    it("should accept valid config", () => {
      const config: SshPolicyConfig = {
        enabled: true,
        contractType: "forseti",
        approvalType: "explicit",
        executionType: "private",
        threshold: 2,
      };
      expect(config.enabled).toBe(true);
      expect(config.threshold).toBe(2);
    });
  });

  /**
   * SshPolicyStatus: Possible states for SSH policy requests.
   */
  describe("SshPolicyStatus", () => {
    // Should include all valid status values
    it("should accept valid statuses", () => {
      const statuses: SshPolicyStatus[] = ["pending", "approved", "committed", "cancelled"];
      expect(statuses).toHaveLength(4);
    });
  });

  /**
   * ApprovalType and ApprovalStatus: Types for admin approval workflows.
   */
  describe("ApprovalType and ApprovalStatus", () => {
    // All user/role management approval types
    it("should accept valid approval types", () => {
      const types: ApprovalType[] = [
        "user_create",
        "user_update",
        "user_delete",
        "role_assign",
        "role_remove",
      ];
      expect(types).toHaveLength(5);
    });

    // All possible approval statuses
    it("should accept valid approval statuses", () => {
      const statuses: ApprovalStatus[] = [
        "pending",
        "approved",
        "denied",
        "committed",
        "cancelled",
      ];
      expect(statuses).toHaveLength(5);
    });
  });

  /**
   * ChangeSetRequest: Request to approve/deny a pending change.
   */
  describe("ChangeSetRequest", () => {
    // Required fields for change set operations
    it("should have required fields", () => {
      const request: ChangeSetRequest = {
        changeSetId: "cs-123",
        changeSetType: "role",
        actionType: "add",
      };
      expect(request.changeSetId).toBe("cs-123");
    });
  });

  /**
   * OverLimitStatus: Resource limit status for users and servers.
   */
  describe("OverLimitStatus", () => {
    // Structure for tracking user/server limits
    it("should structure user and server limits", () => {
      const status: OverLimitStatus = {
        users: {
          isOverLimit: true,
          enabled: 10,
          total: 12,
          limit: 5,
          overBy: 5,
        },
        servers: {
          isOverLimit: false,
          enabled: 2,
          total: 3,
          limit: 10,
          overBy: 0,
        },
      };
      expect(status.users.isOverLimit).toBe(true);
      expect(status.servers.isOverLimit).toBe(false);
    });
  });

  /**
   * LicenseInfo: Complete license and subscription data.
   */
  describe("LicenseInfo", () => {
    // Full license info structure with usage and limits
    it("should structure license data", () => {
      const info: LicenseInfo = {
        subscription: null,
        usage: { users: 3, servers: 1 },
        limits: { maxUsers: 5, maxServers: 2 },
        tier: "free",
        tierName: "Free",
      };
      expect(info.tier).toBe("free");
      expect(info.limits.maxUsers).toBe(5);
    });
  });

  /**
   * Recording types: Session recording metadata and statistics.
   */
  describe("Recording types", () => {
    // RecordingSummary: Brief info about a recording
    it("should structure RecordingSummary", () => {
      const summary: RecordingSummary = {
        id: "rec-1",
        sessionId: "sess-1",
        serverId: "srv-1",
        serverName: "Production",
        userId: "user-1",
        userEmail: "user@example.com",
        sshUser: "ubuntu",
        startedAt: "2024-01-01T00:00:00Z",
        endedAt: "2024-01-01T01:00:00Z",
        duration: 3600,
        terminalWidth: 120,
        terminalHeight: 40,
        fileSize: 102400,
      };
      expect(summary.duration).toBe(3600);
    });

    // RecordingStats: Aggregate recording statistics
    it("should structure RecordingStats", () => {
      const stats: RecordingStats = {
        totalCount: 100,
        totalStorage: 1073741824,
        totalStorageFormatted: "1 GB",
      };
      expect(stats.totalCount).toBe(100);
    });
  });

  /**
   * FileOperationLog: SFTP/SCP file operation audit log.
   */
  describe("FileOperationLog", () => {
    // Full file operation structure with all metadata
    it("should structure file operation data", () => {
      const op: FileOperationLog = {
        id: "op-1",
        sessionId: "sess-1",
        serverId: "srv-1",
        serverName: "Server",
        serverHost: "192.168.1.1",
        userId: "user-1",
        userEmail: "user@example.com",
        sshUser: "root",
        operation: "upload",
        path: "/home/user/file.txt",
        targetPath: null,
        fileSize: 1024,
        mode: "sftp",
        status: "success",
        errorMessage: null,
        timestamp: "2024-01-01T12:00:00Z",
      };
      expect(op.operation).toBe("upload");
      expect(op.mode).toBe("sftp");
    });
  });
});
