/**
 * @fileoverview Tests for the server-side authentication middleware.
 *
 * This file tests:
 * - authenticate() - JWT token verification and user extraction
 * - requireAdmin() - Admin role authorization guard
 * - requirePolicyCreator() - Policy creator permission guard
 *
 * The auth middleware handles TideCloak JWT verification, extracting
 * user information, roles, and permissions from tokens for authorization.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Request, Response, NextFunction } from "express";

// Mock the TideCloak verification module before importing auth
vi.mock("../../server/lib/auth/tideJWT", () => ({
  verifyTideCloakToken: vi.fn(),
}));

// Import after mocking
import { authenticate, requireAdmin, requirePolicyCreator, type AuthenticatedRequest } from "../../server/auth";
import { verifyTideCloakToken } from "../../server/lib/auth/tideJWT";

const mockVerifyToken = verifyTideCloakToken as any;

/**
 * Tests for authentication and authorization middleware.
 * Uses mocked TideCloak token verification.
 */
describe("Auth Middleware", () => {
  let mockRequest: Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let jsonMock: any;
  let statusMock: any;

  beforeEach(() => {
    vi.clearAllMocks();

    jsonMock = vi.fn();
    statusMock = vi.fn().mockReturnValue({ json: jsonMock });

    mockRequest = {
      headers: {},
      query: {},
    };

    mockResponse = {
      status: statusMock,
      json: jsonMock,
    };

    mockNext = vi.fn();
  });

  /**
   * Tests for authenticate() middleware.
   * Verifies JWT tokens and extracts user information.
   */
  describe("authenticate", () => {
    // Request without any token should be rejected
    it("should return 401 when no token is provided", async () => {
      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Authentication required" });
      expect(mockNext).not.toHaveBeenCalled();
    });

    // Token from "Bearer xxx" format in Authorization header
    it("should extract token from Authorization header", async () => {
      mockRequest.headers = { authorization: "Bearer test-token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "user-123",
        preferred_username: "testuser",
        email: "test@example.com",
        resource_access: {},
        realm_access: { roles: [] },
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockVerifyToken).toHaveBeenCalledWith("test-token", []);
      expect(mockNext).toHaveBeenCalled();
    });

    // Token from ?token=xxx query parameter (for WebSocket connections)
    it("should extract token from query parameter", async () => {
      mockRequest.query = { token: "query-token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "user-123",
        preferred_username: "testuser",
        email: "test@example.com",
        resource_access: {},
        realm_access: { roles: [] },
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockVerifyToken).toHaveBeenCalledWith("query-token", []);
      expect(mockNext).toHaveBeenCalled();
    });

    // Header takes precedence when both are provided
    it("should prefer Authorization header over query token", async () => {
      mockRequest.headers = { authorization: "Bearer header-token" };
      mockRequest.query = { token: "query-token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "user-123",
        preferred_username: "testuser",
        email: "test@example.com",
        resource_access: {},
        realm_access: { roles: [] },
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockVerifyToken).toHaveBeenCalledWith("header-token", []);
    });

    // Invalid/expired token returns null from verify function
    it("should return 401 when token verification fails", async () => {
      mockRequest.headers = { authorization: "Bearer invalid-token" };
      mockVerifyToken.mockResolvedValueOnce(null);

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Invalid or expired token" });
      expect(mockNext).not.toHaveBeenCalled();
    });

    // Verification throws an error (network issue, malformed token, etc.)
    it("should return 401 when token verification throws", async () => {
      mockRequest.headers = { authorization: "Bearer bad-token" };
      mockVerifyToken.mockRejectedValueOnce(new Error("Token expired"));

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Token verification failed" });
    });

    // tide-realm-admin in realm-management client grants admin role
    it("should set user as admin when tide-realm-admin is in client roles", async () => {
      mockRequest.headers = { authorization: "Bearer admin-token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "admin-123",
        preferred_username: "admin",
        email: "admin@example.com",
        resource_access: {
          "realm-management": {
            roles: ["tide-realm-admin"],
          },
        },
        realm_access: { roles: [] },
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect((mockRequest as AuthenticatedRequest).user?.role).toBe("admin");
      expect((mockRequest as AuthenticatedRequest).user?.isAdmin).toBeUndefined(); // isAdmin is computed in AdminUser, not OIDCUser
    });

    // User without admin role gets "user" role
    it("should set user as regular user when no admin role", async () => {
      mockRequest.headers = { authorization: "Bearer user-token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "user-123",
        preferred_username: "user",
        email: "user@example.com",
        resource_access: {},
        realm_access: { roles: ["user"] },
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect((mockRequest as AuthenticatedRequest).user?.role).toBe("user");
    });

    // Custom claim for server access permissions
    it("should extract allowed_servers from token", async () => {
      mockRequest.headers = { authorization: "Bearer token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "user-123",
        preferred_username: "user",
        email: "user@example.com",
        resource_access: {},
        realm_access: { roles: [] },
        allowed_servers: ["server-1", "server-2"],
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect((mockRequest as AuthenticatedRequest).user?.allowedServers).toEqual(["server-1", "server-2"]);
    });

    // Raw token stored for downstream API calls
    it("should store access token on request", async () => {
      mockRequest.headers = { authorization: "Bearer my-token" };
      mockVerifyToken.mockResolvedValueOnce({
        sub: "user-123",
        preferred_username: "user",
        email: "user@example.com",
        resource_access: {},
        realm_access: { roles: [] },
      });

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect((mockRequest as AuthenticatedRequest).accessToken).toBe("my-token");
    });

    // Full decoded payload stored for custom claim access
    it("should store token payload on request", async () => {
      mockRequest.headers = { authorization: "Bearer token" };
      const payload = {
        sub: "user-123",
        preferred_username: "user",
        email: "user@example.com",
        resource_access: {},
        realm_access: { roles: [] },
        custom_claim: "value",
      };
      mockVerifyToken.mockResolvedValueOnce(payload);

      await authenticate(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect((mockRequest as AuthenticatedRequest).tokenPayload).toEqual(payload);
    });
  });

  /**
   * Tests for requireAdmin() middleware.
   * Guards routes that require administrator privileges.
   */
  describe("requireAdmin", () => {
    // Must be authenticated first (user object must exist)
    it("should return 401 when no user on request", () => {
      requireAdmin(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Authentication required" });
      expect(mockNext).not.toHaveBeenCalled();
    });

    // Regular users cannot access admin routes
    it("should return 403 when user is not admin", () => {
      mockRequest.user = {
        id: "user-123",
        username: "user",
        email: "user@example.com",
        role: "user",
        allowedServers: [],
      };

      requireAdmin(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Admin access required" });
      expect(mockNext).not.toHaveBeenCalled();
    });

    // Admin role allows access
    it("should call next when user is admin", () => {
      mockRequest.user = {
        id: "admin-123",
        username: "admin",
        email: "admin@example.com",
        role: "admin",
        allowedServers: [],
      };

      requireAdmin(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });
  });

  /**
   * Tests for requirePolicyCreator() middleware.
   * Guards routes that require policy creation permissions.
   * Allows: tide-realm-admin, realm-admin, or policy-creator role.
   */
  describe("requirePolicyCreator", () => {
    // Must be authenticated first
    it("should return 401 when no user on request", () => {
      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Authentication required" });
    });

    // Token payload required to check specific roles
    it("should return 401 when no token payload", () => {
      mockRequest.user = {
        id: "user-123",
        username: "user",
        email: "user@example.com",
        role: "user",
        allowedServers: [],
      };
      // tokenPayload is undefined

      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Token payload not available" });
    });

    // tide-realm-admin can create policies (full admin)
    it("should allow tide-realm-admin", () => {
      mockRequest.user = {
        id: "admin-123",
        username: "admin",
        email: "admin@example.com",
        role: "admin",
        allowedServers: [],
      };
      mockRequest.tokenPayload = {
        sub: "admin-123",
        resource_access: {
          "realm-management": {
            roles: ["tide-realm-admin"],
          },
        },
        realm_access: { roles: [] },
      } as any;

      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });

    // realm-admin can create policies (Keycloak admin)
    it("should allow realm-admin", () => {
      mockRequest.user = {
        id: "admin-123",
        username: "admin",
        email: "admin@example.com",
        role: "admin",
        allowedServers: [],
      };
      mockRequest.tokenPayload = {
        sub: "admin-123",
        resource_access: {
          "realm-management": {
            roles: ["realm-admin"],
          },
        },
        realm_access: { roles: [] },
      } as any;

      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });

    // policy-creator role in keylessh client grants permission
    it("should allow policy-creator role in resource client", () => {
      mockRequest.user = {
        id: "creator-123",
        username: "creator",
        email: "creator@example.com",
        role: "user",
        allowedServers: [],
      };
      mockRequest.tokenPayload = {
        sub: "creator-123",
        resource_access: {
          "keylessh": {
            roles: ["policy-creator"],
          },
        },
        realm_access: { roles: [] },
      } as any;

      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });

    // User without any policy creator roles is denied
    it("should return 403 when user lacks policy creator permissions", () => {
      mockRequest.user = {
        id: "user-123",
        username: "user",
        email: "user@example.com",
        role: "user",
        allowedServers: [],
      };
      mockRequest.tokenPayload = {
        sub: "user-123",
        resource_access: {
          "keylessh": {
            roles: ["viewer"],
          },
        },
        realm_access: { roles: ["user"] },
      } as any;

      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({ message: "Policy creator access required" });
    });

    // Admin roles can also be in realm_access (not just resource_access)
    it("should check realm_access for admin roles", () => {
      mockRequest.user = {
        id: "admin-123",
        username: "admin",
        email: "admin@example.com",
        role: "admin",
        allowedServers: [],
      };
      mockRequest.tokenPayload = {
        sub: "admin-123",
        resource_access: {},
        realm_access: { roles: ["tide-realm-admin"] },
      } as any;

      requirePolicyCreator(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });
  });
});
