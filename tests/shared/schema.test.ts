/**
 * @fileoverview Tests for the shared database schema definitions.
 *
 * This file tests:
 * - Subscription tier configurations (free, pro, enterprise limits)
 * - Zod insert schemas for database tables (users, servers, sessions, subscriptions, billing)
 * - TypeScript type definitions for enums and interfaces
 *
 * These schemas are used by Drizzle ORM for database operations and
 * Zod for runtime validation of data before insertion.
 */

import { describe, it, expect } from "vitest";
import {
  insertUserSchema,
  insertServerSchema,
  insertSessionSchema,
  insertSubscriptionSchema,
  insertBillingHistorySchema,
  subscriptionTiers,
  type InsertUser,
  type InsertServer,
  type InsertSession,
  type UserRole,
  type ServerStatus,
  type ConnectionStatus,
  type FileOperationType,
  type FileOperationMode,
  type FileOperationStatus,
  type SubscriptionTier,
  type SubscriptionStatus,
} from "@shared/schema";

/**
 * Tests for the subscription tier configuration object.
 * Verifies that each tier has correct user and server limits.
 */
describe("Schema Types", () => {
  describe("subscriptionTiers", () => {
    // Verifies the free tier has restrictive limits: 5 users, 2 servers
    it("should have free tier with correct limits", () => {
      expect(subscriptionTiers.free).toEqual({
        name: "Free",
        maxUsers: 5,
        maxServers: 2,
      });
    });

    // Verifies the pro tier has moderate limits: 25 users, 10 servers
    it("should have pro tier with correct limits", () => {
      expect(subscriptionTiers.pro).toEqual({
        name: "Pro",
        maxUsers: 25,
        maxServers: 10,
      });
    });

    // Verifies enterprise tier uses -1 to indicate unlimited resources
    it("should have enterprise tier with unlimited access", () => {
      expect(subscriptionTiers.enterprise).toEqual({
        name: "Enterprise",
        maxUsers: -1,
        maxServers: -1,
      });
    });
  });
});

/**
 * Tests for Zod insert schemas.
 * These schemas validate data before inserting into the database.
 * They ensure required fields are present and data types are correct.
 */
describe("Insert Schemas", () => {
  /**
   * Tests for user insertion validation.
   * Users require: username, email, role, allowedServers
   */
  describe("insertUserSchema", () => {
    // Confirms a complete user object passes validation
    it("should validate a valid user", () => {
      const validUser: InsertUser = {
        username: "testuser",
        email: "test@example.com",
        role: "user",
        allowedServers: [],
      };

      const result = insertUserSchema.safeParse(validUser);
      expect(result.success).toBe(true);
    });

    // Username is required - validation should fail without it
    it("should reject user without username", () => {
      const invalidUser = {
        email: "test@example.com",
        role: "user",
        allowedServers: [],
      };

      const result = insertUserSchema.safeParse(invalidUser);
      expect(result.success).toBe(false);
    });

    // Email is required - validation should fail without it
    it("should reject user without email", () => {
      const invalidUser = {
        username: "testuser",
        role: "user",
        allowedServers: [],
      };

      const result = insertUserSchema.safeParse(invalidUser);
      expect(result.success).toBe(false);
    });

    // Users can have a list of servers they're allowed to access
    it("should accept user with allowed servers array", () => {
      const validUser: InsertUser = {
        username: "testuser",
        email: "test@example.com",
        role: "admin",
        allowedServers: ["server-1", "server-2"],
      };

      const result = insertUserSchema.safeParse(validUser);
      expect(result.success).toBe(true);
    });
  });

  /**
   * Tests for server insertion validation.
   * Servers require: name, host. Optional: port, environment, tags, sshUsers, recording settings
   */
  describe("insertServerSchema", () => {
    // Confirms a complete server object with all fields passes validation
    it("should validate a valid server", () => {
      const validServer: InsertServer = {
        name: "Production Server",
        host: "192.168.1.100",
        port: 22,
        environment: "production",
        tags: ["web", "api"],
        enabled: true,
        sshUsers: ["root", "ubuntu"],
        recordingEnabled: false,
        recordedUsers: [],
      };

      const result = insertServerSchema.safeParse(validServer);
      expect(result.success).toBe(true);
    });

    // Server name is required for identification
    it("should reject server without name", () => {
      const invalidServer = {
        host: "192.168.1.100",
        port: 22,
      };

      const result = insertServerSchema.safeParse(invalidServer);
      expect(result.success).toBe(false);
    });

    // Host (IP or hostname) is required for connection
    it("should reject server without host", () => {
      const invalidServer = {
        name: "Test Server",
        port: 22,
      };

      const result = insertServerSchema.safeParse(invalidServer);
      expect(result.success).toBe(false);
    });

    // Only name and host are strictly required; other fields have defaults
    it("should accept server with minimal fields", () => {
      const minimalServer = {
        name: "Test Server",
        host: "localhost",
      };

      const result = insertServerSchema.safeParse(minimalServer);
      expect(result.success).toBe(true);
    });
  });

  /**
   * Tests for session insertion validation.
   * Sessions track active SSH connections between users and servers.
   * Required: userId, serverId, sshUser
   */
  describe("insertSessionSchema", () => {
    // Confirms a valid session object passes validation
    it("should validate a valid session", () => {
      const validSession: InsertSession = {
        userId: "user-123",
        serverId: "server-456",
        sshUser: "ubuntu",
        status: "active",
      };

      const result = insertSessionSchema.safeParse(validSession);
      expect(result.success).toBe(true);
    });

    // Must know which user initiated the session
    it("should reject session without userId", () => {
      const invalidSession = {
        serverId: "server-456",
        sshUser: "ubuntu",
      };

      const result = insertSessionSchema.safeParse(invalidSession);
      expect(result.success).toBe(false);
    });

    // Must know which server the session connects to
    it("should reject session without serverId", () => {
      const invalidSession = {
        userId: "user-123",
        sshUser: "ubuntu",
      };

      const result = insertSessionSchema.safeParse(invalidSession);
      expect(result.success).toBe(false);
    });

    // Must know the SSH username used for the connection
    it("should reject session without sshUser", () => {
      const invalidSession = {
        userId: "user-123",
        serverId: "server-456",
      };

      const result = insertSessionSchema.safeParse(invalidSession);
      expect(result.success).toBe(false);
    });
  });

  /**
   * Tests for subscription insertion validation.
   * Subscriptions track the organization's billing tier and Stripe integration.
   */
  describe("insertSubscriptionSchema", () => {
    // Minimal subscription just needs tier and status
    it("should validate a valid subscription", () => {
      const validSubscription = {
        tier: "pro",
        status: "active",
      };

      const result = insertSubscriptionSchema.safeParse(validSubscription);
      expect(result.success).toBe(true);
    });

    // Full subscription includes Stripe customer/subscription IDs for billing
    it("should accept subscription with Stripe fields", () => {
      const subscription = {
        tier: "enterprise",
        stripeCustomerId: "cus_123",
        stripeSubscriptionId: "sub_456",
        stripePriceId: "price_789",
        status: "active",
        currentPeriodEnd: 1735689600,
        cancelAtPeriodEnd: false,
      };

      const result = insertSubscriptionSchema.safeParse(subscription);
      expect(result.success).toBe(true);
    });
  });

  /**
   * Tests for billing history insertion validation.
   * Billing history tracks past payments and invoices.
   */
  describe("insertBillingHistorySchema", () => {
    // Basic billing entry with amount and status
    it("should validate a valid billing history entry", () => {
      const validBilling = {
        subscriptionId: "sub-123",
        amount: 2999, // Amount in cents ($29.99)
        currency: "usd",
        status: "paid",
      };

      const result = insertBillingHistorySchema.safeParse(validBilling);
      expect(result.success).toBe(true);
    });

    // Must link to a subscription
    it("should reject billing without subscriptionId", () => {
      const invalidBilling = {
        amount: 2999,
        currency: "usd",
        status: "paid",
      };

      const result = insertBillingHistorySchema.safeParse(invalidBilling);
      expect(result.success).toBe(false);
    });

    // Must have a payment amount
    it("should reject billing without amount", () => {
      const invalidBilling = {
        subscriptionId: "sub-123",
        currency: "usd",
        status: "paid",
      };

      const result = insertBillingHistorySchema.safeParse(invalidBilling);
      expect(result.success).toBe(false);
    });
  });
});

/**
 * Tests for TypeScript type definitions.
 * These ensure the type literals are correctly defined and usable.
 */
describe("Type Definitions", () => {
  /**
   * UserRole type: "user" | "admin"
   * Used for access control throughout the application.
   */
  describe("UserRole", () => {
    // Both role values should be assignable to UserRole type
    it("should accept valid user roles", () => {
      const userRole: UserRole = "user";
      const adminRole: UserRole = "admin";
      expect(userRole).toBe("user");
      expect(adminRole).toBe("admin");
    });
  });

  /**
   * ServerStatus type: "online" | "offline" | "unknown"
   * Indicates the result of server health checks.
   */
  describe("ServerStatus", () => {
    // All three status values should be valid
    it("should accept valid server statuses", () => {
      const online: ServerStatus = "online";
      const offline: ServerStatus = "offline";
      const unknown: ServerStatus = "unknown";
      expect(online).toBe("online");
      expect(offline).toBe("offline");
      expect(unknown).toBe("unknown");
    });
  });

  /**
   * ConnectionStatus type: "connecting" | "connected" | "disconnected" | "error"
   * Tracks the state of WebSocket/SSH connections.
   */
  describe("ConnectionStatus", () => {
    // All four connection states should be valid
    it("should accept valid connection statuses", () => {
      const connecting: ConnectionStatus = "connecting";
      const connected: ConnectionStatus = "connected";
      const disconnected: ConnectionStatus = "disconnected";
      const error: ConnectionStatus = "error";
      expect(connecting).toBe("connecting");
      expect(connected).toBe("connected");
      expect(disconnected).toBe("disconnected");
      expect(error).toBe("error");
    });
  });

  /**
   * File operation types for SFTP/SCP logging.
   * Tracks what actions users perform on remote files.
   */
  describe("FileOperation types", () => {
    // Six types of file operations are tracked
    it("should accept valid file operation types", () => {
      const types: FileOperationType[] = [
        "upload",
        "download",
        "delete",
        "mkdir",
        "rename",
        "chmod",
      ];
      expect(types).toHaveLength(6);
    });

    // Two transfer modes: SFTP (interactive) and SCP (batch)
    it("should accept valid file operation modes", () => {
      const sftp: FileOperationMode = "sftp";
      const scp: FileOperationMode = "scp";
      expect(sftp).toBe("sftp");
      expect(scp).toBe("scp");
    });

    // Operations either succeed or fail with an error
    it("should accept valid file operation statuses", () => {
      const success: FileOperationStatus = "success";
      const error: FileOperationStatus = "error";
      expect(success).toBe("success");
      expect(error).toBe("error");
    });
  });

  /**
   * Subscription types for billing/licensing.
   */
  describe("Subscription types", () => {
    // Three pricing tiers available
    it("should accept valid subscription tiers", () => {
      const tiers: SubscriptionTier[] = ["free", "pro", "enterprise"];
      expect(tiers).toHaveLength(3);
    });

    // Four possible subscription states from Stripe
    it("should accept valid subscription statuses", () => {
      const statuses: SubscriptionStatus[] = [
        "active",
        "canceled",
        "past_due",
        "trialing",
      ];
      expect(statuses).toHaveLength(4);
    });
  });
});
