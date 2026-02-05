import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Organizations table
export const organizations = sqliteTable("organizations", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }),
});

// Organization membership (user ↔ org with role)
export const organizationUsers = sqliteTable("organization_users", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id").notNull(),
  userId: text("user_id").notNull(),
  role: text("role").notNull().default("user"), // "global-admin" | "org-admin" | "user"
  joinedAt: integer("joined_at", { mode: "timestamp" }).notNull(),
});

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull(),
  role: text("role").notNull().default("user"),
  allowedServers: text("allowed_servers", { mode: "json" }).$type<string[]>().notNull().default([]),
});

// SSH bridges - WebSocket-to-TCP relay endpoints
export const bridges = sqliteTable("bridges", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(), // WebSocket URL, e.g., wss://bridge.example.com/ws/tcp
  description: text("description"),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  isDefault: integer("is_default", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  organizationId: text("organization_id").notNull().default("default"),
});

export const servers = sqliteTable("servers", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(22),
  environment: text("environment").notNull().default("production"),
  tags: text("tags", { mode: "json" }).$type<string[]>().notNull().default([]),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  sshUsers: text("ssh_users", { mode: "json" }).$type<string[]>().notNull().default([]),
  // Session recording settings
  recordingEnabled: integer("recording_enabled", { mode: "boolean" }).notNull().default(false),
  recordedUsers: text("recorded_users", { mode: "json" }).$type<string[]>().notNull().default([]), // Empty = all users when enabled
  // Bridge association - null means use default/embedded bridge
  bridgeId: text("bridge_id"),
  organizationId: text("organization_id").notNull().default("default"),
});

export const sessions = sqliteTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull(),
  userUsername: text("user_username"),
  userEmail: text("user_email"),
  serverId: text("server_id").notNull(),
  sshUser: text("ssh_user").notNull(),
  status: text("status").notNull().default("active"),
  startedAt: integer("started_at", { mode: "timestamp" }).notNull(),
  endedAt: integer("ended_at", { mode: "timestamp" }),
  recordingId: text("recording_id"), // Link to recording if session was recorded
  organizationId: text("organization_id").notNull().default("default"),
});

// File operations log - tracks SFTP/SCP file transfers
export const fileOperations = sqliteTable("file_operations", {
  id: text("id").primaryKey(),
  sessionId: text("session_id").notNull(),
  serverId: text("server_id").notNull(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email"),
  sshUser: text("ssh_user").notNull(),
  operation: text("operation").notNull(), // "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod"
  path: text("path").notNull(),
  targetPath: text("target_path"), // For rename operations
  fileSize: integer("file_size"), // Size in bytes (for upload/download)
  mode: text("mode").notNull(), // "sftp" | "scp"
  status: text("status").notNull(), // "success" | "error"
  errorMessage: text("error_message"),
  timestamp: integer("timestamp", { mode: "timestamp" }).notNull(),
  organizationId: text("organization_id").notNull().default("default"),
});

// Session recordings table - stores terminal I/O for playback
export const recordings = sqliteTable("recordings", {
  id: text("id").primaryKey(),
  sessionId: text("session_id").notNull(),
  serverId: text("server_id").notNull(),
  serverName: text("server_name").notNull(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  sshUser: text("ssh_user").notNull(),
  startedAt: integer("started_at", { mode: "timestamp" }).notNull(),
  endedAt: integer("ended_at", { mode: "timestamp" }),
  duration: integer("duration"), // Duration in seconds
  terminalWidth: integer("terminal_width").notNull().default(80),
  terminalHeight: integer("terminal_height").notNull().default(24),
  // Recording data in asciicast v2 format (JSON lines)
  data: text("data").notNull().default(""),
  // Searchable text content (all output concatenated)
  textContent: text("text_content").notNull().default(""),
  fileSize: integer("file_size").notNull().default(0), // Size in bytes
  organizationId: text("organization_id").notNull().default("default"),
});

// Subscription tier definitions
export const subscriptionTiers = {
  free: { name: 'Free', maxUsers: 5, maxServers: 2 },
  pro: { name: 'Pro', maxUsers: 25, maxServers: 10 },
  enterprise: { name: 'Enterprise', maxUsers: -1, maxServers: -1 }, // -1 = unlimited
} as const;

export type SubscriptionTier = keyof typeof subscriptionTiers;
export type SubscriptionStatus = 'active' | 'canceled' | 'past_due' | 'trialing';

// Organization subscription table
export const subscriptions = sqliteTable("subscriptions", {
  id: text("id").primaryKey(),
  tier: text("tier").notNull().default("free"),
  stripeCustomerId: text("stripe_customer_id"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  stripePriceId: text("stripe_price_id"),
  status: text("status").notNull().default("active"),
  currentPeriodEnd: integer("current_period_end"),
  cancelAtPeriodEnd: integer("cancel_at_period_end", { mode: "boolean" }).default(false),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at"),
  organizationId: text("organization_id").notNull().default("default"),
});

// Billing history table
export const billingHistory = sqliteTable("billing_history", {
  id: text("id").primaryKey(),
  subscriptionId: text("subscription_id").notNull(),
  stripeInvoiceId: text("stripe_invoice_id"),
  amount: integer("amount").notNull(), // cents
  currency: text("currency").notNull().default("usd"),
  status: text("status").notNull(), // paid, open, void
  invoicePdf: text("invoice_pdf"),
  description: text("description"),
  createdAt: integer("created_at").notNull(),
  organizationId: text("organization_id").notNull().default("default"),
});

export const insertUserSchema = createInsertSchema(users).omit({ id: true });
export const insertServerSchema = createInsertSchema(servers).omit({ id: true });
export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true, startedAt: true, endedAt: true });
export const insertSubscriptionSchema = createInsertSchema(subscriptions).omit({ id: true, createdAt: true, updatedAt: true });
export const insertBillingHistorySchema = createInsertSchema(billingHistory).omit({ id: true, createdAt: true });
export const insertBridgeSchema = createInsertSchema(bridges).omit({ id: true, createdAt: true });
export const insertOrganizationSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true, updatedAt: true });
export const insertOrganizationUserSchema = createInsertSchema(organizationUsers).omit({ id: true, joinedAt: true });

export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertServer = z.infer<typeof insertServerSchema>;
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type InsertSubscription = z.infer<typeof insertSubscriptionSchema>;
export type InsertBillingHistory = z.infer<typeof insertBillingHistorySchema>;
export type InsertBridge = z.infer<typeof insertBridgeSchema>;
export type InsertOrganization = z.infer<typeof insertOrganizationSchema>;
export type InsertOrganizationUser = z.infer<typeof insertOrganizationUserSchema>;

export type User = typeof users.$inferSelect;
export type Server = typeof servers.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type FileOperation = typeof fileOperations.$inferSelect;
export type Subscription = typeof subscriptions.$inferSelect;
export type BillingHistory = typeof billingHistory.$inferSelect;
export type Bridge = typeof bridges.$inferSelect;
export type Organization = typeof organizations.$inferSelect;
export type OrganizationUser = typeof organizationUsers.$inferSelect;

// File operation types for API
export type FileOperationType = "upload" | "download" | "delete" | "mkdir" | "rename" | "chmod";
export type FileOperationMode = "sftp" | "scp";
export type FileOperationStatus = "success" | "error";

// Over-limit status for resources
export interface OverLimitStatus {
  users: {
    isOverLimit: boolean;
    enabled: number;
    total: number;
    limit: number;
    overBy: number;
  };
  servers: {
    isOverLimit: boolean;
    enabled: number;
    total: number;
    limit: number;
    overBy: number;
  };
}

// License info response for API
export interface LicenseInfo {
  subscription: Subscription | null;
  usage: { users: number; servers: number };
  limits: { maxUsers: number; maxServers: number };
  tier: SubscriptionTier;
  tierName: string;
  overLimit?: OverLimitStatus;
}

// Limit check response
export interface LimitCheck {
  allowed: boolean;
  current: number;
  limit: number;
  tier: SubscriptionTier;
  tierName: string;
}

export type UserRole = "user" | "admin";
export type OrgRole = "global-admin" | "org-admin" | "user";

export interface OIDCUser {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  allowedServers: string[];
  organizationId: string;
  orgRole: OrgRole;
}

export interface AuthState {
  user: OIDCUser | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  organizationId: string | null;
  orgRole: OrgRole | null;
}

export type ServerStatus = "online" | "offline" | "unknown";

export interface ServerWithAccess extends Server {
  allowedSshUsers: string[];
  status: ServerStatus;  // Actual health status from health check
}

export interface ActiveSession extends Session {
  serverName: string;
  serverHost: string;
}

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error";

// Admin User type (TideCloak Admin API shape)
export interface AdminUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  username?: string;
  role: string[];  // Array of role names
  linked: boolean; // Tide account link status
  enabled: boolean; // Whether the user account is enabled
  isAdmin: boolean; // Whether the user is an administrator
}

// Admin User Update type
export interface AdminUserUpdate extends AdminUser {
  rolesToAdd?: string[];
  rolesToRemove?: string[];
}

// Admin Role type (TideCloak Admin API shape)
export interface AdminRole {
  id: string;
  name: string;
  description?: string;
  clientRole?: boolean;
  clientId?: string;
}

// Policy Template parameter definition
export interface TemplateParameter {
  name: string;
  type: "string" | "number" | "boolean" | "select";
  helpText: string;
  required: boolean;
  defaultValue?: string | number | boolean;
  options?: string[];  // For "select" type
}

// Policy Template entity
export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  csCode: string;
  parameters: TemplateParameter[];
  createdBy: string;
  createdAt: number;
  updatedAt?: number;
}

export interface InsertPolicyTemplate {
  name: string;
  description: string;
  csCode: string;
  parameters: TemplateParameter[];
  createdBy: string;
}
