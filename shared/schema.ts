import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull(),
  role: text("role").notNull().default("user"),
  allowedServers: text("allowed_servers", { mode: "json" }).$type<string[]>().notNull().default([]),
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
  healthCheckUrl: text("health_check_url"),  // Optional health API endpoint
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
});

export const insertUserSchema = createInsertSchema(users).omit({ id: true });
export const insertServerSchema = createInsertSchema(servers).omit({ id: true });
export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true, startedAt: true, endedAt: true });
export const insertSubscriptionSchema = createInsertSchema(subscriptions).omit({ id: true, createdAt: true, updatedAt: true });
export const insertBillingHistorySchema = createInsertSchema(billingHistory).omit({ id: true, createdAt: true });

export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertServer = z.infer<typeof insertServerSchema>;
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type InsertSubscription = z.infer<typeof insertSubscriptionSchema>;
export type InsertBillingHistory = z.infer<typeof insertBillingHistorySchema>;

export type User = typeof users.$inferSelect;
export type Server = typeof servers.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type Subscription = typeof subscriptions.$inferSelect;
export type BillingHistory = typeof billingHistory.$inferSelect;

// License info response for API
export interface LicenseInfo {
  subscription: Subscription | null;
  usage: { users: number; servers: number };
  limits: { maxUsers: number; maxServers: number };
  tier: SubscriptionTier;
  tierName: string;
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

export interface OIDCUser {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  allowedServers: string[];
}

export interface AuthState {
  user: OIDCUser | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
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
