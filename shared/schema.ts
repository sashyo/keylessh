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

export const insertUserSchema = createInsertSchema(users).omit({ id: true });
export const insertServerSchema = createInsertSchema(servers).omit({ id: true });
export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true, startedAt: true, endedAt: true });

export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertServer = z.infer<typeof insertServerSchema>;
export type InsertSession = z.infer<typeof insertSessionSchema>;

export type User = typeof users.$inferSelect;
export type Server = typeof servers.$inferSelect;
export type Session = typeof sessions.$inferSelect;

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
