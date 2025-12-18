import { pgTable, text, varchar, boolean, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull(),
  role: text("role").notNull().default("user"),
  allowedServers: text("allowed_servers").array().notNull().default([]),
});

export const servers = pgTable("servers", {
  id: varchar("id").primaryKey(),
  name: text("name").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(22),
  environment: text("environment").notNull().default("production"),
  tags: text("tags").array().notNull().default([]),
  enabled: boolean("enabled").notNull().default(true),
  sshUsers: text("ssh_users").array().notNull().default([]),
});

export const sessions = pgTable("sessions", {
  id: varchar("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  serverId: varchar("server_id").notNull(),
  sshUser: text("ssh_user").notNull(),
  status: text("status").notNull().default("active"),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  endedAt: timestamp("ended_at"),
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

export interface ServerWithAccess extends Server {
  allowedSshUsers: string[];
}

export interface ActiveSession extends Session {
  serverName: string;
  serverHost: string;
}

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error";
