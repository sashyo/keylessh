import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import { eq, desc, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";
import { mkdirSync, existsSync } from "fs";
import { dirname } from "path";
import {
  users,
  servers,
  sessions,
  subscriptions,
  billingHistory,
  subscriptionTiers,
  type User,
  type InsertUser,
  type Server,
  type InsertServer,
  type Session,
  type InsertSession,
  type PolicyTemplate,
  type InsertPolicyTemplate,
  type TemplateParameter,
  type Subscription,
  type InsertSubscription,
  type BillingHistory,
  type InsertBillingHistory,
  type SubscriptionTier,
  type LicenseInfo,
  type LimitCheck,
} from "@shared/schema";
import { getAdminPolicy } from "./lib/tidecloakApi";
import { createRequire } from "module";
import { fileURLToPath } from "url";

// Use createRequire for heimdall-tide (CJS module with broken ESM exports)
const require = createRequire(import.meta.url || fileURLToPath(new URL(".", import.meta.url)));
const { PolicySignRequest } = require("heimdall-tide");

// Base64 conversion helpers for Tide request handling
function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getUsers(): Promise<User[]>;
  updateUser(id: string, data: Partial<User>): Promise<User | undefined>;

  getServers(): Promise<Server[]>;
  getServer(id: string): Promise<Server | undefined>;
  getServersByIds(ids: string[]): Promise<Server[]>;
  createServer(server: InsertServer): Promise<Server>;
  updateServer(id: string, data: Partial<Server>): Promise<Server | undefined>;
  deleteServer(id: string): Promise<boolean>;

  getSessions(): Promise<Session[]>;
  getSession(id: string): Promise<Session | undefined>;
  getSessionsByUserId(userId: string): Promise<Session[]>;
  createSession(session: InsertSession): Promise<Session>;
  updateSession(id: string, data: Partial<Session>): Promise<Session | undefined>;
  endSession(id: string): Promise<boolean>;
}

// Database path
const DB_PATH = process.env.DATABASE_URL || "./data/keylessh.db";

// Ensure data directory exists
const dbDir = dirname(DB_PATH);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

// Initialize SQLite database
const sqlite = new Database(DB_PATH);
sqlite.pragma("journal_mode = WAL");

// Initialize Drizzle
const db = drizzle(sqlite);

// Create tables if they don't exist
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    allowed_servers TEXT NOT NULL DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    environment TEXT NOT NULL DEFAULT 'production',
    tags TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    ssh_users TEXT NOT NULL DEFAULT '[]',
    health_check_url TEXT
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_username TEXT,
    user_email TEXT,
    server_id TEXT NOT NULL,
    ssh_user TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    started_at INTEGER NOT NULL,
    ended_at INTEGER
  );

  -- Approval tables
  CREATE TABLE IF NOT EXISTS pending_approvals (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK(type IN ('user_create', 'user_update', 'user_delete', 'role_assign', 'role_remove')),
    requested_by TEXT NOT NULL,
    target_user_id TEXT,
    target_user_email TEXT,
    data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'committed', 'cancelled')),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS approval_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL,
    user_vuid TEXT NOT NULL,
    user_email TEXT NOT NULL,
    decision INTEGER NOT NULL CHECK(decision IN (0, 1)),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (approval_id) REFERENCES pending_approvals(id) ON DELETE CASCADE,
    UNIQUE(approval_id, user_vuid)
  );

  CREATE TABLE IF NOT EXISTS access_change_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    type TEXT NOT NULL CHECK(type IN ('created', 'approved', 'denied', 'deleted', 'committed', 'cancelled')),
    approval_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    target_user TEXT,
    details TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_access_change_logs_timestamp ON access_change_logs(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_access_change_logs_approval_id ON access_change_logs(approval_id);

  -- SSH signing policies for roles (committed policies)
  CREATE TABLE IF NOT EXISTS ssh_policies (
    role_id TEXT PRIMARY KEY,
    contract_type TEXT NOT NULL,
    approval_type TEXT NOT NULL CHECK(approval_type IN ('implicit', 'explicit')),
    execution_type TEXT NOT NULL CHECK(execution_type IN ('public', 'private')),
    threshold INTEGER NOT NULL DEFAULT 1,
    policy_data TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER
  );

  -- Pending SSH policy requests (awaiting approval)
  CREATE TABLE IF NOT EXISTS pending_ssh_policies (
    id TEXT PRIMARY KEY,
    role_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_by_email TEXT,
    policy_request_data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'committed', 'cancelled')),
    threshold INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER
  );

  -- SSH policy approval decisions
  CREATE TABLE IF NOT EXISTS ssh_policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_request_id TEXT NOT NULL,
    user_vuid TEXT NOT NULL,
    user_email TEXT NOT NULL,
    decision INTEGER NOT NULL CHECK(decision IN (0, 1)),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(policy_request_id, user_vuid)
  );

  -- SSH policy change logs
  CREATE TABLE IF NOT EXISTS ssh_policy_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    type TEXT NOT NULL CHECK(type IN ('created', 'approved', 'denied', 'committed', 'cancelled')),
    policy_request_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    role_id TEXT,
    details TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ssh_policy_logs_timestamp ON ssh_policy_logs(timestamp DESC);

  -- Policy templates for reusable Forseti contracts
  CREATE TABLE IF NOT EXISTS policy_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    cs_code TEXT NOT NULL,
    parameters TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER
  );

  -- Subscription table for license management
  CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    stripe_price_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    current_period_end INTEGER,
    cancel_at_period_end INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER
  );

  -- Billing history table
  CREATE TABLE IF NOT EXISTS billing_history (
    id TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    stripe_invoice_id TEXT,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'usd',
    status TEXT NOT NULL,
    invoice_pdf TEXT,
    description TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_billing_history_subscription ON billing_history(subscription_id);
  CREATE INDEX IF NOT EXISTS idx_billing_history_created ON billing_history(created_at DESC);
`);

// Lightweight migrations for existing DBs (CREATE TABLE IF NOT EXISTS doesn't alter).
try {
  const serverColumns = sqlite
    .prepare(`PRAGMA table_info(servers)`)
    .all() as Array<{ name: string }>;
  const hasHealthCheckUrl = serverColumns.some((c) => c.name === "health_check_url");
  if (!hasHealthCheckUrl) {
    sqlite.prepare(`ALTER TABLE servers ADD COLUMN health_check_url TEXT`).run();
  }
} catch {
  // Ignore migration errors; queries will surface issues.
}

try {
  const sessionColumns = sqlite
    .prepare(`PRAGMA table_info(sessions)`)
    .all() as Array<{ name: string }>;
  const hasUserUsername = sessionColumns.some((c) => c.name === "user_username");
  const hasUserEmail = sessionColumns.some((c) => c.name === "user_email");
  if (!hasUserUsername) {
    sqlite.prepare(`ALTER TABLE sessions ADD COLUMN user_username TEXT`).run();
  }
  if (!hasUserEmail) {
    sqlite.prepare(`ALTER TABLE sessions ADD COLUMN user_email TEXT`).run();
  }
} catch {
  // Ignore migration errors; queries will surface issues.
}

// Migration: Add policy_data column to ssh_policies for storing committed policy bytes
try {
  const policyColumns = sqlite
    .prepare(`PRAGMA table_info(ssh_policies)`)
    .all() as Array<{ name: string }>;
  const hasPolicyData = policyColumns.some((c) => c.name === "policy_data");
  if (!hasPolicyData) {
    sqlite.prepare(`ALTER TABLE ssh_policies ADD COLUMN policy_data TEXT`).run();
  }
} catch {
  // Ignore migration errors; queries will surface issues.
}

export class SQLiteStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const result = db.select().from(users).where(eq(users.id, id)).get();
    return result;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const result = db.select().from(users).where(eq(users.username, username)).get();
    return result;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = {
      id,
      username: insertUser.username,
      email: insertUser.email,
      role: insertUser.role ?? "user",
      allowedServers: (insertUser.allowedServers ?? []) as string[],
    };
    db.insert(users).values(user).run();
    return user;
  }

  async getUsers(): Promise<User[]> {
    return db.select().from(users).all();
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const existing = await this.getUser(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    db.update(users).set(updated).where(eq(users.id, id)).run();
    return updated;
  }

  async getServers(): Promise<Server[]> {
    return db.select().from(servers).all();
  }

  async getServer(id: string): Promise<Server | undefined> {
    const result = db.select().from(servers).where(eq(servers.id, id)).get();
    return result;
  }

  async getServersByIds(ids: string[]): Promise<Server[]> {
    if (ids.length === 0) return [];
    return db.select().from(servers).where(inArray(servers.id, ids)).all();
  }

  async createServer(insertServer: InsertServer): Promise<Server> {
    const id = randomUUID();
    const server: Server = {
      id,
      name: insertServer.name,
      host: insertServer.host,
      port: insertServer.port ?? 22,
      environment: insertServer.environment ?? "production",
      tags: (insertServer.tags ?? []) as string[],
      enabled: insertServer.enabled ?? true,
      sshUsers: (insertServer.sshUsers ?? []) as string[],
      healthCheckUrl: insertServer.healthCheckUrl ?? null,
    };
    db.insert(servers).values(server).run();
    return server;
  }

  async updateServer(id: string, data: Partial<Server>): Promise<Server | undefined> {
    const existing = await this.getServer(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    db.update(servers).set(updated).where(eq(servers.id, id)).run();
    return updated;
  }

  async deleteServer(id: string): Promise<boolean> {
    const result = db.delete(servers).where(eq(servers.id, id)).run();
    return result.changes > 0;
  }

  async getSessions(): Promise<Session[]> {
    return db.select().from(sessions).orderBy(desc(sessions.startedAt)).all();
  }

  async getSession(id: string): Promise<Session | undefined> {
    const result = db.select().from(sessions).where(eq(sessions.id, id)).get();
    return result;
  }

  async getSessionsByUserId(userId: string): Promise<Session[]> {
    return db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId))
      .orderBy(desc(sessions.startedAt))
      .all();
  }

  async createSession(insertSession: InsertSession): Promise<Session> {
    const id = randomUUID();
    const session: Session = {
      id,
      userId: insertSession.userId,
      userUsername: insertSession.userUsername ?? null,
      userEmail: insertSession.userEmail ?? null,
      serverId: insertSession.serverId,
      sshUser: insertSession.sshUser,
      status: insertSession.status ?? "active",
      startedAt: new Date(),
      endedAt: null,
    };
    db.insert(sessions).values(session).run();
    return session;
  }

  async updateSession(id: string, data: Partial<Session>): Promise<Session | undefined> {
    const existing = await this.getSession(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    db.update(sessions).set(updated).where(eq(sessions.id, id)).run();
    return updated;
  }

  async endSession(id: string): Promise<boolean> {
    const result = db
      .update(sessions)
      .set({ status: "completed", endedAt: new Date() })
      .where(eq(sessions.id, id))
      .run();
    return result.changes > 0;
  }
}

// Approval types
export type ApprovalType = 'user_create' | 'user_update' | 'user_delete' | 'role_assign' | 'role_remove';
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'committed' | 'cancelled';

export interface PendingApproval {
  id: string;
  type: ApprovalType;
  requestedBy: string;
  targetUserId?: string;
  targetUserEmail?: string;
  data: string;
  status: ApprovalStatus;
  createdAt: number;
  updatedAt?: number;
  approvedBy?: string[];
  deniedBy?: string[];
}

export interface ApprovalDecision {
  id: number;
  approvalId: string;
  userVuid: string;
  userEmail: string;
  decision: number; // 0 = denied, 1 = approved
  createdAt: number;
}

export interface AccessChangeLog {
  id: number;
  timestamp: number;
  type: string;
  approvalId: string;
  userEmail: string;
  targetUser?: string;
  details?: string;
}

// Approval storage class
export class ApprovalStorage {
  // Get all pending approvals with their decisions
  async getPendingApprovals(): Promise<PendingApproval[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM pending_approvals WHERE status = 'pending' ORDER BY created_at DESC
    `).all() as any[];

    return Promise.all(rows.map(async (row) => {
      const approvers = sqlite.prepare(`
        SELECT user_vuid FROM approval_decisions WHERE approval_id = ? AND decision = 1
      `).all(row.id) as { user_vuid: string }[];

      const deniers = sqlite.prepare(`
        SELECT user_vuid FROM approval_decisions WHERE approval_id = ? AND decision = 0
      `).all(row.id) as { user_vuid: string }[];

      return {
        id: row.id,
        type: row.type as ApprovalType,
        requestedBy: row.requested_by,
        targetUserId: row.target_user_id,
        targetUserEmail: row.target_user_email,
        data: row.data,
        status: row.status as ApprovalStatus,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        approvedBy: approvers.map(a => a.user_vuid),
        deniedBy: deniers.map(d => d.user_vuid),
      };
    }));
  }

  // Create a new approval request
  async createApproval(
    type: ApprovalType,
    requestedBy: string,
    data: any,
    targetUserId?: string,
    targetUserEmail?: string
  ): Promise<string> {
    const id = randomUUID();
    sqlite.prepare(`
      INSERT INTO pending_approvals (id, type, requested_by, target_user_id, target_user_email, data, status)
      VALUES (?, ?, ?, ?, ?, ?, 'pending')
    `).run(id, type, requestedBy, targetUserId, targetUserEmail, JSON.stringify(data));

    // Log the creation
    await this.addAccessChangeLog('created', id, requestedBy, targetUserEmail, JSON.stringify(data));

    return id;
  }

  // Add a decision (approval or denial) to an approval request
  async addDecision(
    approvalId: string,
    userVuid: string,
    userEmail: string,
    approved: boolean
  ): Promise<boolean> {
    try {
      sqlite.prepare(`
        INSERT INTO approval_decisions (approval_id, user_vuid, user_email, decision)
        VALUES (?, ?, ?, ?)
      `).run(approvalId, userVuid, userEmail, approved ? 1 : 0);

      // Log the decision
      await this.addAccessChangeLog(
        approved ? 'approved' : 'denied',
        approvalId,
        userEmail,
        undefined,
        undefined
      );

      return true;
    } catch (error) {
      // Unique constraint violation means user already voted
      console.error('Error adding decision:', error);
      return false;
    }
  }

  // Remove a decision (for changing vote)
  async removeDecision(approvalId: string, userVuid: string): Promise<boolean> {
    const result = sqlite.prepare(`
      DELETE FROM approval_decisions WHERE approval_id = ? AND user_vuid = ?
    `).run(approvalId, userVuid);
    return result.changes > 0;
  }

  // Commit an approval (mark as committed)
  async commitApproval(id: string, userEmail: string): Promise<boolean> {
    const result = sqlite.prepare(`
      UPDATE pending_approvals SET status = 'committed', updated_at = strftime('%s', 'now')
      WHERE id = ? AND status = 'pending'
    `).run(id);

    if (result.changes > 0) {
      await this.addAccessChangeLog('committed', id, userEmail);
    }

    return result.changes > 0;
  }

  // Cancel an approval request
  async cancelApproval(id: string, userEmail: string): Promise<boolean> {
    const result = sqlite.prepare(`
      UPDATE pending_approvals SET status = 'cancelled', updated_at = strftime('%s', 'now')
      WHERE id = ? AND status = 'pending'
    `).run(id);

    if (result.changes > 0) {
      await this.addAccessChangeLog('cancelled', id, userEmail);
    }

    return result.changes > 0;
  }

  // Delete an approval request
  async deleteApproval(id: string, userEmail: string): Promise<boolean> {
    // First get the approval to log target user
    const approval = sqlite.prepare(`
      SELECT target_user_email FROM pending_approvals WHERE id = ?
    `).get(id) as { target_user_email?: string } | undefined;

    const result = sqlite.prepare(`
      DELETE FROM pending_approvals WHERE id = ?
    `).run(id);

    if (result.changes > 0) {
      await this.addAccessChangeLog('deleted', id, userEmail, approval?.target_user_email);
    }

    return result.changes > 0;
  }

  // Get approval by ID
  async getApproval(id: string): Promise<PendingApproval | undefined> {
    const row = sqlite.prepare(`
      SELECT * FROM pending_approvals WHERE id = ?
    `).get(id) as any | undefined;

    if (!row) return undefined;

    const approvers = sqlite.prepare(`
      SELECT user_vuid FROM approval_decisions WHERE approval_id = ? AND decision = 1
    `).all(id) as { user_vuid: string }[];

    const deniers = sqlite.prepare(`
      SELECT user_vuid FROM approval_decisions WHERE approval_id = ? AND decision = 0
    `).all(id) as { user_vuid: string }[];

    return {
      id: row.id,
      type: row.type as ApprovalType,
      requestedBy: row.requested_by,
      targetUserId: row.target_user_id,
      targetUserEmail: row.target_user_email,
      data: row.data,
      status: row.status as ApprovalStatus,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      approvedBy: approvers.map(a => a.user_vuid),
      deniedBy: deniers.map(d => d.user_vuid),
    };
  }

  // Add access change log entry
  async addAccessChangeLog(
    type: string,
    approvalId: string,
    userEmail: string,
    targetUser?: string,
    details?: string
  ): Promise<void> {
    sqlite.prepare(`
      INSERT INTO access_change_logs (type, approval_id, user_email, target_user, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(type, approvalId, userEmail, targetUser, details);
  }

  // Get access change logs
  async getAccessChangeLogs(limit: number = 100, offset: number = 0): Promise<AccessChangeLog[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM access_change_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?
    `).all(limit, offset) as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      type: row.type,
      approvalId: row.approval_id,
      userEmail: row.user_email,
      targetUser: row.target_user,
      details: row.details,
    }));
  }
}

// SSH Policy types
export interface SshPolicy {
  roleId: string;
  contractType: string;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
  policyData?: string; // Base64 encoded committed policy bytes
  createdAt: number;
  updatedAt?: number;
}

export interface InsertSshPolicy {
  roleId: string;
  contractType: string;
  approvalType: "implicit" | "explicit";
  executionType: "public" | "private";
  threshold: number;
  policyData?: string; // Base64 encoded committed policy bytes
}

// SSH Policy storage class
export class PolicyStorage {
  // Create or update a policy for a role
  async upsertPolicy(policy: InsertSshPolicy): Promise<SshPolicy> {
    const existing = await this.getPolicy(policy.roleId);

    if (existing) {
      sqlite.prepare(`
        UPDATE ssh_policies
        SET contract_type = ?, approval_type = ?, execution_type = ?, threshold = ?, policy_data = ?, updated_at = strftime('%s', 'now')
        WHERE role_id = ?
      `).run(policy.contractType, policy.approvalType, policy.executionType, policy.threshold, policy.policyData || null, policy.roleId);

      return {
        ...policy,
        createdAt: existing.createdAt,
        updatedAt: Math.floor(Date.now() / 1000),
      };
    } else {
      sqlite.prepare(`
        INSERT INTO ssh_policies (role_id, contract_type, approval_type, execution_type, threshold, policy_data)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(policy.roleId, policy.contractType, policy.approvalType, policy.executionType, policy.threshold, policy.policyData || null);

      return {
        ...policy,
        createdAt: Math.floor(Date.now() / 1000),
      };
    }
  }

  // Get policy by role ID
  async getPolicy(roleId: string): Promise<SshPolicy | undefined> {
    const row = sqlite.prepare(`
      SELECT * FROM ssh_policies WHERE role_id = ?
    `).get(roleId) as any | undefined;

    if (!row) return undefined;

    return {
      roleId: row.role_id,
      contractType: row.contract_type,
      approvalType: row.approval_type as "implicit" | "explicit",
      executionType: row.execution_type as "public" | "private",
      threshold: row.threshold,
      policyData: row.policy_data || undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // Get all policies
  async getAllPolicies(): Promise<SshPolicy[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM ssh_policies ORDER BY created_at DESC
    `).all() as any[];

    return rows.map(row => ({
      roleId: row.role_id,
      contractType: row.contract_type,
      approvalType: row.approval_type as "implicit" | "explicit",
      executionType: row.execution_type as "public" | "private",
      threshold: row.threshold,
      policyData: row.policy_data || undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  // Delete policy by role ID
  async deletePolicy(roleId: string): Promise<boolean> {
    const result = sqlite.prepare(`
      DELETE FROM ssh_policies WHERE role_id = ?
    `).run(roleId);
    return result.changes > 0;
  }
}

// Pending SSH Policy types
export interface PendingSshPolicy {
  id: string;
  roleId: string;
  requestedBy: string;
  requestedByEmail?: string;
  policyRequestData: string;
  status: "pending" | "approved" | "committed" | "cancelled";
  threshold: number;
  createdAt: number;
  updatedAt?: number;
  approvalCount?: number;
  rejectionCount?: number;
  approvedBy?: string[];
  deniedBy?: string[];
  commitReady?: boolean;
}

export interface InsertPendingSshPolicy {
  id: string;
  roleId: string;
  requestedBy: string;
  requestedByEmail?: string;
  policyRequestData: string;
  threshold?: number;
}

export interface SshPolicyDecision {
  policyRequestId: string;
  userVuid: string;
  userEmail: string;
  decision: 0 | 1; // 0 = reject, 1 = approve
  createdAt: number;
}

// Pending SSH Policy storage class
export class PendingPolicyStorage {
  // Create a new pending policy request
  async createPendingPolicy(policy: InsertPendingSshPolicy): Promise<PendingSshPolicy> {
    sqlite.prepare(`
      INSERT INTO pending_ssh_policies (id, role_id, requested_by, requested_by_email, policy_request_data, threshold)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(policy.id, policy.roleId, policy.requestedBy, policy.requestedByEmail || null, policy.policyRequestData, policy.threshold || 1);

    // Log the creation
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, details)
      VALUES ('created', ?, ?, ?, ?)
    `).run(policy.id, policy.requestedByEmail || policy.requestedBy, policy.roleId, JSON.stringify({ threshold: policy.threshold || 1 }));

    return {
      ...policy,
      status: "pending",
      threshold: policy.threshold || 1,
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  // Get pending policy by ID
  async getPendingPolicy(id: string): Promise<PendingSshPolicy | undefined> {
    const row = sqlite.prepare(`
      SELECT p.*,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approval_count,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as rejection_count
      FROM pending_ssh_policies p WHERE p.id = ?
    `).get(id) as any | undefined;

    if (!row) return undefined;

    return {
      id: row.id,
      roleId: row.role_id,
      requestedBy: row.requested_by,
      requestedByEmail: row.requested_by_email,
      policyRequestData: row.policy_request_data,
      status: row.status as "pending" | "approved" | "committed" | "cancelled",
      threshold: row.threshold,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      approvalCount: row.approval_count,
      rejectionCount: row.rejection_count,
    };
  }

  // Get all pending policies (not yet committed or cancelled)
  // For commit-ready policies, adds the admin policy to the request (required for Ork commit)
  async getAllPendingPolicies(): Promise<PendingSshPolicy[]> {
    const rows = sqlite.prepare(`
      SELECT p.*,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approval_count,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as rejection_count,
        (SELECT GROUP_CONCAT(user_vuid) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approved_by,
        (SELECT GROUP_CONCAT(user_vuid) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as denied_by
      FROM pending_ssh_policies p
      WHERE p.status IN ('pending', 'approved')
      ORDER BY p.created_at DESC
    `).all() as any[];

    // Fetch admin policy from TideCloak (needed to authorize commits)
    let adminPolicyBytes: Uint8Array | null = null;
    try {
      const adminPolicyBase64 = await getAdminPolicy();
      adminPolicyBytes = base64ToBytes(adminPolicyBase64);
    } catch (error) {
      console.error("Failed to fetch admin policy:", error);
      // Continue without admin policy - commits will fail but approvals still work
    }

    const policies = await Promise.all(rows.map(async row => {
      const isCommitReady = (row.approval_count || 0) >= row.threshold;
      let policyRequestData = row.policy_request_data;

      // If commit-ready and we have admin policy, add it to the request
      if (isCommitReady && adminPolicyBytes) {
        try {
          const request = PolicySignRequest.decode(base64ToBytes(policyRequestData));
          // Add the admin policy to authorize the commit
          request.addPolicy(adminPolicyBytes);
          const updatedData = bytesToBase64(request.encode());

          // Update the request in the database with admin policy attached
          sqlite.prepare(`
            UPDATE pending_ssh_policies SET policy_request_data = ? WHERE id = ?
          `).run(updatedData, row.id);

          policyRequestData = updatedData;
        } catch (error) {
          console.error(`Failed to add admin policy to request ${row.id}:`, error);
        }
      }

      return {
        id: row.id,
        roleId: row.role_id,
        requestedBy: row.requested_by,
        requestedByEmail: row.requested_by_email,
        policyRequestData,
        status: row.status as "pending" | "approved" | "committed" | "cancelled",
        threshold: row.threshold,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        approvalCount: row.approval_count || 0,
        rejectionCount: row.rejection_count || 0,
        approvedBy: row.approved_by ? row.approved_by.split(',') : [],
        deniedBy: row.denied_by ? row.denied_by.split(',') : [],
        commitReady: isCommitReady,
      };
    }));

    return policies;
  }

  // Add approval/rejection decision
  async addDecision(decision: Omit<SshPolicyDecision, "createdAt">): Promise<void> {
    // Insert or update decision
    sqlite.prepare(`
      INSERT INTO ssh_policy_decisions (policy_request_id, user_vuid, user_email, decision)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(policy_request_id, user_vuid) DO UPDATE SET decision = excluded.decision, created_at = strftime('%s', 'now')
    `).run(decision.policyRequestId, decision.userVuid, decision.userEmail, decision.decision);

    // Log the decision
    const logType = decision.decision === 1 ? "approved" : "denied";
    const policy = await this.getPendingPolicy(decision.policyRequestId);
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id)
      VALUES (?, ?, ?, ?)
    `).run(logType, decision.policyRequestId, decision.userEmail, policy?.roleId || null);

    // Check if threshold is met
    if (policy && policy.approvalCount && policy.approvalCount + 1 >= policy.threshold) {
      await this.updateStatus(decision.policyRequestId, "approved");
    }
  }

  // Update policy status
  async updateStatus(id: string, status: "pending" | "approved" | "committed" | "cancelled"): Promise<void> {
    sqlite.prepare(`
      UPDATE pending_ssh_policies SET status = ?, updated_at = strftime('%s', 'now') WHERE id = ?
    `).run(status, id);
  }

  // Get decisions for a policy
  async getDecisions(policyRequestId: string): Promise<SshPolicyDecision[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM ssh_policy_decisions WHERE policy_request_id = ? ORDER BY created_at DESC
    `).all(policyRequestId) as any[];

    return rows.map(row => ({
      policyRequestId: row.policy_request_id,
      userVuid: row.user_vuid,
      userEmail: row.user_email,
      decision: row.decision as 0 | 1,
      createdAt: row.created_at,
    }));
  }

  // Check if user has already voted
  async hasUserVoted(policyRequestId: string, userVuid: string): Promise<boolean> {
    const row = sqlite.prepare(`
      SELECT 1 FROM ssh_policy_decisions WHERE policy_request_id = ? AND user_vuid = ?
    `).get(policyRequestId, userVuid);
    return !!row;
  }

  // Get user's decision (returns 1 for approval, 0 for rejection, null if no decision)
  async getUserDecision(policyRequestId: string, userVuid: string): Promise<number | null> {
    const row = sqlite.prepare(`
      SELECT decision FROM ssh_policy_decisions WHERE policy_request_id = ? AND user_vuid = ?
    `).get(policyRequestId, userVuid) as { decision: number } | undefined;
    return row ? row.decision : null;
  }

  // Update the policy request data (used to store signed/approved request)
  async updatePolicyRequest(id: string, policyRequestData: string): Promise<void> {
    sqlite.prepare(`
      UPDATE pending_ssh_policies SET policy_request_data = ? WHERE id = ?
    `).run(policyRequestData, id);
  }

  // Revoke a user's decision (remove their vote) - matches ideed-swarm's RemovePolicyApproval
  async revokeDecision(policyRequestId: string, userVuid: string): Promise<boolean> {
    const result = sqlite.prepare(`
      DELETE FROM ssh_policy_decisions WHERE policy_request_id = ? AND user_vuid = ?
    `).run(policyRequestId, userVuid);
    return result.changes > 0;
  }

  // Commit a policy (after approval threshold is met)
  async commitPolicy(id: string, userEmail: string): Promise<void> {
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");
    if (policy.status !== "approved") throw new Error("Policy not approved yet");

    await this.updateStatus(id, "committed");

    // Log the commit
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id)
      VALUES ('committed', ?, ?, ?)
    `).run(id, userEmail, policy.roleId);
  }

  // Cancel a pending policy
  async cancelPolicy(id: string, userEmail: string): Promise<void> {
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");

    await this.updateStatus(id, "cancelled");

    // Log the cancellation
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id)
      VALUES ('cancelled', ?, ?, ?)
    `).run(id, userEmail, policy.roleId);
  }

  // Get policy logs
  async getLogs(limit: number = 100): Promise<any[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM ssh_policy_logs ORDER BY timestamp DESC LIMIT ?
    `).all(limit) as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      type: row.type,
      policyRequestId: row.policy_request_id,
      userEmail: row.user_email,
      roleId: row.role_id,
      details: row.details,
    }));
  }
}

// Policy Template storage class
export class TemplateStorage {
  // Create a new template
  async createTemplate(template: InsertPolicyTemplate): Promise<PolicyTemplate> {
    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    sqlite.prepare(`
      INSERT INTO policy_templates (id, name, description, cs_code, parameters, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, template.name, template.description, template.csCode, JSON.stringify(template.parameters), template.createdBy, now);

    return {
      id,
      name: template.name,
      description: template.description,
      csCode: template.csCode,
      parameters: template.parameters,
      createdBy: template.createdBy,
      createdAt: now,
    };
  }

  // Get template by ID
  async getTemplate(id: string): Promise<PolicyTemplate | undefined> {
    const row = sqlite.prepare(`
      SELECT * FROM policy_templates WHERE id = ?
    `).get(id) as any | undefined;

    if (!row) return undefined;

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      csCode: row.cs_code,
      parameters: JSON.parse(row.parameters || '[]') as TemplateParameter[],
      createdBy: row.created_by,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // Get template by name
  async getTemplateByName(name: string): Promise<PolicyTemplate | undefined> {
    const row = sqlite.prepare(`
      SELECT * FROM policy_templates WHERE name = ?
    `).get(name) as any | undefined;

    if (!row) return undefined;

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      csCode: row.cs_code,
      parameters: JSON.parse(row.parameters || '[]') as TemplateParameter[],
      createdBy: row.created_by,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // Get all templates
  async getAllTemplates(): Promise<PolicyTemplate[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM policy_templates ORDER BY created_at DESC
    `).all() as any[];

    return rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      csCode: row.cs_code,
      parameters: JSON.parse(row.parameters || '[]') as TemplateParameter[],
      createdBy: row.created_by,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  // Update a template
  async updateTemplate(id: string, data: Partial<InsertPolicyTemplate>): Promise<PolicyTemplate | undefined> {
    const existing = await this.getTemplate(id);
    if (!existing) return undefined;

    const updates: string[] = [];
    const values: any[] = [];

    if (data.name !== undefined) {
      updates.push('name = ?');
      values.push(data.name);
    }
    if (data.description !== undefined) {
      updates.push('description = ?');
      values.push(data.description);
    }
    if (data.csCode !== undefined) {
      updates.push('cs_code = ?');
      values.push(data.csCode);
    }
    if (data.parameters !== undefined) {
      updates.push('parameters = ?');
      values.push(JSON.stringify(data.parameters));
    }

    if (updates.length > 0) {
      updates.push('updated_at = ?');
      values.push(Math.floor(Date.now() / 1000));
      values.push(id);

      sqlite.prepare(`
        UPDATE policy_templates SET ${updates.join(', ')} WHERE id = ?
      `).run(...values);
    }

    return this.getTemplate(id);
  }

  // Delete a template
  async deleteTemplate(id: string): Promise<boolean> {
    const result = sqlite.prepare(`
      DELETE FROM policy_templates WHERE id = ?
    `).run(id);
    return result.changes > 0;
  }
}

// Default SSH policy template
const DEFAULT_SSH_TEMPLATE = {
  name: "SSH Access Policy",
  description: "Standard SSH access policy with role-based authorization. Configure approval and execution types for SSH challenge signing.",
  csCode: `using Ork.Forseti.Sdk;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Validates SSH signing requests based on policy parameters.
/// </summary>
public class SshPolicy : IAccessPolicy
{
    public PolicyDecision Authorize(AccessContext ctx)
    {
        var policy = ctx.Policy;
        var doken = ctx.Doken;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        if (doken == null)
            return PolicyDecision.Deny("No doken provided");

        // Get required parameters from policy
        if (!policy.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        // Verify that the user's doken contains the required role for this resource
        if (!doken.Payload.ResourceAccessRoleExists(resource, requiredRole))
            return PolicyDecision.Deny($"User does not have the required role '{requiredRole}' for resource '{resource}'");

        // Get configurable parameters
        var approvalType = "{{APPROVAL_TYPE}}";
        var executionType = "{{EXECUTION_TYPE}}";

        // Log the authorization attempt
        ForsetiSdk.Log($"SSH signing authorized for role '{requiredRole}' (approval: {approvalType}, execution: {executionType})");

        return PolicyDecision.Allow();
    }
}`,
  parameters: [
    {
      name: "APPROVAL_TYPE",
      type: "select" as const,
      helpText: "Determines if user approval is needed before signing. 'implicit' allows automatic signing, 'explicit' requires user confirmation.",
      required: true,
      defaultValue: "implicit",
      options: ["implicit", "explicit"]
    },
    {
      name: "EXECUTION_TYPE",
      type: "select" as const,
      helpText: "Controls who can execute the signing operation. 'private' restricts to role members, 'public' allows broader access.",
      required: true,
      defaultValue: "private",
      options: ["public", "private"]
    }
  ],
  createdBy: "system"
};

// Seed or update default template
try {
  const existingTemplate = sqlite.prepare(`SELECT id, cs_code FROM policy_templates WHERE name = ? AND created_by = 'system'`).get(DEFAULT_SSH_TEMPLATE.name) as { id: string; cs_code: string } | undefined;

  if (!existingTemplate) {
    // Create new default template
    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    sqlite.prepare(`
      INSERT INTO policy_templates (id, name, description, cs_code, parameters, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, DEFAULT_SSH_TEMPLATE.name, DEFAULT_SSH_TEMPLATE.description, DEFAULT_SSH_TEMPLATE.csCode, JSON.stringify(DEFAULT_SSH_TEMPLATE.parameters), DEFAULT_SSH_TEMPLATE.createdBy, now);
  } else if (existingTemplate.cs_code !== DEFAULT_SSH_TEMPLATE.csCode) {
    // Update existing system template if code has changed (e.g., role check was added)
    const now = Math.floor(Date.now() / 1000);
    sqlite.prepare(`
      UPDATE policy_templates SET cs_code = ?, description = ?, parameters = ?, updated_at = ? WHERE id = ?
    `).run(DEFAULT_SSH_TEMPLATE.csCode, DEFAULT_SSH_TEMPLATE.description, JSON.stringify(DEFAULT_SSH_TEMPLATE.parameters), now, existingTemplate.id);
  }
} catch {
  // Ignore seeding errors
}

// Subscription storage class for license management
export class SubscriptionStorage {
  // Get the current subscription (there's only one per installation)
  async getSubscription(): Promise<Subscription | null> {
    const row = sqlite.prepare(`
      SELECT * FROM subscriptions ORDER BY created_at DESC LIMIT 1
    `).get() as any | undefined;

    if (!row) return null;

    return {
      id: row.id,
      tier: row.tier as SubscriptionTier,
      stripeCustomerId: row.stripe_customer_id,
      stripeSubscriptionId: row.stripe_subscription_id,
      stripePriceId: row.stripe_price_id,
      status: row.status,
      currentPeriodEnd: row.current_period_end,
      cancelAtPeriodEnd: !!row.cancel_at_period_end,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // Create or update the subscription
  async upsertSubscription(data: Partial<InsertSubscription> & { tier?: SubscriptionTier }): Promise<Subscription> {
    const existing = await this.getSubscription();
    const now = Math.floor(Date.now() / 1000);

    if (existing) {
      // Update existing subscription
      const updates: string[] = [];
      const values: any[] = [];

      if (data.tier !== undefined) {
        updates.push('tier = ?');
        values.push(data.tier);
      }
      if (data.stripeCustomerId !== undefined) {
        updates.push('stripe_customer_id = ?');
        values.push(data.stripeCustomerId);
      }
      if (data.stripeSubscriptionId !== undefined) {
        updates.push('stripe_subscription_id = ?');
        values.push(data.stripeSubscriptionId);
      }
      if (data.stripePriceId !== undefined) {
        updates.push('stripe_price_id = ?');
        values.push(data.stripePriceId);
      }
      if (data.status !== undefined) {
        updates.push('status = ?');
        values.push(data.status);
      }
      if (data.currentPeriodEnd !== undefined) {
        updates.push('current_period_end = ?');
        values.push(data.currentPeriodEnd);
      }
      if (data.cancelAtPeriodEnd !== undefined) {
        updates.push('cancel_at_period_end = ?');
        values.push(data.cancelAtPeriodEnd ? 1 : 0);
      }

      if (updates.length > 0) {
        updates.push('updated_at = ?');
        values.push(now);
        values.push(existing.id);

        sqlite.prepare(`
          UPDATE subscriptions SET ${updates.join(', ')} WHERE id = ?
        `).run(...values);
      }

      return (await this.getSubscription())!;
    } else {
      // Create new subscription
      const id = randomUUID();
      sqlite.prepare(`
        INSERT INTO subscriptions (id, tier, stripe_customer_id, stripe_subscription_id, stripe_price_id, status, current_period_end, cancel_at_period_end, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        data.tier || 'free',
        data.stripeCustomerId || null,
        data.stripeSubscriptionId || null,
        data.stripePriceId || null,
        data.status || 'active',
        data.currentPeriodEnd || null,
        data.cancelAtPeriodEnd ? 1 : 0,
        now
      );

      return (await this.getSubscription())!;
    }
  }

  // Get current usage counts
  async getUsageCounts(): Promise<{ users: number; servers: number }> {
    // Count servers from local database
    const serverCount = sqlite.prepare(`
      SELECT COUNT(*) as count FROM servers
    `).get() as { count: number };

    // Note: Users are counted from TideCloak, not local DB
    // This method returns server count; user count comes from TideCloak API
    return {
      users: 0, // Will be filled from TideCloak
      servers: serverCount.count,
    };
  }

  // Get server count only (for limit checks)
  async getServerCount(): Promise<number> {
    const result = sqlite.prepare(`
      SELECT COUNT(*) as count FROM servers
    `).get() as { count: number };
    return result.count;
  }

  // Check if can add a resource (user or server)
  async checkCanAdd(resource: 'user' | 'server', currentCount: number): Promise<LimitCheck> {
    const subscription = await this.getSubscription();
    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];
    const limit = resource === 'user' ? tierConfig.maxUsers : tierConfig.maxServers;

    // -1 means unlimited
    const allowed = limit === -1 || currentCount < limit;

    return {
      allowed,
      current: currentCount,
      limit: limit === -1 ? Infinity : limit,
      tier,
      tierName: tierConfig.name,
    };
  }

  // Get full license info
  async getLicenseInfo(userCount: number): Promise<LicenseInfo> {
    const subscription = await this.getSubscription();
    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];
    const serverCount = await this.getServerCount();

    return {
      subscription,
      usage: { users: userCount, servers: serverCount },
      limits: {
        maxUsers: tierConfig.maxUsers === -1 ? Infinity : tierConfig.maxUsers,
        maxServers: tierConfig.maxServers === -1 ? Infinity : tierConfig.maxServers,
      },
      tier,
      tierName: tierConfig.name,
    };
  }

  // Add a billing history record
  async addBillingRecord(data: {
    stripeInvoiceId?: string;
    amount: number;
    currency?: string;
    status: string;
    invoicePdf?: string;
    description?: string;
  }): Promise<void> {
    const subscription = await this.getSubscription();
    if (!subscription) return;

    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    sqlite.prepare(`
      INSERT INTO billing_history (id, subscription_id, stripe_invoice_id, amount, currency, status, invoice_pdf, description, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      subscription.id,
      data.stripeInvoiceId || null,
      data.amount,
      data.currency || 'usd',
      data.status,
      data.invoicePdf || null,
      data.description || null,
      now
    );
  }

  // Get billing history
  async getBillingHistory(limit: number = 50): Promise<BillingHistory[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM billing_history ORDER BY created_at DESC LIMIT ?
    `).all(limit) as any[];

    return rows.map(row => ({
      id: row.id,
      subscriptionId: row.subscription_id,
      stripeInvoiceId: row.stripe_invoice_id,
      amount: row.amount,
      currency: row.currency,
      status: row.status,
      invoicePdf: row.invoice_pdf,
      description: row.description,
      createdAt: row.created_at,
    }));
  }
}

export const storage = new SQLiteStorage();
export const approvalStorage = new ApprovalStorage();
export const policyStorage = new PolicyStorage();
export const pendingPolicyStorage = new PendingPolicyStorage();
export const templateStorage = new TemplateStorage();
export const subscriptionStorage = new SubscriptionStorage();
