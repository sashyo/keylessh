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
  recordings,
  fileOperations,
  subscriptions,
  billingHistory,
  subscriptionTiers,
  type User,
  type InsertUser,
  type Server,
  type InsertServer,
  type Session,
  type InsertSession,
  type FileOperation,
  type FileOperationType,
  type FileOperationMode,
  type FileOperationStatus,
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
import { isStripeConfigured } from "./lib/stripe";
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
    ssh_users TEXT NOT NULL DEFAULT '[]'
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
    details TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'committed', 'cancelled')),
    approval_count INTEGER NOT NULL DEFAULT 0,
    threshold INTEGER NOT NULL DEFAULT 1
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

  -- Session recordings table
  CREATE TABLE IF NOT EXISTS recordings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    ssh_user TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    duration INTEGER,
    terminal_width INTEGER NOT NULL DEFAULT 80,
    terminal_height INTEGER NOT NULL DEFAULT 24,
    data TEXT NOT NULL DEFAULT '',
    text_content TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_recordings_session ON recordings(session_id);
  CREATE INDEX IF NOT EXISTS idx_recordings_server ON recordings(server_id);
  CREATE INDEX IF NOT EXISTS idx_recordings_user ON recordings(user_id);
  CREATE INDEX IF NOT EXISTS idx_recordings_started ON recordings(started_at DESC);

  -- File operations log table
  CREATE TABLE IF NOT EXISTS file_operations (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    user_email TEXT,
    ssh_user TEXT NOT NULL,
    operation TEXT NOT NULL,
    path TEXT NOT NULL,
    target_path TEXT,
    file_size INTEGER,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    timestamp INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_file_ops_session ON file_operations(session_id);
  CREATE INDEX IF NOT EXISTS idx_file_ops_server ON file_operations(server_id);
  CREATE INDEX IF NOT EXISTS idx_file_ops_user ON file_operations(user_id);
  CREATE INDEX IF NOT EXISTS idx_file_ops_timestamp ON file_operations(timestamp DESC);
`);

// Lightweight migrations for existing DBs (CREATE TABLE IF NOT EXISTS doesn't alter).

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

// Migration: Add users_over_limit and servers_over_limit columns to subscriptions for SSH access control
try {
  const subColumns = sqlite
    .prepare(`PRAGMA table_info(subscriptions)`)
    .all() as Array<{ name: string }>;
  const hasUsersOverLimit = subColumns.some((c) => c.name === "users_over_limit");
  if (!hasUsersOverLimit) {
    sqlite.prepare(`ALTER TABLE subscriptions ADD COLUMN users_over_limit INTEGER DEFAULT 0`).run();
  }
  const hasServersOverLimit = subColumns.some((c) => c.name === "servers_over_limit");
  if (!hasServersOverLimit) {
    sqlite.prepare(`ALTER TABLE subscriptions ADD COLUMN servers_over_limit INTEGER DEFAULT 0`).run();
  }
} catch {
  // Ignore migration errors; queries will surface issues.
}

// Migration: Add recording columns to servers table
try {
  const serverColumns = sqlite
    .prepare(`PRAGMA table_info(servers)`)
    .all() as Array<{ name: string }>;
  const hasRecordingEnabled = serverColumns.some((c) => c.name === "recording_enabled");
  if (!hasRecordingEnabled) {
    sqlite.prepare(`ALTER TABLE servers ADD COLUMN recording_enabled INTEGER NOT NULL DEFAULT 0`).run();
  }
  const hasRecordedUsers = serverColumns.some((c) => c.name === "recorded_users");
  if (!hasRecordedUsers) {
    sqlite.prepare(`ALTER TABLE servers ADD COLUMN recorded_users TEXT NOT NULL DEFAULT '[]'`).run();
  }
} catch {
  // Ignore migration errors; queries will surface issues.
}

// Migration: Add recording_id column to sessions table
try {
  const sessionColumns = sqlite
    .prepare(`PRAGMA table_info(sessions)`)
    .all() as Array<{ name: string }>;
  const hasRecordingId = sessionColumns.some((c) => c.name === "recording_id");
  if (!hasRecordingId) {
    sqlite.prepare(`ALTER TABLE sessions ADD COLUMN recording_id TEXT`).run();
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
      recordingEnabled: insertServer.recordingEnabled ?? false,
      recordedUsers: (insertServer.recordedUsers ?? []) as string[],
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
      recordingId: insertSession.recordingId ?? null,
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

    // Log the creation with approval_count=0 at time of creation
    const threshold = policy.threshold || 1;
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, details, status, approval_count, threshold)
      VALUES ('created', ?, ?, ?, ?, 'pending', 0, ?)
    `).run(policy.id, policy.requestedByEmail || policy.requestedBy, policy.roleId, JSON.stringify({ threshold }), threshold);

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

    // Refetch to get updated counts after this decision
    const policy = await this.getPendingPolicy(decision.policyRequestId);
    const logType = decision.decision === 1 ? "approved" : "denied";
    const approvalCount = policy?.approvalCount || 0;
    const threshold = policy?.threshold || 1;

    // Calculate what status will be after this action
    let statusAfterAction = "pending";
    if (decision.decision === 1 && approvalCount >= threshold) {
      statusAfterAction = "approved";
      await this.updateStatus(decision.policyRequestId, "approved");
    }

    // Log the decision with status and counts at time of action
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(logType, decision.policyRequestId, decision.userEmail, policy?.roleId || null, statusAfterAction, approvalCount, threshold);
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

    // Log the commit with status and counts at time of action
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
      VALUES ('committed', ?, ?, ?, 'committed', ?, ?)
    `).run(id, userEmail, policy.roleId, policy.approvalCount || 0, policy.threshold);
  }

  // Cancel a pending policy
  async cancelPolicy(id: string, userEmail: string): Promise<void> {
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");

    await this.updateStatus(id, "cancelled");

    // Log the cancellation with status and counts at time of action
    sqlite.prepare(`
      INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
      VALUES ('cancelled', ?, ?, ?, 'cancelled', ?, ?)
    `).run(id, userEmail, policy.roleId, policy.approvalCount || 0, policy.threshold);
  }

  // Get policy logs (full audit trail showing all actions)
  async getLogs(limit: number = 100, offset: number = 0): Promise<any[]> {
    const rows = sqlite.prepare(`
      SELECT
        l.*,
        p.created_at as policy_created_at,
        p.requested_by_email as policy_requested_by
      FROM ssh_policy_logs l
      LEFT JOIN pending_ssh_policies p ON l.policy_request_id = p.id
      ORDER BY l.timestamp DESC
      LIMIT ? OFFSET ?
    `).all(limit, offset) as any[];

    return rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      type: row.type,
      policyRequestId: row.policy_request_id,
      userEmail: row.user_email,
      roleId: row.role_id,
      details: row.details,
      policyStatus: row.status,
      policyThreshold: row.threshold,
      policyCreatedAt: row.policy_created_at,
      policyRequestedBy: row.policy_requested_by,
      approvalCount: row.approval_count || 0,
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
  description: "Standard SSH access policy with role-based authorization. Implements the 3-method IAccessPolicy interface for ValidateData, ValidateApprovers, and ValidateExecutor.",
  csCode: `using Ork.Forseti.Sdk;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Implements the 3-method IAccessPolicy interface:
/// - ValidateData: ALWAYS called (validates policy parameters)
/// - ValidateApprovers: Called if approvalType == EXPLICIT (validates approver dokens)
/// - ValidateExecutor: Called if executorType == PRIVATE (validates executor doken)
/// </summary>
public class SshPolicy : IAccessPolicy
{
    /// <summary>
    /// Validate the request data. Always called.
    /// Checks that required policy parameters (role, resource) are present.
    /// </summary>
    public PolicyDecision ValidateData(DataContext ctx)
    {
        var policy = ctx.Policy;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        // Get required parameters from policy
        if (!policy.Params.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.Params.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        ForsetiSdk.Log($"ValidateData: policy validated for role '{requiredRole}' on resource '{resource}'");
        return PolicyDecision.Allow();
    }

    /// <summary>
    /// Validate approvers when policy.approvalType == EXPLICIT.
    /// Checks that at least one approver has the required role for the resource.
    /// </summary>
    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var policy = ctx.Policy;
        var dokens = ctx.Dokens;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        if (dokens == null || dokens.Count == 0)
            return PolicyDecision.Deny("No approver dokens provided");

        // Get required parameters
        if (!policy.Params.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.Params.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        // Check if any approver has the required role
        foreach (var doken in dokens)
        {
            if (doken.Payload.ResourceAccessRoleExists(resource, requiredRole))
            {
                ForsetiSdk.Log($"ValidateApprovers: approver has role '{requiredRole}' for resource '{resource}'");
                return PolicyDecision.Allow();
            }
        }

        return PolicyDecision.Deny($"No approver has the required role '{requiredRole}' for resource '{resource}'");
    }

    /// <summary>
    /// Validate executor when policy.executorType == PRIVATE.
    /// Checks that the executor (from Authorization header) has the required role.
    /// </summary>
    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var policy = ctx.Policy;
        var doken = ctx.Doken;

        if (policy == null)
            return PolicyDecision.Deny("No policy provided");

        if (doken == null)
            return PolicyDecision.Deny("No executor doken provided");

        // Get required parameters
        if (!policy.Params.TryGetParameter<string>("role", out var requiredRole) || string.IsNullOrEmpty(requiredRole))
            return PolicyDecision.Deny("Policy missing required 'role' parameter");

        if (!policy.Params.TryGetParameter<string>("resource", out var resource) || string.IsNullOrEmpty(resource))
            return PolicyDecision.Deny("Policy missing required 'resource' parameter");

        // Verify that the executor's doken contains the required role
        if (!doken.Payload.ResourceAccessRoleExists(resource, requiredRole))
            return PolicyDecision.Deny($"Executor does not have the required role '{requiredRole}' for resource '{resource}'");

        ForsetiSdk.Log($"ValidateExecutor: executor has role '{requiredRole}' for resource '{resource}'");
        return PolicyDecision.Allow();
    }
}`,
  parameters: [] as TemplateParameter[],
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

  // Get enabled server count
  async getEnabledServerCount(): Promise<number> {
    const result = sqlite.prepare(`
      SELECT COUNT(*) as count FROM servers WHERE enabled = 1
    `).get() as { count: number };
    return result.count;
  }

  // Get server counts (total and enabled)
  async getServerCounts(): Promise<{ total: number; enabled: number }> {
    const result = sqlite.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled
      FROM servers
    `).get() as { total: number; enabled: number };
    return { total: result.total, enabled: result.enabled || 0 };
  }

  // Check if can add a resource (user or server)
  async checkCanAdd(resource: 'user' | 'server', currentCount: number): Promise<LimitCheck> {
    // If Stripe is not configured, allow unlimited resources
    if (!isStripeConfigured()) {
      return {
        allowed: true,
        current: currentCount,
        limit: Infinity,
        tier: 'enterprise',
        tierName: 'Unlimited',
      };
    }

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
  async getLicenseInfo(
    userCounts: { total: number; enabled: number }
  ): Promise<LicenseInfo> {
    const serverCounts = await this.getServerCounts();

    // If Stripe is not configured, return unlimited license info
    if (!isStripeConfigured()) {
      return {
        subscription: null,
        usage: { users: userCounts.total, servers: serverCounts.total },
        limits: {
          maxUsers: Infinity,
          maxServers: Infinity,
        },
        tier: 'enterprise',
        tierName: 'Unlimited',
        overLimit: {
          users: {
            isOverLimit: false,
            enabled: userCounts.enabled,
            total: userCounts.total,
            limit: -1,
            overBy: 0,
          },
          servers: {
            isOverLimit: false,
            enabled: serverCounts.enabled,
            total: serverCounts.total,
            limit: -1,
            overBy: 0,
          },
        },
      };
    }

    const subscription = await this.getSubscription();
    const tier: SubscriptionTier = (subscription?.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];

    const userLimit = tierConfig.maxUsers === -1 ? Infinity : tierConfig.maxUsers;
    const serverLimit = tierConfig.maxServers === -1 ? Infinity : tierConfig.maxServers;

    // Calculate over-limit status
    const userOverBy = userLimit === Infinity ? 0 : Math.max(0, userCounts.enabled - userLimit);
    const serverOverBy = serverLimit === Infinity ? 0 : Math.max(0, serverCounts.enabled - serverLimit);

    return {
      subscription,
      usage: { users: userCounts.total, servers: serverCounts.total },
      limits: {
        maxUsers: userLimit,
        maxServers: serverLimit,
      },
      tier,
      tierName: tierConfig.name,
      overLimit: {
        users: {
          isOverLimit: userOverBy > 0,
          enabled: userCounts.enabled,
          total: userCounts.total,
          limit: userLimit === Infinity ? -1 : userLimit,
          overBy: userOverBy,
        },
        servers: {
          isOverLimit: serverOverBy > 0,
          enabled: serverCounts.enabled,
          total: serverCounts.total,
          limit: serverLimit === Infinity ? -1 : serverLimit,
          overBy: serverOverBy,
        },
      },
    };
  }

  // Update the cached over-limit status for SSH access control
  async updateOverLimitStatus(usersOverLimit: boolean, serversOverLimit: boolean): Promise<void> {
    const subscription = await this.getSubscription();
    if (!subscription) return;

    sqlite.prepare(`
      UPDATE subscriptions SET users_over_limit = ?, servers_over_limit = ? WHERE id = ?
    `).run(usersOverLimit ? 1 : 0, serversOverLimit ? 1 : 0, subscription.id);
  }

  // Check if SSH access is blocked due to being over limit
  async isSshBlocked(): Promise<{ blocked: boolean; reason?: string }> {
    // If Stripe is not configured, never block SSH access
    if (!isStripeConfigured()) {
      return { blocked: false };
    }

    const subscription = await this.getSubscription();
    if (!subscription) {
      return { blocked: false };
    }

    // Get the tier limits
    const tier: SubscriptionTier = (subscription.tier as SubscriptionTier) || 'free';
    const tierConfig = subscriptionTiers[tier];
    const serverLimit = tierConfig.maxServers;

    // Real-time check for servers (we have this data locally)
    const serverCounts = await this.getServerCounts();
    const serversOverLimit = serverLimit !== -1 && serverCounts.enabled > serverLimit;

    // Check the cached users_over_limit status (users require TideCloak API)
    const row = sqlite.prepare(`
      SELECT users_over_limit FROM subscriptions WHERE id = ?
    `).get(subscription.id) as { users_over_limit: number } | undefined;

    const usersOverLimit = row?.users_over_limit === 1;

    if (usersOverLimit && serversOverLimit) {
      return {
        blocked: true,
        reason: "Your organization has exceeded both user and server limits. Please contact an administrator to enable SSH access.",
      };
    }

    if (usersOverLimit) {
      return {
        blocked: true,
        reason: "Your organization has exceeded the user limit for the current plan. Please contact an administrator to enable SSH access.",
      };
    }

    if (serversOverLimit) {
      return {
        blocked: true,
        reason: "Your organization has exceeded the server limit for the current plan. Please contact an administrator to enable SSH access.",
      };
    }

    return { blocked: false };
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

// Recording types
export interface Recording {
  id: string;
  sessionId: string;
  serverId: string;
  serverName: string;
  userId: string;
  userEmail: string;
  sshUser: string;
  startedAt: Date;
  endedAt?: Date | null;
  duration?: number | null;
  terminalWidth: number;
  terminalHeight: number;
  data: string;
  textContent: string;
  fileSize: number;
}

export interface InsertRecording {
  sessionId: string;
  serverId: string;
  serverName: string;
  userId: string;
  userEmail: string;
  sshUser: string;
  terminalWidth?: number;
  terminalHeight?: number;
}

// Recording storage class for session recordings
export class RecordingStorage {
  // Create a new recording
  async createRecording(data: InsertRecording): Promise<Recording> {
    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    sqlite.prepare(`
      INSERT INTO recordings (id, session_id, server_id, server_name, user_id, user_email, ssh_user, started_at, terminal_width, terminal_height)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.sessionId,
      data.serverId,
      data.serverName,
      data.userId,
      data.userEmail,
      data.sshUser,
      now,
      data.terminalWidth || 80,
      data.terminalHeight || 24
    );

    return {
      id,
      sessionId: data.sessionId,
      serverId: data.serverId,
      serverName: data.serverName,
      userId: data.userId,
      userEmail: data.userEmail,
      sshUser: data.sshUser,
      startedAt: new Date(now * 1000),
      endedAt: null,
      duration: null,
      terminalWidth: data.terminalWidth || 80,
      terminalHeight: data.terminalHeight || 24,
      data: "",
      textContent: "",
      fileSize: 0,
    };
  }

  // Append data to a recording (asciicast v2 format - JSON lines)
  async appendData(id: string, eventData: string): Promise<void> {
    sqlite.prepare(`
      UPDATE recordings SET data = data || ?, file_size = file_size + ? WHERE id = ?
    `).run(eventData, Buffer.byteLength(eventData, 'utf8'), id);
  }

  // Append text content for searchability
  async appendTextContent(id: string, text: string): Promise<void> {
    sqlite.prepare(`
      UPDATE recordings SET text_content = text_content || ? WHERE id = ?
    `).run(text, id);
  }

  // Finalize a recording (set end time and calculate duration)
  async finalizeRecording(id: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    // Get start time to calculate duration
    const row = sqlite.prepare(`
      SELECT started_at FROM recordings WHERE id = ?
    `).get(id) as { started_at: number } | undefined;

    if (row) {
      const duration = now - row.started_at;
      sqlite.prepare(`
        UPDATE recordings SET ended_at = ?, duration = ? WHERE id = ?
      `).run(now, duration, id);
    }
  }

  // Get recording by ID
  async getRecording(id: string): Promise<Recording | undefined> {
    const row = sqlite.prepare(`
      SELECT * FROM recordings WHERE id = ?
    `).get(id) as any | undefined;

    if (!row) return undefined;

    return this.mapRow(row);
  }

  // Get recording by session ID
  async getRecordingBySessionId(sessionId: string): Promise<Recording | undefined> {
    const row = sqlite.prepare(`
      SELECT * FROM recordings WHERE session_id = ?
    `).get(sessionId) as any | undefined;

    if (!row) return undefined;

    return this.mapRow(row);
  }

  // Get all recordings (paginated)
  async getRecordings(limit: number = 50, offset: number = 0): Promise<Recording[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM recordings ORDER BY started_at DESC LIMIT ? OFFSET ?
    `).all(limit, offset) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get recordings by server ID
  async getRecordingsByServer(serverId: string, limit: number = 50): Promise<Recording[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM recordings WHERE server_id = ? ORDER BY started_at DESC LIMIT ?
    `).all(serverId, limit) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get recordings by user ID
  async getRecordingsByUser(userId: string, limit: number = 50): Promise<Recording[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM recordings WHERE user_id = ? ORDER BY started_at DESC LIMIT ?
    `).all(userId, limit) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Search recordings by text content
  async searchRecordings(query: string, limit: number = 50): Promise<Recording[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM recordings WHERE text_content LIKE ? ORDER BY started_at DESC LIMIT ?
    `).all(`%${query}%`, limit) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get recording count
  async getRecordingCount(): Promise<number> {
    const row = sqlite.prepare(`
      SELECT COUNT(*) as count FROM recordings
    `).get() as { count: number };
    return row.count;
  }

  // Get total storage used by recordings
  async getTotalStorageBytes(): Promise<number> {
    const row = sqlite.prepare(`
      SELECT SUM(file_size) as total FROM recordings
    `).get() as { total: number | null };
    return row.total || 0;
  }

  // Delete a recording
  async deleteRecording(id: string): Promise<boolean> {
    const result = sqlite.prepare(`
      DELETE FROM recordings WHERE id = ?
    `).run(id);
    return result.changes > 0;
  }

  // Delete recordings older than a certain date
  async deleteRecordingsOlderThan(date: Date): Promise<number> {
    const timestamp = Math.floor(date.getTime() / 1000);
    const result = sqlite.prepare(`
      DELETE FROM recordings WHERE started_at < ?
    `).run(timestamp);
    return result.changes;
  }

  // Map database row to Recording type
  private mapRow(row: any): Recording {
    return {
      id: row.id,
      sessionId: row.session_id,
      serverId: row.server_id,
      serverName: row.server_name,
      userId: row.user_id,
      userEmail: row.user_email,
      sshUser: row.ssh_user,
      startedAt: new Date(row.started_at * 1000),
      endedAt: row.ended_at ? new Date(row.ended_at * 1000) : null,
      duration: row.duration,
      terminalWidth: row.terminal_width,
      terminalHeight: row.terminal_height,
      data: row.data,
      textContent: row.text_content,
      fileSize: row.file_size,
    };
  }
}

// File operation storage class
export interface InsertFileOperation {
  sessionId: string;
  serverId: string;
  userId: string;
  userEmail?: string;
  sshUser: string;
  operation: FileOperationType;
  path: string;
  targetPath?: string;
  fileSize?: number;
  mode: FileOperationMode;
  status: FileOperationStatus;
  errorMessage?: string;
}

export class FileOperationStorage {
  // Log a file operation
  async logOperation(data: InsertFileOperation): Promise<FileOperation> {
    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    sqlite.prepare(`
      INSERT INTO file_operations (id, session_id, server_id, user_id, user_email, ssh_user, operation, path, target_path, file_size, mode, status, error_message, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.sessionId,
      data.serverId,
      data.userId,
      data.userEmail || null,
      data.sshUser,
      data.operation,
      data.path,
      data.targetPath || null,
      data.fileSize || null,
      data.mode,
      data.status,
      data.errorMessage || null,
      now
    );

    return {
      id,
      sessionId: data.sessionId,
      serverId: data.serverId,
      userId: data.userId,
      userEmail: data.userEmail || null,
      sshUser: data.sshUser,
      operation: data.operation,
      path: data.path,
      targetPath: data.targetPath || null,
      fileSize: data.fileSize || null,
      mode: data.mode,
      status: data.status,
      errorMessage: data.errorMessage || null,
      timestamp: new Date(now * 1000),
    };
  }

  // Get file operations by session ID
  async getOperationsBySession(sessionId: string): Promise<FileOperation[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM file_operations WHERE session_id = ? ORDER BY timestamp DESC
    `).all(sessionId) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get file operations by server ID
  async getOperationsByServer(serverId: string, limit: number = 100): Promise<FileOperation[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM file_operations WHERE server_id = ? ORDER BY timestamp DESC LIMIT ?
    `).all(serverId, limit) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get file operations by user ID
  async getOperationsByUser(userId: string, limit: number = 100): Promise<FileOperation[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM file_operations WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?
    `).all(userId, limit) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get all file operations (paginated)
  async getOperations(limit: number = 100, offset: number = 0): Promise<FileOperation[]> {
    const rows = sqlite.prepare(`
      SELECT * FROM file_operations ORDER BY timestamp DESC LIMIT ? OFFSET ?
    `).all(limit, offset) as any[];

    return rows.map(row => this.mapRow(row));
  }

  // Get operation count
  async getOperationCount(): Promise<number> {
    const row = sqlite.prepare(`
      SELECT COUNT(*) as count FROM file_operations
    `).get() as { count: number };
    return row.count;
  }

  // Delete operations older than a certain date
  async deleteOperationsOlderThan(date: Date): Promise<number> {
    const timestamp = Math.floor(date.getTime() / 1000);
    const result = sqlite.prepare(`
      DELETE FROM file_operations WHERE timestamp < ?
    `).run(timestamp);
    return result.changes;
  }

  // Map database row to FileOperation type
  private mapRow(row: any): FileOperation {
    return {
      id: row.id,
      sessionId: row.session_id,
      serverId: row.server_id,
      userId: row.user_id,
      userEmail: row.user_email,
      sshUser: row.ssh_user,
      operation: row.operation as FileOperationType,
      path: row.path,
      targetPath: row.target_path,
      fileSize: row.file_size,
      mode: row.mode as FileOperationMode,
      status: row.status as FileOperationStatus,
      errorMessage: row.error_message,
      timestamp: new Date(row.timestamp * 1000),
    };
  }
}

export const storage = new SQLiteStorage();
export const approvalStorage = new ApprovalStorage();
export const policyStorage = new PolicyStorage();
export const pendingPolicyStorage = new PendingPolicyStorage();
export const templateStorage = new TemplateStorage();
export const subscriptionStorage = new SubscriptionStorage();
export const recordingStorage = new RecordingStorage();
export const fileOperationStorage = new FileOperationStorage();
