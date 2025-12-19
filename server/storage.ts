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
  type User,
  type InsertUser,
  type Server,
  type InsertServer,
  type Session,
  type InsertSession,
} from "@shared/schema";

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
    server_id TEXT NOT NULL,
    ssh_user TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    started_at INTEGER NOT NULL,
    ended_at INTEGER
  );

  -- Approval tables (matching ideed-swarm structure)
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
`);

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

export const storage = new SQLiteStorage();
export const approvalStorage = new ApprovalStorage();
