import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import { eq, desc, inArray, and, lt } from "drizzle-orm";
import { randomUUID } from "crypto";
import {
  users,
  servers,
  sessions,
  recordings,
  fileOperations,
  subscriptions,
  billingHistory,
  bridges,
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
  type Bridge,
  type InsertBridge,
  type SubscriptionTier,
  type LicenseInfo,
  type LimitCheck,
} from "@shared/schema";
import { getAdminPolicy } from "./lib/tidecloakApi";
import { isStripeConfigured } from "./lib/stripe";
import { createRequire } from "module";

// Use createRequire for heimdall-tide (CJS module with broken ESM exports)
// In CJS bundle __filename is available; in ESM dev mode use import.meta.url
const require = createRequire(
  typeof __filename !== "undefined" ? __filename : import.meta.url
);
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

// Database connection
const DATABASE_URL = process.env.DATABASE_URL || "postgresql://localhost:5432/keylessh";

// Initialize PostgreSQL connection pool
const pool = new pg.Pool({ connectionString: DATABASE_URL });

// Initialize Drizzle
const db = drizzle(pool);

// Create tables if they don't exist
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      allowed_servers JSONB NOT NULL DEFAULT '[]'
    );

    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 22,
      environment TEXT NOT NULL DEFAULT 'production',
      tags JSONB NOT NULL DEFAULT '[]',
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      ssh_users JSONB NOT NULL DEFAULT '[]',
      recording_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      recorded_users JSONB NOT NULL DEFAULT '[]',
      bridge_id TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      user_username TEXT,
      user_email TEXT,
      server_id TEXT NOT NULL,
      ssh_user TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      started_at TIMESTAMP NOT NULL,
      ended_at TIMESTAMP,
      recording_id TEXT
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
      created_at INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
      updated_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS approval_decisions (
      id SERIAL PRIMARY KEY,
      approval_id TEXT NOT NULL,
      user_vuid TEXT NOT NULL,
      user_email TEXT NOT NULL,
      decision INTEGER NOT NULL CHECK(decision IN (0, 1)),
      created_at INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
      FOREIGN KEY (approval_id) REFERENCES pending_approvals(id) ON DELETE CASCADE,
      UNIQUE(approval_id, user_vuid)
    );

    CREATE TABLE IF NOT EXISTS access_change_logs (
      id SERIAL PRIMARY KEY,
      timestamp INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
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
      created_at INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
      updated_at INTEGER
    );

    -- Pending SSH policy requests (awaiting approval)
    CREATE TABLE IF NOT EXISTS pending_ssh_policies (
      id TEXT PRIMARY KEY,
      role_id TEXT NOT NULL,
      requested_by TEXT NOT NULL,
      requested_by_email TEXT,
      policy_request_data TEXT NOT NULL,
      contract_code TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'committed', 'cancelled')),
      threshold INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
      updated_at INTEGER
    );

    -- SSH policy approval decisions
    CREATE TABLE IF NOT EXISTS ssh_policy_decisions (
      id SERIAL PRIMARY KEY,
      policy_request_id TEXT NOT NULL,
      user_vuid TEXT NOT NULL,
      user_email TEXT NOT NULL,
      decision INTEGER NOT NULL CHECK(decision IN (0, 1)),
      created_at INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
      UNIQUE(policy_request_id, user_vuid)
    );

    -- SSH policy change logs
    CREATE TABLE IF NOT EXISTS ssh_policy_logs (
      id SERIAL PRIMARY KEY,
      timestamp INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
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
      created_at INTEGER NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::INTEGER,
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
      cancel_at_period_end BOOLEAN DEFAULT FALSE,
      users_over_limit BOOLEAN DEFAULT FALSE,
      servers_over_limit BOOLEAN DEFAULT FALSE,
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
      started_at TIMESTAMP NOT NULL,
      ended_at TIMESTAMP,
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
      timestamp TIMESTAMP NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_file_ops_session ON file_operations(session_id);
    CREATE INDEX IF NOT EXISTS idx_file_ops_server ON file_operations(server_id);
    CREATE INDEX IF NOT EXISTS idx_file_ops_user ON file_operations(user_id);
    CREATE INDEX IF NOT EXISTS idx_file_ops_timestamp ON file_operations(timestamp DESC);

    -- SSH bridges - WebSocket-to-TCP relay endpoints
    CREATE TABLE IF NOT EXISTS bridges (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      description TEXT,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_bridges_enabled ON bridges(enabled);
    CREATE INDEX IF NOT EXISTS idx_bridges_default ON bridges(is_default);
  `);
}

// Seed: Create default bridge from BRIDGE_URL env var if no bridges exist
async function seedDefaultBridge() {
  try {
    const bridgeUrl = process.env.BRIDGE_URL;
    if (bridgeUrl) {
      const result = await pool.query(`SELECT COUNT(*) as count FROM bridges`);
      if (parseInt(result.rows[0].count) === 0) {
        const id = randomUUID();
        const now = new Date();
        await pool.query(
          `INSERT INTO bridges (id, name, url, description, enabled, is_default, created_at)
           VALUES ($1, $2, $3, $4, TRUE, TRUE, $5)`,
          [id, "Default Bridge", bridgeUrl, "Auto-created from BRIDGE_URL environment variable", now]
        );
        console.log(`[Storage] Created default bridge from BRIDGE_URL: ${bridgeUrl}`);
      }
    }
  } catch (err) {
    console.error(`[Storage] Failed to seed default bridge: ${err}`);
  }
}

// Default SSH policy template
const DEFAULT_SSH_TEMPLATE = {
  name: "SSH Access Policy",
  description:
    "Standard SSH access policy with role-based authorization. Uses [PolicyParam] attributes and DecisionBuilder for clean, declarative policy logic.",
  csCode: `using Ork.Forseti.Sdk;
using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// SSH Challenge Signing Policy for Keyle-SSH.
/// Uses [PolicyParam] attributes for automatic parameter binding and
/// DecisionBuilder for composable policy validation.
/// </summary>
public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for SSH access.")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check.")]
    public string Resource { get; set; }

    /// <summary>
    /// Validate the request data. Always called.
    /// This validates ctx.Data is an SSHv2 publickey authentication "to-be-signed" payload:
    /// string session_id || byte 50 || string user || string "ssh-connection" || string "publickey" || bool TRUE
    /// || string alg || string key_blob
    /// </summary>
    public PolicyDecision ValidateData(DataContext ctx)
    {
        if (string.IsNullOrWhiteSpace(Role))
            return PolicyDecision.Deny("Role is missing.");

        var parts = Role.Split(':', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[1].Length == 0)
            return PolicyDecision.Deny("Role must be in the form 'prefix:role'.");

        var userRole = parts[1];

        if (ctx == null || ctx.Data == null || ctx.Data.Length == 0)
            return PolicyDecision.Deny("No data provided for SSH challenge validation");

        if (ctx.Data.Length < 24)
            return PolicyDecision.Deny($"Data too short to be an SSH publickey challenge: {ctx.Data.Length} bytes");

        if (ctx.Data.Length > 8192)
            return PolicyDecision.Deny($"Data too large for SSH challenge: {ctx.Data.Length} bytes (maximum 8192)");

        if (!SshPublicKeyChallenge.TryParse(ctx.Data, out var parsed, out var err))
            return PolicyDecision.Deny(err);

        if (parsed.PublicKeyAlgorithm != "ssh-ed25519")
            return PolicyDecision.Deny("Only ssh-ed25519 allowed");

        if(parsed.Username != userRole) {
            return PolicyDecision.Deny("Not allowed to log in as " + parsed.Username);
        }

        return PolicyDecision.Allow();
    }

    public PolicyDecision ValidateApprovers(ApproversContext ctx)
    {
        var approvers = DokenDto.WrapAll(ctx.Dokens);
        return Decision
            .Require(approvers != null && approvers.Count > 0, "No approver dokens provided")
            .RequireAnyWithRole(approvers, Resource, Role);
    }

    public PolicyDecision ValidateExecutor(ExecutorContext ctx)
    {
        var executor = new DokenDto(ctx.Doken);
        return Decision
            .RequireNotExpired(executor)
            .RequireRole(executor, Resource, Role);
    }

    internal static class SshPublicKeyChallenge
    {
        internal sealed class Parsed
        {
            public int SessionIdLength { get; set; }
            public string Username { get; set; }
            public string Service { get; set; }
            public string Method { get; set; }
            public string PublicKeyAlgorithm { get; set; }
            public string PublicKeyBlobType { get; set; }
            public int PublicKeyBlobLength { get; set; }
        }

        public static bool TryParse(byte[] buf, out Parsed parsed, out string error)
        {
            parsed = null;
            error = "";

            int off = 0;

            // session_id (ssh string)
            if (!TryReadSshString(buf, ref off, out var sessionId))
            {
                error = "Invalid SSH string for session_id";
                return false;
            }

            // Common session_id lengths: 20/32/48/64
            if (!(sessionId.Length == 20 || sessionId.Length == 32 || sessionId.Length == 48 || sessionId.Length == 64))
            {
                error = $"Unexpected session_id length: {sessionId.Length}";
                return false;
            }

            // message type
            if (!TryReadByte(buf, ref off, out byte msg))
            {
                error = "Missing SSH message type";
                return false;
            }

            if (msg != 50) // SSH_MSG_USERAUTH_REQUEST
            {
                error = $"Not SSH userauth request (expected msg 50, got {msg})";
                return false;
            }

            // username, service, method
            if (!TryReadSshAscii(buf, ref off, 256, out var username, out error)) return false;
            if (!TryReadSshAscii(buf, ref off, 64, out var service, out error)) return false;
            if (!TryReadSshAscii(buf, ref off, 64, out var method, out error)) return false;

            if (!string.Equals(service, "ssh-connection", StringComparison.Ordinal))
            {
                error = $"Unexpected SSH service: {service}";
                return false;
            }

            if (!string.Equals(method, "publickey", StringComparison.Ordinal))
            {
                error = $"Unexpected SSH auth method: {method}";
                return false;
            }

            // boolean TRUE
            if (!TryReadByte(buf, ref off, out byte hasSig))
            {
                error = "Missing publickey boolean";
                return false;
            }

            if (hasSig != 1)
            {
                error = "Expected publickey boolean TRUE (1)";
                return false;
            }

            // algorithm
            if (!TryReadSshAscii(buf, ref off, 128, out var alg, out error)) return false;

            // Allowlist
            var allowed = new HashSet<string>(StringComparer.Ordinal)
            {
                "ssh-ed25519",
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            };

            if (!allowed.Contains(alg))
            {
                error = $"Disallowed/unknown SSH public key algorithm: {alg}";
                return false;
            }

            // key blob
            if (!TryReadSshString(buf, ref off, out var keyBlob))
            {
                error = "Invalid SSH string for publickey blob";
                return false;
            }

            if (keyBlob.Length < 8)
            {
                error = "Publickey blob too short";
                return false;
            }

            // key blob begins with ssh string key type
            int kbOff = 0;
            if (!TryReadSshString(keyBlob, ref kbOff, out var keyTypeBytes))
            {
                error = "Invalid publickey blob (missing key type string)";
                return false;
            }

            var keyType = AsciiString(keyTypeBytes, 64);
            if (keyType == null)
            {
                error = "Invalid publickey blob key type (non-ASCII or too long)";
                return false;
            }

            if (!IsAlgConsistentWithKeyType(alg, keyType))
            {
                error = $"Algorithm/key type mismatch: alg={alg}, keyType={keyType}";
                return false;
            }

            // Strict: no trailing bytes
            if (off != buf.Length)
            {
                error = $"Unexpected trailing data: {buf.Length - off} bytes";
                return false;
            }

            parsed = new Parsed
            {
                SessionIdLength = sessionId.Length,
                Username = username,
                Service = service,
                Method = method,
                PublicKeyAlgorithm = alg,
                PublicKeyBlobType = keyType,
                PublicKeyBlobLength = keyBlob.Length
            };

            return true;
        }

        private static bool IsAlgConsistentWithKeyType(string alg, string keyType)
        {
            if (alg == "ssh-ed25519") return keyType == "ssh-ed25519";
            if (alg == "rsa-sha2-256" || alg == "rsa-sha2-512") return keyType == "ssh-rsa";
            if (alg.StartsWith("ecdsa-sha2-nistp", StringComparison.Ordinal)) return keyType == alg;
            return false;
        }

        private static bool TryReadByte(byte[] buf, ref int off, out byte b)
        {
            b = 0;
            if (off >= buf.Length) return false;
            b = buf[off++];
            return true;
        }

        private static bool TryReadU32(byte[] buf, ref int off, out uint v)
        {
            v = 0;
            if (off + 4 > buf.Length) return false;
            v = (uint)(buf[off] << 24 | buf[off + 1] << 16 | buf[off + 2] << 8 | buf[off + 3]);
            off += 4;
            return true;
        }

        // SSH "string" = uint32 len + len bytes
        private static bool TryReadSshString(byte[] buf, ref int off, out byte[] s)
        {
            s = null;
            if (!TryReadU32(buf, ref off, out var len)) return false;
            if (len > (uint)(buf.Length - off)) return false;

            s = new byte[(int)len];
            Buffer.BlockCopy(buf, off, s, 0, (int)len);
            off += (int)len;
            return true;
        }

        private static bool TryReadSshAscii(byte[] buf, ref int off, int maxLen, out string value, out string error)
        {
            value = "";
            error = "";

            if (!TryReadSshString(buf, ref off, out var bytes))
            {
                error = "Invalid SSH string field";
                return false;
            }

            if (bytes.Length == 0 || bytes.Length > maxLen)
            {
                error = $"Invalid field length: {bytes.Length} (max {maxLen})";
                return false;
            }

            var s = AsciiString(bytes, maxLen);
            if (s == null)
            {
                error = "Field contains non-ASCII or control characters";
                return false;
            }

            value = s;
            return true;
        }

        private static string AsciiString(byte[] bytes, int maxLen)
        {
            if (bytes.Length == 0 || bytes.Length > maxLen) return null;

            for (int i = 0; i < bytes.Length; i++)
            {
                byte c = bytes[i];
                if (c < 0x20 || c > 0x7E) return null;
            }

            return Encoding.ASCII.GetString(bytes);
        }
    }
}`,
  parameters: [] as TemplateParameter[],
  createdBy: "system",
};

// Seed or update default template
async function seedDefaultTemplate() {
  try {
    const result = await pool.query(
      `SELECT id, cs_code FROM policy_templates WHERE name = $1 AND created_by = 'system'`,
      [DEFAULT_SSH_TEMPLATE.name]
    );
    const existingTemplate = result.rows[0] as { id: string; cs_code: string } | undefined;

    if (!existingTemplate) {
      const id = randomUUID();
      const now = Math.floor(Date.now() / 1000);
      await pool.query(
        `INSERT INTO policy_templates (id, name, description, cs_code, parameters, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, DEFAULT_SSH_TEMPLATE.name, DEFAULT_SSH_TEMPLATE.description, DEFAULT_SSH_TEMPLATE.csCode, JSON.stringify(DEFAULT_SSH_TEMPLATE.parameters), DEFAULT_SSH_TEMPLATE.createdBy, now]
      );
    } else if (existingTemplate.cs_code !== DEFAULT_SSH_TEMPLATE.csCode) {
      const now = Math.floor(Date.now() / 1000);
      await pool.query(
        `UPDATE policy_templates SET cs_code = $1, description = $2, parameters = $3, updated_at = $4 WHERE id = $5`,
        [DEFAULT_SSH_TEMPLATE.csCode, DEFAULT_SSH_TEMPLATE.description, JSON.stringify(DEFAULT_SSH_TEMPLATE.parameters), now, existingTemplate.id]
      );
    }
  } catch {
    // Ignore seeding errors
  }
}

// Run all initialization
const dbReady = (async () => {
  await initializeDatabase();
  await seedDefaultBridge();
  await seedDefaultTemplate();
})();

// Helper to ensure DB is initialized before queries
async function ensureDb() {
  await dbReady;
}

export class SQLiteStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    await ensureDb();
    const [result] = await db.select().from(users).where(eq(users.id, id));
    return result;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    await ensureDb();
    const [result] = await db.select().from(users).where(eq(users.username, username));
    return result;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    await ensureDb();
    const id = randomUUID();
    const user: User = {
      id,
      username: insertUser.username,
      email: insertUser.email,
      role: insertUser.role ?? "user",
      allowedServers: (insertUser.allowedServers ?? []) as string[],
    };
    await db.insert(users).values(user);
    return user;
  }

  async getUsers(): Promise<User[]> {
    await ensureDb();
    return db.select().from(users);
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    await ensureDb();
    const existing = await this.getUser(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    await db.update(users).set(updated).where(eq(users.id, id));
    return updated;
  }

  async getServers(): Promise<Server[]> {
    await ensureDb();
    return db.select().from(servers);
  }

  async getServer(id: string): Promise<Server | undefined> {
    await ensureDb();
    const [result] = await db.select().from(servers).where(eq(servers.id, id));
    return result;
  }

  async getServersByIds(ids: string[]): Promise<Server[]> {
    await ensureDb();
    if (ids.length === 0) return [];
    return db.select().from(servers).where(inArray(servers.id, ids));
  }

  async createServer(insertServer: InsertServer): Promise<Server> {
    await ensureDb();
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
      bridgeId: insertServer.bridgeId ?? null,
    };
    await db.insert(servers).values(server);
    return server;
  }

  async updateServer(id: string, data: Partial<Server>): Promise<Server | undefined> {
    await ensureDb();
    const existing = await this.getServer(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    await db.update(servers).set(updated).where(eq(servers.id, id));
    return updated;
  }

  async deleteServer(id: string): Promise<boolean> {
    await ensureDb();
    const result = await db.delete(servers).where(eq(servers.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  async getSessions(): Promise<Session[]> {
    await ensureDb();
    return db.select().from(sessions).orderBy(desc(sessions.startedAt));
  }

  async getSession(id: string): Promise<Session | undefined> {
    await ensureDb();
    const [result] = await db.select().from(sessions).where(eq(sessions.id, id));
    return result;
  }

  async getSessionsByUserId(userId: string): Promise<Session[]> {
    await ensureDb();
    return db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId))
      .orderBy(desc(sessions.startedAt));
  }

  async createSession(insertSession: InsertSession): Promise<Session> {
    await ensureDb();
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
    await db.insert(sessions).values(session);
    return session;
  }

  async updateSession(id: string, data: Partial<Session>): Promise<Session | undefined> {
    await ensureDb();
    const existing = await this.getSession(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...data, id };
    await db.update(sessions).set(updated).where(eq(sessions.id, id));
    return updated;
  }

  async endSession(id: string): Promise<boolean> {
    await ensureDb();
    const result = await db
      .update(sessions)
      .set({ status: "completed", endedAt: new Date() })
      .where(eq(sessions.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  /**
   * Clean up stale sessions that have been "active" for longer than the given
   * threshold. This catches ghost sessions left behind when browsers crash or
   * network drops prevent normal cleanup.
   */
  async cleanupStaleSessions(maxAgeMs: number = 24 * 60 * 60 * 1000): Promise<number> {
    await ensureDb();
    const cutoff = new Date(Date.now() - maxAgeMs);
    const result = await db
      .update(sessions)
      .set({ status: "completed", endedAt: new Date() })
      .where(and(eq(sessions.status, "active"), lt(sessions.startedAt, cutoff)));
    return result.rowCount ?? 0;
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
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM pending_approvals WHERE status = 'pending' ORDER BY created_at DESC`
    );
    const rows = result.rows;

    return Promise.all(rows.map(async (row: any) => {
      const approversResult = await pool.query(
        `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 1`,
        [row.id]
      );

      const deniersResult = await pool.query(
        `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 0`,
        [row.id]
      );

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
        approvedBy: approversResult.rows.map((a: any) => a.user_vuid),
        deniedBy: deniersResult.rows.map((d: any) => d.user_vuid),
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
    await ensureDb();
    const id = randomUUID();
    await pool.query(
      `INSERT INTO pending_approvals (id, type, requested_by, target_user_id, target_user_email, data, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
      [id, type, requestedBy, targetUserId, targetUserEmail, JSON.stringify(data)]
    );

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
    await ensureDb();
    try {
      await pool.query(
        `INSERT INTO approval_decisions (approval_id, user_vuid, user_email, decision)
         VALUES ($1, $2, $3, $4)`,
        [approvalId, userVuid, userEmail, approved ? 1 : 0]
      );

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
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM approval_decisions WHERE approval_id = $1 AND user_vuid = $2`,
      [approvalId, userVuid]
    );
    return (result.rowCount ?? 0) > 0;
  }

  // Commit an approval (mark as committed)
  async commitApproval(id: string, userEmail: string): Promise<boolean> {
    await ensureDb();
    const result = await pool.query(
      `UPDATE pending_approvals SET status = 'committed', updated_at = EXTRACT(EPOCH FROM NOW())::INTEGER
       WHERE id = $1 AND status = 'pending'`,
      [id]
    );

    if ((result.rowCount ?? 0) > 0) {
      await this.addAccessChangeLog('committed', id, userEmail);
    }

    return (result.rowCount ?? 0) > 0;
  }

  // Cancel an approval request
  async cancelApproval(id: string, userEmail: string): Promise<boolean> {
    await ensureDb();
    const result = await pool.query(
      `UPDATE pending_approvals SET status = 'cancelled', updated_at = EXTRACT(EPOCH FROM NOW())::INTEGER
       WHERE id = $1 AND status = 'pending'`,
      [id]
    );

    if ((result.rowCount ?? 0) > 0) {
      await this.addAccessChangeLog('cancelled', id, userEmail);
    }

    return (result.rowCount ?? 0) > 0;
  }

  // Delete an approval request
  async deleteApproval(id: string, userEmail: string): Promise<boolean> {
    await ensureDb();
    // First get the approval to log target user
    const approvalResult = await pool.query(
      `SELECT target_user_email FROM pending_approvals WHERE id = $1`,
      [id]
    );
    const approval = approvalResult.rows[0] as { target_user_email?: string } | undefined;

    const result = await pool.query(
      `DELETE FROM pending_approvals WHERE id = $1`,
      [id]
    );

    if ((result.rowCount ?? 0) > 0) {
      await this.addAccessChangeLog('deleted', id, userEmail, approval?.target_user_email);
    }

    return (result.rowCount ?? 0) > 0;
  }

  // Get approval by ID
  async getApproval(id: string): Promise<PendingApproval | undefined> {
    await ensureDb();
    const rowResult = await pool.query(
      `SELECT * FROM pending_approvals WHERE id = $1`,
      [id]
    );
    const row = rowResult.rows[0] as any | undefined;

    if (!row) return undefined;

    const approversResult = await pool.query(
      `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 1`,
      [id]
    );

    const deniersResult = await pool.query(
      `SELECT user_vuid FROM approval_decisions WHERE approval_id = $1 AND decision = 0`,
      [id]
    );

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
      approvedBy: approversResult.rows.map((a: any) => a.user_vuid),
      deniedBy: deniersResult.rows.map((d: any) => d.user_vuid),
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
    await ensureDb();
    await pool.query(
      `INSERT INTO access_change_logs (type, approval_id, user_email, target_user, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [type, approvalId, userEmail, targetUser, details]
    );
  }

  // Get access change logs
  async getAccessChangeLogs(limit: number = 100, offset: number = 0): Promise<AccessChangeLog[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM access_change_logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return result.rows.map((row: any) => ({
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
    await ensureDb();
    const existing = await this.getPolicy(policy.roleId);

    if (existing) {
      await pool.query(
        `UPDATE ssh_policies
         SET contract_type = $1, approval_type = $2, execution_type = $3, threshold = $4, policy_data = $5, updated_at = EXTRACT(EPOCH FROM NOW())::INTEGER
         WHERE role_id = $6`,
        [policy.contractType, policy.approvalType, policy.executionType, policy.threshold, policy.policyData || null, policy.roleId]
      );

      return {
        ...policy,
        createdAt: existing.createdAt,
        updatedAt: Math.floor(Date.now() / 1000),
      };
    } else {
      await pool.query(
        `INSERT INTO ssh_policies (role_id, contract_type, approval_type, execution_type, threshold, policy_data)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [policy.roleId, policy.contractType, policy.approvalType, policy.executionType, policy.threshold, policy.policyData || null]
      );

      return {
        ...policy,
        createdAt: Math.floor(Date.now() / 1000),
      };
    }
  }

  // Get policy by role ID
  async getPolicy(roleId: string): Promise<SshPolicy | undefined> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM ssh_policies WHERE role_id = $1`,
      [roleId]
    );
    const row = result.rows[0] as any | undefined;

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
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM ssh_policies ORDER BY created_at DESC`
    );

    return result.rows.map((row: any) => ({
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
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM ssh_policies WHERE role_id = $1`,
      [roleId]
    );
    return (result.rowCount ?? 0) > 0;
  }
}

// Pending SSH Policy types
export interface PendingSshPolicy {
  id: string;
  roleId: string;
  requestedBy: string;
  requestedByEmail?: string;
  policyRequestData: string;
  contractCode?: string;
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
  contractCode?: string;
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
    await ensureDb();
    await pool.query(
      `INSERT INTO pending_ssh_policies (id, role_id, requested_by, requested_by_email, policy_request_data, contract_code, threshold)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [policy.id, policy.roleId, policy.requestedBy, policy.requestedByEmail || null, policy.policyRequestData, policy.contractCode || null, policy.threshold || 1]
    );

    // Log the creation with approval_count=0 at time of creation
    const threshold = policy.threshold || 1;
    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, details, status, approval_count, threshold)
       VALUES ('created', $1, $2, $3, $4, 'pending', 0, $5)`,
      [policy.id, policy.requestedByEmail || policy.requestedBy, policy.roleId, JSON.stringify({ threshold }), threshold]
    );

    return {
      ...policy,
      status: "pending",
      threshold: policy.threshold || 1,
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  // Get pending policy by ID
  async getPendingPolicy(id: string): Promise<PendingSshPolicy | undefined> {
    await ensureDb();
    const result = await pool.query(
      `SELECT p.*,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approval_count,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as rejection_count
       FROM pending_ssh_policies p WHERE p.id = $1`,
      [id]
    );
    const row = result.rows[0] as any | undefined;

    if (!row) return undefined;

    return {
      id: row.id,
      roleId: row.role_id,
      requestedBy: row.requested_by,
      requestedByEmail: row.requested_by_email,
      policyRequestData: row.policy_request_data,
      contractCode: row.contract_code,
      status: row.status as "pending" | "approved" | "committed" | "cancelled",
      threshold: row.threshold,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      approvalCount: parseInt(row.approval_count),
      rejectionCount: parseInt(row.rejection_count),
    };
  }

  // Get all pending policies (not yet committed or cancelled)
  // For commit-ready policies, adds the admin policy to the request (required for Ork commit)
  async getAllPendingPolicies(): Promise<PendingSshPolicy[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT p.*,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approval_count,
        (SELECT COUNT(*) FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as rejection_count,
        (SELECT STRING_AGG(user_vuid, ',') FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 1) as approved_by,
        (SELECT STRING_AGG(user_vuid, ',') FROM ssh_policy_decisions d WHERE d.policy_request_id = p.id AND d.decision = 0) as denied_by
       FROM pending_ssh_policies p
       WHERE p.status IN ('pending', 'approved')
       ORDER BY p.created_at DESC`
    );
    const rows = result.rows;

    // Fetch admin policy from TideCloak (needed to authorize commits)
    let adminPolicyBytes: Uint8Array | null = null;
    try {
      const adminPolicyBase64 = await getAdminPolicy();
      adminPolicyBytes = base64ToBytes(adminPolicyBase64);
    } catch (error) {
      console.error("Failed to fetch admin policy:", error);
      // Continue without admin policy - commits will fail but approvals still work
    }

    const policies = await Promise.all(rows.map(async (row: any) => {
      const isCommitReady = (parseInt(row.approval_count) || 0) >= row.threshold;
      let policyRequestData = row.policy_request_data;

      // If commit-ready and we have admin policy, add it to the request
      if (isCommitReady && adminPolicyBytes) {
        try {
          const request = PolicySignRequest.decode(base64ToBytes(policyRequestData));
          // Add the admin policy to authorize the commit
          request.addPolicy(adminPolicyBytes);
          const updatedData = bytesToBase64(request.encode());

          // Update the request in the database with admin policy attached
          await pool.query(
            `UPDATE pending_ssh_policies SET policy_request_data = $1 WHERE id = $2`,
            [updatedData, row.id]
          );

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
        contractCode: row.contract_code,
        status: row.status as "pending" | "approved" | "committed" | "cancelled",
        threshold: row.threshold,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        approvalCount: parseInt(row.approval_count) || 0,
        rejectionCount: parseInt(row.rejection_count) || 0,
        approvedBy: row.approved_by ? row.approved_by.split(',') : [],
        deniedBy: row.denied_by ? row.denied_by.split(',') : [],
        commitReady: isCommitReady,
      };
    }));

    return policies;
  }

  // Add approval/rejection decision
  async addDecision(decision: Omit<SshPolicyDecision, "createdAt">): Promise<void> {
    await ensureDb();
    // Insert or update decision
    await pool.query(
      `INSERT INTO ssh_policy_decisions (policy_request_id, user_vuid, user_email, decision)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT(policy_request_id, user_vuid) DO UPDATE SET decision = EXCLUDED.decision, created_at = EXTRACT(EPOCH FROM NOW())::INTEGER`,
      [decision.policyRequestId, decision.userVuid, decision.userEmail, decision.decision]
    );

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
    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [logType, decision.policyRequestId, decision.userEmail, policy?.roleId || null, statusAfterAction, approvalCount, threshold]
    );
  }

  // Update policy status
  async updateStatus(id: string, status: "pending" | "approved" | "committed" | "cancelled"): Promise<void> {
    await ensureDb();
    await pool.query(
      `UPDATE pending_ssh_policies SET status = $1, updated_at = EXTRACT(EPOCH FROM NOW())::INTEGER WHERE id = $2`,
      [status, id]
    );
  }

  // Get decisions for a policy
  async getDecisions(policyRequestId: string): Promise<SshPolicyDecision[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM ssh_policy_decisions WHERE policy_request_id = $1 ORDER BY created_at DESC`,
      [policyRequestId]
    );

    return result.rows.map((row: any) => ({
      policyRequestId: row.policy_request_id,
      userVuid: row.user_vuid,
      userEmail: row.user_email,
      decision: row.decision as 0 | 1,
      createdAt: row.created_at,
    }));
  }

  // Check if user has already voted
  async hasUserVoted(policyRequestId: string, userVuid: string): Promise<boolean> {
    await ensureDb();
    const result = await pool.query(
      `SELECT 1 FROM ssh_policy_decisions WHERE policy_request_id = $1 AND user_vuid = $2`,
      [policyRequestId, userVuid]
    );
    return result.rows.length > 0;
  }

  // Get user's decision (returns 1 for approval, 0 for rejection, null if no decision)
  async getUserDecision(policyRequestId: string, userVuid: string): Promise<number | null> {
    await ensureDb();
    const result = await pool.query(
      `SELECT decision FROM ssh_policy_decisions WHERE policy_request_id = $1 AND user_vuid = $2`,
      [policyRequestId, userVuid]
    );
    const row = result.rows[0] as { decision: number } | undefined;
    return row ? row.decision : null;
  }

  // Update the policy request data (used to store signed/approved request)
  async updatePolicyRequest(id: string, policyRequestData: string): Promise<void> {
    await ensureDb();
    await pool.query(
      `UPDATE pending_ssh_policies SET policy_request_data = $1 WHERE id = $2`,
      [policyRequestData, id]
    );
  }

  // Revoke a user's decision (remove their vote) - matches ideed-swarm's RemovePolicyApproval
  async revokeDecision(policyRequestId: string, userVuid: string): Promise<boolean> {
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM ssh_policy_decisions WHERE policy_request_id = $1 AND user_vuid = $2`,
      [policyRequestId, userVuid]
    );
    return (result.rowCount ?? 0) > 0;
  }

  // Commit a policy (after approval threshold is met)
  async commitPolicy(id: string, userEmail: string): Promise<void> {
    await ensureDb();
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");
    if (policy.status !== "approved") throw new Error("Policy not approved yet");

    await this.updateStatus(id, "committed");

    // Log the commit with status and counts at time of action
    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
       VALUES ('committed', $1, $2, $3, 'committed', $4, $5)`,
      [id, userEmail, policy.roleId, policy.approvalCount || 0, policy.threshold]
    );
  }

  // Cancel a pending policy
  async cancelPolicy(id: string, userEmail: string): Promise<void> {
    await ensureDb();
    const policy = await this.getPendingPolicy(id);
    if (!policy) throw new Error("Policy not found");

    await this.updateStatus(id, "cancelled");

    // Log the cancellation with status and counts at time of action
    await pool.query(
      `INSERT INTO ssh_policy_logs (type, policy_request_id, user_email, role_id, status, approval_count, threshold)
       VALUES ('cancelled', $1, $2, $3, 'cancelled', $4, $5)`,
      [id, userEmail, policy.roleId, policy.approvalCount || 0, policy.threshold]
    );
  }

  // Get policy logs (full audit trail showing all actions)
  async getLogs(limit: number = 100, offset: number = 0): Promise<any[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT
        l.*,
        p.created_at as policy_created_at,
        p.requested_by_email as policy_requested_by
       FROM ssh_policy_logs l
       LEFT JOIN pending_ssh_policies p ON l.policy_request_id = p.id
       ORDER BY l.timestamp DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return result.rows.map((row: any) => ({
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
    await ensureDb();
    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    await pool.query(
      `INSERT INTO policy_templates (id, name, description, cs_code, parameters, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [id, template.name, template.description, template.csCode, JSON.stringify(template.parameters), template.createdBy, now]
    );

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
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM policy_templates WHERE id = $1`,
      [id]
    );
    const row = result.rows[0] as any | undefined;

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
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM policy_templates WHERE name = $1`,
      [name]
    );
    const row = result.rows[0] as any | undefined;

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
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM policy_templates ORDER BY created_at DESC`
    );

    return result.rows.map((row: any) => ({
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
    await ensureDb();
    const existing = await this.getTemplate(id);
    if (!existing) return undefined;

    const updates: string[] = [];
    const values: any[] = [];
    let paramIdx = 1;

    if (data.name !== undefined) {
      updates.push(`name = $${paramIdx++}`);
      values.push(data.name);
    }
    if (data.description !== undefined) {
      updates.push(`description = $${paramIdx++}`);
      values.push(data.description);
    }
    if (data.csCode !== undefined) {
      updates.push(`cs_code = $${paramIdx++}`);
      values.push(data.csCode);
    }
    if (data.parameters !== undefined) {
      updates.push(`parameters = $${paramIdx++}`);
      values.push(JSON.stringify(data.parameters));
    }

    if (updates.length > 0) {
      updates.push(`updated_at = $${paramIdx++}`);
      values.push(Math.floor(Date.now() / 1000));
      values.push(id);

      await pool.query(
        `UPDATE policy_templates SET ${updates.join(', ')} WHERE id = $${paramIdx}`,
        values
      );
    }

    return this.getTemplate(id);
  }

  // Delete a template
  async deleteTemplate(id: string): Promise<boolean> {
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM policy_templates WHERE id = $1`,
      [id]
    );
    return (result.rowCount ?? 0) > 0;
  }
}

// Subscription storage class for license management
export class SubscriptionStorage {
  // Get the current subscription (there's only one per installation)
  async getSubscription(): Promise<Subscription | null> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM subscriptions ORDER BY created_at DESC LIMIT 1`
    );
    const row = result.rows[0] as any | undefined;

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
    await ensureDb();
    const existing = await this.getSubscription();
    const now = Math.floor(Date.now() / 1000);

    if (existing) {
      // Update existing subscription
      const updates: string[] = [];
      const values: any[] = [];
      let paramIdx = 1;

      if (data.tier !== undefined) {
        updates.push(`tier = $${paramIdx++}`);
        values.push(data.tier);
      }
      if (data.stripeCustomerId !== undefined) {
        updates.push(`stripe_customer_id = $${paramIdx++}`);
        values.push(data.stripeCustomerId);
      }
      if (data.stripeSubscriptionId !== undefined) {
        updates.push(`stripe_subscription_id = $${paramIdx++}`);
        values.push(data.stripeSubscriptionId);
      }
      if (data.stripePriceId !== undefined) {
        updates.push(`stripe_price_id = $${paramIdx++}`);
        values.push(data.stripePriceId);
      }
      if (data.status !== undefined) {
        updates.push(`status = $${paramIdx++}`);
        values.push(data.status);
      }
      if (data.currentPeriodEnd !== undefined) {
        updates.push(`current_period_end = $${paramIdx++}`);
        values.push(data.currentPeriodEnd);
      }
      if (data.cancelAtPeriodEnd !== undefined) {
        updates.push(`cancel_at_period_end = $${paramIdx++}`);
        values.push(data.cancelAtPeriodEnd);
      }

      if (updates.length > 0) {
        updates.push(`updated_at = $${paramIdx++}`);
        values.push(now);
        values.push(existing.id);

        await pool.query(
          `UPDATE subscriptions SET ${updates.join(', ')} WHERE id = $${paramIdx}`,
          values
        );
      }

      return (await this.getSubscription())!;
    } else {
      // Create new subscription
      const id = randomUUID();
      await pool.query(
        `INSERT INTO subscriptions (id, tier, stripe_customer_id, stripe_subscription_id, stripe_price_id, status, current_period_end, cancel_at_period_end, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          id,
          data.tier || 'free',
          data.stripeCustomerId || null,
          data.stripeSubscriptionId || null,
          data.stripePriceId || null,
          data.status || 'active',
          data.currentPeriodEnd || null,
          data.cancelAtPeriodEnd || false,
          now
        ]
      );

      return (await this.getSubscription())!;
    }
  }

  // Get current usage counts
  async getUsageCounts(): Promise<{ users: number; servers: number }> {
    await ensureDb();
    // Count servers from local database
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM servers`
    );

    // Note: Users are counted from TideCloak, not local DB
    // This method returns server count; user count comes from TideCloak API
    return {
      users: 0, // Will be filled from TideCloak
      servers: parseInt(result.rows[0].count),
    };
  }

  // Get server count only (for limit checks)
  async getServerCount(): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM servers`
    );
    return parseInt(result.rows[0].count);
  }

  // Get enabled server count
  async getEnabledServerCount(): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM servers WHERE enabled = TRUE`
    );
    return parseInt(result.rows[0].count);
  }

  // Get server counts (total and enabled)
  async getServerCounts(): Promise<{ total: number; enabled: number }> {
    await ensureDb();
    const result = await pool.query(
      `SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE enabled = TRUE) as enabled
       FROM servers`
    );
    return { total: parseInt(result.rows[0].total), enabled: parseInt(result.rows[0].enabled) || 0 };
  }

  // Check if can add a resource (user or server)
  async checkCanAdd(resource: 'user' | 'server', currentCount: number): Promise<LimitCheck> {
    await ensureDb();
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
    await ensureDb();
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
    await ensureDb();
    const subscription = await this.getSubscription();
    if (!subscription) return;

    await pool.query(
      `UPDATE subscriptions SET users_over_limit = $1, servers_over_limit = $2 WHERE id = $3`,
      [usersOverLimit, serversOverLimit, subscription.id]
    );
  }

  // Check if SSH access is blocked due to being over limit
  async isSshBlocked(): Promise<{ blocked: boolean; reason?: string }> {
    await ensureDb();
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
    const result = await pool.query(
      `SELECT users_over_limit FROM subscriptions WHERE id = $1`,
      [subscription.id]
    );
    const row = result.rows[0] as { users_over_limit: boolean } | undefined;

    const usersOverLimit = row?.users_over_limit === true;

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
    await ensureDb();
    const subscription = await this.getSubscription();
    if (!subscription) return;

    const id = randomUUID();
    const now = Math.floor(Date.now() / 1000);

    await pool.query(
      `INSERT INTO billing_history (id, subscription_id, stripe_invoice_id, amount, currency, status, invoice_pdf, description, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        id,
        subscription.id,
        data.stripeInvoiceId || null,
        data.amount,
        data.currency || 'usd',
        data.status,
        data.invoicePdf || null,
        data.description || null,
        now
      ]
    );
  }

  // Get billing history
  async getBillingHistory(limit: number = 50): Promise<BillingHistory[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM billing_history ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );

    return result.rows.map((row: any) => ({
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
    await ensureDb();
    const id = randomUUID();
    const now = new Date();

    await pool.query(
      `INSERT INTO recordings (id, session_id, server_id, server_name, user_id, user_email, ssh_user, started_at, terminal_width, terminal_height)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
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
      ]
    );

    return {
      id,
      sessionId: data.sessionId,
      serverId: data.serverId,
      serverName: data.serverName,
      userId: data.userId,
      userEmail: data.userEmail,
      sshUser: data.sshUser,
      startedAt: now,
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
    await ensureDb();
    await pool.query(
      `UPDATE recordings SET data = data || $1, file_size = file_size + $2 WHERE id = $3`,
      [eventData, Buffer.byteLength(eventData, 'utf8'), id]
    );
  }

  // Append text content for searchability
  async appendTextContent(id: string, text: string): Promise<void> {
    await ensureDb();
    await pool.query(
      `UPDATE recordings SET text_content = text_content || $1 WHERE id = $2`,
      [text, id]
    );
  }

  // Finalize a recording (set end time and calculate duration)
  async finalizeRecording(id: string): Promise<void> {
    await ensureDb();
    const now = new Date();

    // Get start time to calculate duration
    const result = await pool.query(
      `SELECT started_at FROM recordings WHERE id = $1`,
      [id]
    );
    const row = result.rows[0] as { started_at: Date } | undefined;

    if (row) {
      const duration = Math.floor((now.getTime() - new Date(row.started_at).getTime()) / 1000);
      await pool.query(
        `UPDATE recordings SET ended_at = $1, duration = $2 WHERE id = $3`,
        [now, duration, id]
      );
    }
  }

  // Get recording by ID
  async getRecording(id: string): Promise<Recording | undefined> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM recordings WHERE id = $1`,
      [id]
    );
    const row = result.rows[0] as any | undefined;

    if (!row) return undefined;

    return this.mapRow(row);
  }

  // Get recording by session ID
  async getRecordingBySessionId(sessionId: string): Promise<Recording | undefined> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM recordings WHERE session_id = $1`,
      [sessionId]
    );
    const row = result.rows[0] as any | undefined;

    if (!row) return undefined;

    return this.mapRow(row);
  }

  // Get all recordings (paginated)
  async getRecordings(limit: number = 50, offset: number = 0): Promise<Recording[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM recordings ORDER BY started_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get recordings by server ID
  async getRecordingsByServer(serverId: string, limit: number = 50): Promise<Recording[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM recordings WHERE server_id = $1 ORDER BY started_at DESC LIMIT $2`,
      [serverId, limit]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get recordings by user ID
  async getRecordingsByUser(userId: string, limit: number = 50): Promise<Recording[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM recordings WHERE user_id = $1 ORDER BY started_at DESC LIMIT $2`,
      [userId, limit]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Search recordings by text content
  async searchRecordings(query: string, limit: number = 50): Promise<Recording[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM recordings WHERE text_content LIKE $1 ORDER BY started_at DESC LIMIT $2`,
      [`%${query}%`, limit]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get recording count
  async getRecordingCount(): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM recordings`
    );
    return parseInt(result.rows[0].count);
  }

  // Get total storage used by recordings
  async getTotalStorageBytes(): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `SELECT COALESCE(SUM(file_size), 0) as total FROM recordings`
    );
    return parseInt(result.rows[0].total);
  }

  // Delete a recording
  async deleteRecording(id: string): Promise<boolean> {
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM recordings WHERE id = $1`,
      [id]
    );
    return (result.rowCount ?? 0) > 0;
  }

  // Delete recordings older than a certain date
  async deleteRecordingsOlderThan(date: Date): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM recordings WHERE started_at < $1`,
      [date]
    );
    return result.rowCount ?? 0;
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
      startedAt: new Date(row.started_at),
      endedAt: row.ended_at ? new Date(row.ended_at) : null,
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
    await ensureDb();
    const id = randomUUID();
    const now = new Date();

    await pool.query(
      `INSERT INTO file_operations (id, session_id, server_id, user_id, user_email, ssh_user, operation, path, target_path, file_size, mode, status, error_message, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      [
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
      ]
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
      timestamp: now,
    };
  }

  // Get file operations by session ID
  async getOperationsBySession(sessionId: string): Promise<FileOperation[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM file_operations WHERE session_id = $1 ORDER BY timestamp DESC`,
      [sessionId]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get file operations by server ID
  async getOperationsByServer(serverId: string, limit: number = 100): Promise<FileOperation[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM file_operations WHERE server_id = $1 ORDER BY timestamp DESC LIMIT $2`,
      [serverId, limit]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get file operations by user ID
  async getOperationsByUser(userId: string, limit: number = 100): Promise<FileOperation[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM file_operations WHERE user_id = $1 ORDER BY timestamp DESC LIMIT $2`,
      [userId, limit]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get all file operations (paginated)
  async getOperations(limit: number = 100, offset: number = 0): Promise<FileOperation[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM file_operations ORDER BY timestamp DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get operation count
  async getOperationCount(): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM file_operations`
    );
    return parseInt(result.rows[0].count);
  }

  // Delete operations older than a certain date
  async deleteOperationsOlderThan(date: Date): Promise<number> {
    await ensureDb();
    const result = await pool.query(
      `DELETE FROM file_operations WHERE timestamp < $1`,
      [date]
    );
    return result.rowCount ?? 0;
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
      timestamp: new Date(row.timestamp),
    };
  }
}

// Bridge storage class for SSH bridge/relay endpoints
export class BridgeStorage {
  // Create a new bridge
  async createBridge(data: InsertBridge): Promise<Bridge> {
    await ensureDb();
    const id = randomUUID();
    const now = new Date();

    // If this bridge is being set as default, unset any existing default
    if (data.isDefault) {
      await pool.query(`UPDATE bridges SET is_default = FALSE`);
    }

    await pool.query(
      `INSERT INTO bridges (id, name, url, description, enabled, is_default, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        id,
        data.name,
        data.url,
        data.description || null,
        data.enabled !== false,
        data.isDefault || false,
        now
      ]
    );

    return {
      id,
      name: data.name,
      url: data.url,
      description: data.description || null,
      enabled: data.enabled !== false,
      isDefault: data.isDefault || false,
      createdAt: now,
    };
  }

  // Get bridge by ID
  async getBridge(id: string): Promise<Bridge | undefined> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM bridges WHERE id = $1`,
      [id]
    );
    const row = result.rows[0] as any | undefined;

    if (!row) return undefined;

    return this.mapRow(row);
  }

  // Get the default bridge
  async getDefaultBridge(): Promise<Bridge | undefined> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM bridges WHERE is_default = TRUE AND enabled = TRUE LIMIT 1`
    );
    const row = result.rows[0] as any | undefined;

    if (!row) return undefined;

    return this.mapRow(row);
  }

  // Get all bridges
  async getBridges(): Promise<Bridge[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM bridges ORDER BY is_default DESC, name ASC`
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Get enabled bridges
  async getEnabledBridges(): Promise<Bridge[]> {
    await ensureDb();
    const result = await pool.query(
      `SELECT * FROM bridges WHERE enabled = TRUE ORDER BY is_default DESC, name ASC`
    );

    return result.rows.map((row: any) => this.mapRow(row));
  }

  // Update a bridge
  async updateBridge(id: string, data: Partial<InsertBridge>): Promise<Bridge | undefined> {
    await ensureDb();
    const existing = await this.getBridge(id);
    if (!existing) return undefined;

    const updates: string[] = [];
    const values: any[] = [];
    let paramIdx = 1;

    if (data.name !== undefined) {
      updates.push(`name = $${paramIdx++}`);
      values.push(data.name);
    }
    if (data.url !== undefined) {
      updates.push(`url = $${paramIdx++}`);
      values.push(data.url);
    }
    if (data.description !== undefined) {
      updates.push(`description = $${paramIdx++}`);
      values.push(data.description || null);
    }
    if (data.enabled !== undefined) {
      updates.push(`enabled = $${paramIdx++}`);
      values.push(data.enabled);
    }
    if (data.isDefault !== undefined) {
      // If setting as default, unset any existing default first
      if (data.isDefault) {
        await pool.query(`UPDATE bridges SET is_default = FALSE`);
      }
      updates.push(`is_default = $${paramIdx++}`);
      values.push(data.isDefault);
    }

    if (updates.length > 0) {
      values.push(id);
      await pool.query(
        `UPDATE bridges SET ${updates.join(', ')} WHERE id = $${paramIdx}`,
        values
      );
    }

    return this.getBridge(id);
  }

  // Delete a bridge
  async deleteBridge(id: string): Promise<boolean> {
    await ensureDb();
    // First, remove this bridge from any servers using it
    await pool.query(`UPDATE servers SET bridge_id = NULL WHERE bridge_id = $1`, [id]);

    const result = await pool.query(
      `DELETE FROM bridges WHERE id = $1`,
      [id]
    );
    return (result.rowCount ?? 0) > 0;
  }

  // Map database row to Bridge type
  private mapRow(row: any): Bridge {
    return {
      id: row.id,
      name: row.name,
      url: row.url,
      description: row.description,
      enabled: !!row.enabled,
      isDefault: !!row.is_default,
      createdAt: new Date(row.created_at),
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
export const bridgeStorage = new BridgeStorage();
