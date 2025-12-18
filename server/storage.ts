import type { User, InsertUser, Server, InsertServer, Session, InsertSession } from "@shared/schema";
import { randomUUID } from "crypto";

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

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private servers: Map<string, Server>;
  private sessions: Map<string, Session>;

  constructor() {
    this.users = new Map();
    this.servers = new Map();
    this.sessions = new Map();
    this.seedMockData();
  }

  private seedMockData() {
    const mockServers: Server[] = [
      {
        id: "server-1",
        name: "Production Web Server",
        host: "prod-web-01.example.com",
        port: 22,
        environment: "production",
        tags: ["web", "nginx", "critical"],
        enabled: true,
        sshUsers: ["root", "deploy", "www-data"],
      },
      {
        id: "server-2",
        name: "Staging API Server",
        host: "staging-api-01.example.com",
        port: 22,
        environment: "staging",
        tags: ["api", "nodejs"],
        enabled: true,
        sshUsers: ["root", "node", "deploy"],
      },
      {
        id: "server-3",
        name: "Development Database",
        host: "dev-db-01.example.com",
        port: 22,
        environment: "development",
        tags: ["database", "postgres"],
        enabled: true,
        sshUsers: ["root", "postgres"],
      },
      {
        id: "server-4",
        name: "Production Load Balancer",
        host: "prod-lb-01.example.com",
        port: 22,
        environment: "production",
        tags: ["lb", "haproxy", "critical"],
        enabled: true,
        sshUsers: ["root", "admin"],
      },
      {
        id: "server-5",
        name: "Backup Server",
        host: "backup-01.example.com",
        port: 22,
        environment: "production",
        tags: ["backup", "storage"],
        enabled: false,
        sshUsers: ["root", "backup"],
      },
    ];

    const mockUsers: User[] = [
      {
        id: "mock-user-1",
        username: "demo.user",
        email: "demo@keylessh.dev",
        role: "admin",
        allowedServers: ["server-1", "server-2", "server-3", "server-4", "server-5"],
      },
      {
        id: "user-2",
        username: "john.developer",
        email: "john@example.com",
        role: "user",
        allowedServers: ["server-2", "server-3"],
      },
      {
        id: "user-3",
        username: "jane.ops",
        email: "jane@example.com",
        role: "admin",
        allowedServers: ["server-1", "server-2", "server-3", "server-4"],
      },
    ];

    const mockSessions: Session[] = [
      {
        id: "session-1",
        userId: "mock-user-1",
        serverId: "server-1",
        sshUser: "root",
        status: "active",
        startedAt: new Date(Date.now() - 3600000),
        endedAt: null,
      },
      {
        id: "session-2",
        userId: "user-2",
        serverId: "server-2",
        sshUser: "deploy",
        status: "completed",
        startedAt: new Date(Date.now() - 86400000),
        endedAt: new Date(Date.now() - 82800000),
      },
    ];

    mockServers.forEach((s) => this.servers.set(s.id, s));
    mockUsers.forEach((u) => this.users.set(u.id, u));
    mockSessions.forEach((s) => this.sessions.set(s.id, s));
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find((user) => user.username === username);
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async getUsers(): Promise<User[]> {
    return Array.from(this.users.values());
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const user = this.users.get(id);
    if (!user) return undefined;
    const updated = { ...user, ...data, id };
    this.users.set(id, updated);
    return updated;
  }

  async getServers(): Promise<Server[]> {
    return Array.from(this.servers.values());
  }

  async getServer(id: string): Promise<Server | undefined> {
    return this.servers.get(id);
  }

  async getServersByIds(ids: string[]): Promise<Server[]> {
    return ids.map((id) => this.servers.get(id)).filter((s): s is Server => !!s);
  }

  async createServer(insertServer: InsertServer): Promise<Server> {
    const id = randomUUID();
    const server: Server = {
      id,
      name: insertServer.name,
      host: insertServer.host,
      port: insertServer.port ?? 22,
      environment: insertServer.environment ?? "production",
      tags: insertServer.tags ?? [],
      enabled: insertServer.enabled ?? true,
      sshUsers: insertServer.sshUsers ?? [],
    };
    this.servers.set(id, server);
    return server;
  }

  async updateServer(id: string, data: Partial<Server>): Promise<Server | undefined> {
    const server = this.servers.get(id);
    if (!server) return undefined;
    const updated = { ...server, ...data, id };
    this.servers.set(id, updated);
    return updated;
  }

  async deleteServer(id: string): Promise<boolean> {
    return this.servers.delete(id);
  }

  async getSessions(): Promise<Session[]> {
    return Array.from(this.sessions.values()).sort(
      (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    );
  }

  async getSession(id: string): Promise<Session | undefined> {
    return this.sessions.get(id);
  }

  async getSessionsByUserId(userId: string): Promise<Session[]> {
    return Array.from(this.sessions.values())
      .filter((s) => s.userId === userId)
      .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
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
    this.sessions.set(id, session);
    return session;
  }

  async updateSession(id: string, data: Partial<Session>): Promise<Session | undefined> {
    const session = this.sessions.get(id);
    if (!session) return undefined;
    const updated = { ...session, ...data, id };
    this.sessions.set(id, updated);
    return updated;
  }

  async endSession(id: string): Promise<boolean> {
    const session = this.sessions.get(id);
    if (!session) return false;
    session.status = "completed";
    session.endedAt = new Date();
    return true;
  }
}

export const storage = new MemStorage();
