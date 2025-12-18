import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { log } from "./index";
import type { ServerWithAccess, ActiveSession } from "@shared/schema";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws, req) => {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const sessionId = url.searchParams.get("session");
    const token = url.searchParams.get("token");

    log(`WebSocket connection for session ${sessionId}`);

    if (!sessionId) {
      ws.close(1008, "Session ID required");
      return;
    }

    ws.send("\x1b[32mConnected to KeyleSSH Terminal\x1b[0m\r\n");
    ws.send("\x1b[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\r\n");
    ws.send("\r\n");
    ws.send("\x1b[33mThis is a mock terminal session.\x1b[0m\r\n");
    ws.send("\x1b[33mIn production, this would connect to your actual SSH server via KeyleSSH backend.\x1b[0m\r\n");
    ws.send("\r\n");
    ws.send("\x1b[36muser@server\x1b[0m:\x1b[34m~\x1b[0m$ ");

    let commandBuffer = "";

    ws.on("message", (data) => {
      const input = data.toString();
      
      for (const char of input) {
        if (char === "\r" || char === "\n") {
          ws.send("\r\n");
          
          const command = commandBuffer.trim();
          commandBuffer = "";
          
          if (command === "help") {
            ws.send("\x1b[33mAvailable commands:\x1b[0m\r\n");
            ws.send("  help     - Show this help message\r\n");
            ws.send("  whoami   - Show current user\r\n");
            ws.send("  hostname - Show hostname\r\n");
            ws.send("  date     - Show current date\r\n");
            ws.send("  uptime   - Show system uptime\r\n");
            ws.send("  ls       - List files\r\n");
            ws.send("  pwd      - Print working directory\r\n");
            ws.send("  clear    - Clear screen\r\n");
            ws.send("  exit     - Close session\r\n");
          } else if (command === "whoami") {
            ws.send("demo-user\r\n");
          } else if (command === "hostname") {
            ws.send("keylessh-demo-server\r\n");
          } else if (command === "date") {
            ws.send(`${new Date().toUTCString()}\r\n`);
          } else if (command === "uptime") {
            ws.send(" 12:34:56 up 42 days,  3:21,  1 user,  load average: 0.08, 0.12, 0.15\r\n");
          } else if (command === "ls") {
            ws.send("\x1b[34mbin\x1b[0m  \x1b[34mdev\x1b[0m  \x1b[34metc\x1b[0m  \x1b[34mhome\x1b[0m  \x1b[34mlib\x1b[0m  \x1b[34mopt\x1b[0m  \x1b[34mproc\x1b[0m  \x1b[34mroot\x1b[0m  \x1b[34mrun\x1b[0m  \x1b[34msbin\x1b[0m  \x1b[34msrv\x1b[0m  \x1b[34msys\x1b[0m  \x1b[34mtmp\x1b[0m  \x1b[34musr\x1b[0m  \x1b[34mvar\x1b[0m\r\n");
          } else if (command === "pwd") {
            ws.send("/home/demo-user\r\n");
          } else if (command === "clear") {
            ws.send("\x1b[2J\x1b[H");
          } else if (command === "exit") {
            ws.send("\x1b[33mGoodbye!\x1b[0m\r\n");
            ws.close();
            return;
          } else if (command) {
            ws.send(`\x1b[31m${command}: command not found\x1b[0m\r\n`);
          }
          
          if (ws.readyState === WebSocket.OPEN) {
            ws.send("\x1b[36muser@server\x1b[0m:\x1b[34m~\x1b[0m$ ");
          }
        } else if (char === "\x7f") {
          if (commandBuffer.length > 0) {
            commandBuffer = commandBuffer.slice(0, -1);
            ws.send("\b \b");
          }
        } else if (char.charCodeAt(0) >= 32) {
          commandBuffer += char;
          ws.send(char);
        }
      }
    });

    ws.on("close", () => {
      log(`WebSocket closed for session ${sessionId}`);
    });

    ws.on("error", (error) => {
      log(`WebSocket error for session ${sessionId}: ${error.message}`);
    });
  });

  app.get("/api/servers", async (req, res) => {
    try {
      const userId = "mock-user-1";
      const user = await storage.getUser(userId);
      
      if (!user) {
        res.json([]);
        return;
      }

      let servers;
      if (user.role === "admin") {
        servers = await storage.getServers();
      } else {
        servers = await storage.getServersByIds(user.allowedServers || []);
      }

      const serversWithAccess: ServerWithAccess[] = servers.map((server) => ({
        ...server,
        allowedSshUsers: server.sshUsers || [],
      }));

      res.json(serversWithAccess);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch servers" });
    }
  });

  app.get("/api/servers/:id", async (req, res) => {
    try {
      const server = await storage.getServer(req.params.id);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      const serverWithAccess: ServerWithAccess = {
        ...server,
        allowedSshUsers: server.sshUsers || [],
      };

      res.json(serverWithAccess);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch server" });
    }
  });

  app.get("/api/sessions", async (req, res) => {
    try {
      const userId = "mock-user-1";
      const sessions = await storage.getSessionsByUserId(userId);
      const servers = await storage.getServers();
      
      const activeSessions: ActiveSession[] = sessions.map((session) => {
        const server = servers.find((s) => s.id === session.serverId);
        return {
          ...session,
          serverName: server?.name || "Unknown",
          serverHost: server?.host || "Unknown",
        };
      });

      res.json(activeSessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch sessions" });
    }
  });

  app.post("/api/sessions", async (req, res) => {
    try {
      const { serverId, sshUser } = req.body;
      const userId = "mock-user-1";

      const server = await storage.getServer(serverId);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }

      const session = await storage.createSession({
        userId,
        serverId,
        sshUser,
        status: "active",
      });

      res.json(session);
    } catch (error) {
      res.status(500).json({ message: "Failed to create session" });
    }
  });

  app.delete("/api/sessions/:id", async (req, res) => {
    try {
      await storage.endSession(req.params.id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to end session" });
    }
  });

  app.get("/api/admin/servers", async (req, res) => {
    try {
      const servers = await storage.getServers();
      res.json(servers);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch servers" });
    }
  });

  app.post("/api/admin/servers", async (req, res) => {
    try {
      const server = await storage.createServer(req.body);
      res.json(server);
    } catch (error) {
      res.status(500).json({ message: "Failed to create server" });
    }
  });

  app.patch("/api/admin/servers/:id", async (req, res) => {
    try {
      const server = await storage.updateServer(req.params.id, req.body);
      if (!server) {
        res.status(404).json({ message: "Server not found" });
        return;
      }
      res.json(server);
    } catch (error) {
      res.status(500).json({ message: "Failed to update server" });
    }
  });

  app.delete("/api/admin/servers/:id", async (req, res) => {
    try {
      const success = await storage.deleteServer(req.params.id);
      if (!success) {
        res.status(404).json({ message: "Server not found" });
        return;
      }
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete server" });
    }
  });

  app.get("/api/admin/users", async (req, res) => {
    try {
      const users = await storage.getUsers();
      res.json(users);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.patch("/api/admin/users/:id", async (req, res) => {
    try {
      const user = await storage.updateUser(req.params.id, req.body);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }
      res.json(user);
    } catch (error) {
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  app.get("/api/admin/sessions", async (req, res) => {
    try {
      const sessions = await storage.getSessions();
      const servers = await storage.getServers();
      
      const activeSessions: ActiveSession[] = sessions.map((session) => {
        const server = servers.find((s) => s.id === session.serverId);
        return {
          ...session,
          serverName: server?.name || "Unknown",
          serverHost: server?.host || "Unknown",
        };
      });

      res.json(activeSessions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch sessions" });
    }
  });

  return httpServer;
}
