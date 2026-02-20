/**
 * API endpoints and static file serving for the portal and admin UI.
 *
 * Returns true if the request was handled, false to fall through to relay.
 */

import type { IncomingMessage, ServerResponse } from "http";
import { readFileSync, existsSync } from "fs";
import { join, resolve, extname } from "path";
import { fileURLToPath } from "url";
import type { Registry } from "../signaling/registry.js";
import type { AdminAuth } from "../auth/jwt.js";
import type { TidecloakConfig } from "../config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = resolve(__filename, "..");
const PUBLIC_DIR = resolve(__dirname, "..", "..", "public");
console.log(`[API] Public dir: ${PUBLIC_DIR} (exists: ${existsSync(PUBLIC_DIR)})`);

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

export interface ApiOptions {
  adminAuth?: AdminAuth;
  tidecloakConfig?: TidecloakConfig;
}

export function createApiHandler(registry: Registry, adminAuth?: AdminAuth, tidecloakConfig?: TidecloakConfig) {
  return function handleApiRequest(
    req: IncomingMessage,
    res: ServerResponse
  ): boolean {
    const url = req.url || "/";
    // Normalize: strip trailing slash (except root "/")
    const rawPath = url.split("?")[0];
    const path = rawPath.length > 1 && rawPath.endsWith("/")
      ? rawPath.slice(0, -1)
      : rawPath;

    // ── API: List WAFs (for portal) ──────────────────
    if (path === "/api/wafs" && req.method === "GET") {
      const wafs = registry.getAllWafs().map((w) => ({
        id: w.id,
        displayName: w.metadata.displayName || w.id,
        description: w.metadata.description || "",
        backends: w.metadata.backends || [],
        clientCount: w.pairedClients.size,
        online: w.ws.readyState === w.ws.OPEN,
      }));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ wafs }));
      return true;
    }

    // ── API: Detailed stats (for admin) ──────────────
    if (path === "/api/admin/stats" && req.method === "GET") {
      if (adminAuth) {
        verifyBearerToken(req, res, adminAuth).then((ok) => {
          if (!ok) return;
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(registry.getDetailedStats()));
        });
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(registry.getDetailedStats()));
      }
      return true;
    }

    // ── API: Select WAF (sets cookie, returns OK) ────
    if (path === "/api/select-waf" && req.method === "POST") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        try {
          const { wafId, backend } = JSON.parse(Buffer.concat(chunks).toString());
          const waf = registry.getWaf(wafId);
          if (!waf) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "WAF not found" }));
            return;
          }
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Set-Cookie": `waf_relay=${wafId}; Path=/; HttpOnly; SameSite=Lax`,
          });
          res.end(JSON.stringify({ success: true, wafId, backend: backend || null }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid request body" }));
        }
      });
      return true;
    }

    // ── API: Select WAF (GET — single redirect, sets cookies) ──
    if (path === "/api/select" && req.method === "GET") {
      const params = new URLSearchParams(url.split("?")[1] || "");
      const wafId = params.get("waf");
      const backend = params.get("backend");
      if (!wafId || !registry.getWaf(wafId)) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "WAF not found" }));
        return true;
      }
      // Only need waf_relay cookie for STUN relay routing.
      // Backend routing is path-based: /__b/<name>/
      const cookies: string[] = [
        `waf_relay=${wafId}; Path=/; HttpOnly; SameSite=Lax`,
      ];
      // Redirect to /__b/<name>/ so the WAF routes to the right backend
      const location = backend
        ? `/__b/${encodeURIComponent(backend)}/`
        : "/";
      res.writeHead(302, {
        Location: location,
        "Set-Cookie": cookies,
      });
      res.end();
      return true;
    }

    // ── API: Clear selection (reset cookies, back to portal) ──
    if (path === "/api/clear-selection" && req.method === "POST") {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "waf_relay=; Path=/; HttpOnly; Max-Age=0",
      });
      res.end(JSON.stringify({ success: true }));
      return true;
    }

    // ── Portal page ──────────────────────────────────
    if (path === "/portal" && req.method === "GET") {
      // Clear WAF affinity cookie so user lands on portal
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": "waf_relay=; Path=/; HttpOnly; Max-Age=0",
      });
      try {
        const content = readFileSync(join(PUBLIC_DIR, "portal.html"));
        res.end(content);
      } catch {
        res.end("Not found");
      }
      return true;
    }

    // ── Root: portal if no cookie, else fall through to relay
    if (path === "/" && req.method === "GET") {
      const hasCookie = parseCookie(req.headers.cookie, "waf_relay");
      if (!hasCookie) {
        serveStaticFile(res, "portal.html");
        return true;
      }
      return false; // Has cookie → relay to WAF
    }

    // ── Admin auth config (injected as JS) ──────────
    if (path === "/admin-config" && req.method === "GET") {
      let js: string;
      if (tidecloakConfig) {
        const cfg = JSON.stringify({
          authServerUrl: tidecloakConfig["auth-server-url"].replace(/\/$/, ""),
          realm: tidecloakConfig.realm,
          clientId: tidecloakConfig.resource,
        });
        js = `window.__ADMIN_AUTH__ = ${cfg};`;
      } else {
        js = `window.__ADMIN_AUTH__ = null;`;
      }
      res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8" });
      res.end(js);
      return true;
    }

    // ── Admin dashboard ──────────────────────────────
    if (path === "/admin" && req.method === "GET") {
      serveStaticFile(res, "admin.html");
      return true;
    }

    // ── Static assets ────────────────────────────────
    if (path.startsWith("/static/")) {
      const filePath = path.slice("/static/".length);
      if (filePath.includes("..")) {
        res.writeHead(403);
        res.end("Forbidden");
        return true;
      }
      serveStaticFile(res, filePath);
      return true;
    }

    return false;
  };

  function serveStaticFile(res: ServerResponse, filename: string): void {
    const filePath = join(PUBLIC_DIR, filename);
    try {
      const content = readFileSync(filePath);
      const ext = extname(filename);
      const contentType = MIME_TYPES[ext] || "application/octet-stream";
      res.writeHead(200, { "Content-Type": contentType });
      res.end(content);
    } catch {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
    }
  }
}

async function verifyBearerToken(
  req: IncomingMessage,
  res: ServerResponse,
  adminAuth: AdminAuth
): Promise<boolean> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Authentication required" }));
    return false;
  }
  const token = authHeader.slice(7);
  const payload = await adminAuth.verifyAdmin(token);
  if (!payload) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid or insufficient permissions" }));
    return false;
  }
  return true;
}

function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}
