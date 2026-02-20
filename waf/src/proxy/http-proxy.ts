/**
 * HTTP auth gateway with server-side OIDC login flow.
 *
 * Public routes (no auth): /login, /auth/*, /health
 * Protected routes: everything else → validate JWT → proxy to backend
 *
 * Auth is extracted from:
 *   1. `waf_access` httpOnly cookie (browser sessions)
 *   2. `Authorization: Bearer <jwt>` header (API/programmatic access)
 *
 * When the access token expires, the WAF transparently refreshes
 * using the refresh token cookie before proxying.
 */

import {
  createServer,
  Server,
  IncomingMessage,
  ServerResponse,
  request as httpRequest,
} from "http";
import {
  createServer as createHttpsServer,
  Server as HttpsServer,
  request as httpsRequest,
} from "https";
import { createHmac } from "crypto";
import { readFileSync } from "fs";
import { join, resolve } from "path";
import type { TidecloakAuth } from "../auth/tidecloak.js";
import type { TidecloakConfig } from "../config.js";
import {
  getOidcEndpoints,
  buildAuthUrl,
  exchangeCode,
  refreshAccessToken,
  buildLogoutUrl,
  parseState,
  type OidcEndpoints,
} from "../auth/oidc.js";

export interface ProxyOptions {
  listenPort: number;
  backendUrl: string;
  backends?: { name: string; url: string }[];
  auth: TidecloakAuth;
  stripAuthHeader: boolean;
  tcConfig: TidecloakConfig;
  /** Public URL for TideCloak (browser-facing). Defaults to config auth-server-url. */
  authServerPublicUrl?: string;
  /** ICE servers for WebRTC, e.g. ["stun:relay.example.com:3478"] */
  iceServers?: string[];
  /** TURN server URL, e.g. "turn:relay.example.com:3478" */
  turnServer?: string;
  /** Shared secret for TURN REST API ephemeral credentials */
  turnSecret?: string;
  /** TLS key + cert for HTTPS. If provided, server uses HTTPS. */
  tls?: { key: string; cert: string };
}

export interface ProxyStats {
  totalRequests: number;
  authorizedRequests: number;
  rejectedRequests: number;
}

// ── Cookie helpers ───────────────────────────────────────────────

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  const cookies: Record<string, string> = {};
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    cookies[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  return cookies;
}

let _useSecureCookies = false;

function buildCookieHeader(
  name: string,
  value: string,
  maxAge: number,
  sameSite: "Lax" | "Strict" = "Lax"
): string {
  const secure = _useSecureCookies ? "; Secure" : "";
  return `${name}=${value}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=${sameSite}${secure}`;
}

function clearCookieHeader(name: string): string {
  return `${name}=; HttpOnly; Path=/; Max-Age=0`;
}

// ── Static file serving ──────────────────────────────────────────

const PUBLIC_DIR = resolve(
  import.meta.dirname ?? join(process.cwd(), "src", "proxy"),
  "..",
  "..",
  "public"
);

function serveFile(
  res: ServerResponse,
  filename: string,
  contentType: string
): void {
  try {
    const content = readFileSync(join(PUBLIC_DIR, filename), "utf-8");
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  }
}

// ── Redirect helper ──────────────────────────────────────────────

function redirect(res: ServerResponse, location: string, status = 302): void {
  res.writeHead(status, { Location: location });
  res.end();
}

// ── Request type detection ───────────────────────────────────────

function isBrowserRequest(req: IncomingMessage): boolean {
  const accept = req.headers.accept || "";
  return accept.includes("text/html");
}

function getCallbackUrl(req: IncomingMessage, isTls: boolean): string {
  const proto = req.headers["x-forwarded-proto"] || (isTls ? "https" : "http");
  const host = req.headers.host || `localhost`;
  return `${proto}://${host}/auth/callback`;
}

// ── Redirect rewriting ──────────────────────────────────────

/**
 * Rewrite `Location` headers that point to localhost or the TideCloak
 * origin. localhost:PORT refs become /__b/<name> paths (path-based
 * backend routing), keeping DataChannel and remote connections working.
 */
function rewriteRedirects(
  headers: Record<string, any>,
  tcOrigin: string,
  portMap?: Map<string, string>
): void {
  if (!headers.location || typeof headers.location !== "string") return;

  // Rewrite TideCloak origin to relative path
  if (tcOrigin && headers.location.startsWith(tcOrigin)) {
    headers.location = headers.location.slice(tcOrigin.length) || "/";
  }
  // Rewrite localhost:PORT → /__b/<name> (known backend) or strip (unknown)
  headers.location = headers.location.replace(
    /^https?:\/\/localhost(:\d+)?/,
    (_match: string, portGroup?: string) => {
      if (portGroup && portMap) {
        const port = portGroup.slice(1);
        const name = portMap.get(port);
        if (name) return `/__b/${encodeURIComponent(name)}`;
      }
      return "";
    }
  );
}

// Regex matching http(s)://localhost:PORT — used to rewrite backend
// cross-references in HTML so they stay within the DataChannel.
const LOCALHOST_URL_RE = /https?:\/\/localhost(:\d+)?/g;

// ── Main proxy factory ───────────────────────────────────────────

export function createProxy(options: ProxyOptions): {
  server: Server | HttpsServer;
  getStats: () => ProxyStats;
} {
  const stats: ProxyStats = {
    totalRequests: 0,
    authorizedRequests: 0,
    rejectedRequests: 0,
  };

  // Build backend lookup map (name → URL)
  const backendMap = new Map<string, URL>();
  if (options.backends?.length) {
    for (const b of options.backends) {
      backendMap.set(b.name, new URL(b.url));
    }
  }
  const defaultBackendUrl = new URL(options.backendUrl);

  // Reverse map: "localhost:PORT" → backend name (for cross-backend routing)
  const portToBackend = new Map<string, string>();
  for (const [name, url] of backendMap) {
    if (url.hostname === "localhost" || url.hostname === "127.0.0.1") {
      portToBackend.set(url.port || (url.protocol === "https:" ? "443" : "80"), name);
    }
  }

  /**
   * Rewrite all localhost:PORT URLs in HTML to /__b/<name> paths.
   * This keeps links, form actions, and JS references within the
   * DataChannel and routes them to the correct backend.
   */
  function rewriteLocalhostInHtml(html: string): string {
    return html.replace(LOCALHOST_URL_RE, (_match: string, portGroup?: string) => {
      if (portGroup) {
        const port = portGroup.slice(1);
        const name = portToBackend.get(port);
        if (name) return `/__b/${encodeURIComponent(name)}`;
      }
      return "";
    });
  }

  function resolveBackend(req: IncomingMessage): URL {
    // Check x-waf-backend header (set by STUN relay) first
    const headerBackend = req.headers["x-waf-backend"] as string | undefined;
    if (headerBackend) {
      const found = backendMap.get(headerBackend);
      if (found) return found;
    }
    // Check waf_backend cookie (direct access)
    const cookies = parseCookies(req.headers.cookie);
    const cookieBackend = cookies["waf_backend"];
    if (cookieBackend) {
      const decoded = decodeURIComponent(cookieBackend);
      const found = backendMap.get(decoded);
      if (found) return found;
    }
    return defaultBackendUrl;
  }

  // TideCloak URL for reverse-proxying auth pages (/realms/*, /resources/*).
  // Always derived from auth-server-url in the tidecloak config.
  const tcProxyUrl = new URL(options.tcConfig["auth-server-url"]);
  const tcProxyIsHttps = tcProxyUrl.protocol === "https:";
  const makeTcRequest = tcProxyIsHttps ? httpsRequest : httpRequest;

  // Browser-facing endpoints use public URL if explicitly set;
  // otherwise derived per-request from Host header (see getBrowserEndpoints)
  const fixedBrowserEndpoints: OidcEndpoints | null = options.authServerPublicUrl
    ? getOidcEndpoints(options.tcConfig, options.authServerPublicUrl)
    : null;
  // Server-side endpoints (token exchange, refresh) always use config URL
  const serverEndpoints: OidcEndpoints = getOidcEndpoints(options.tcConfig);
  const clientId = options.tcConfig.resource;
  const isTls = !!options.tls;
  _useSecureCookies = isTls;

  /** Get browser-facing OIDC endpoints.
   *  Uses authServerPublicUrl if explicitly set, otherwise returns relative
   *  paths (/realms/...) so auth traffic stays on the WAF origin.
   *  The /realms/* proxy forwards these to the real TideCloak server. */
  function getBrowserEndpoints(_req: IncomingMessage): OidcEndpoints {
    if (fixedBrowserEndpoints) return fixedBrowserEndpoints;
    // Empty base → relative paths: /realms/wafwaf/protocol/openid-connect/auth
    return getOidcEndpoints(options.tcConfig, "");
  }

  const requestHandler = async (req: IncomingMessage, res: ServerResponse) => {
      const url = req.url || "/";
      const path = url.split("?")[0];

      // ── Public routes ────────────────────────────────────

      // Static JS files
      if (path.startsWith("/js/") && path.endsWith(".js")) {
        // Allow SW to control root scope even though it lives under /js/
        if (path === "/js/sw.js") {
          res.setHeader("Service-Worker-Allowed", "/");
        }
        serveFile(res, path.slice(1), "application/javascript; charset=utf-8");
        return;
      }

      // WebRTC config — tells the browser how to connect for P2P upgrade
      if (path === "/webrtc-config") {
        const proto = (req.headers["x-forwarded-proto"] as string) || "http";
        const host = req.headers.host || "localhost";
        const wsProto = proto === "https" ? "wss" : "ws";
        const webrtcConfig: Record<string, unknown> = {
          signalingUrl: `${wsProto}://${host}`,
          stunServer: options.iceServers?.[0]
            ? `stun:${options.iceServers[0].replace("stun:", "")}`
            : null,
        };
        if (options.turnServer && options.turnSecret) {
          // Generate ephemeral TURN credentials (valid for 1 hour)
          const expiry = Math.floor(Date.now() / 1000) + 3600;
          const turnUsername = `${expiry}`;
          const turnPassword = createHmac("sha1", options.turnSecret)
            .update(turnUsername)
            .digest("base64");
          webrtcConfig.turnServer = options.turnServer;
          webrtcConfig.turnUsername = turnUsername;
          webrtcConfig.turnPassword = turnPassword;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(webrtcConfig));
        return;
      }

      // Login page
      if (path === "/login") {
        serveFile(res, "login.html", "text/html; charset=utf-8");
        return;
      }

      // OIDC: initiate login
      if (path === "/auth/login") {
        const params = new URLSearchParams(url.split("?")[1] || "");
        const originalUrl = params.get("redirect") || "/";
        const callbackUrl = getCallbackUrl(req, isTls);
        const { url: authUrl } = buildAuthUrl(
          getBrowserEndpoints(req),
          clientId,
          callbackUrl,
          originalUrl
        );
        redirect(res, authUrl);
        return;
      }

      // OIDC: callback from TideCloak
      if (path === "/auth/callback") {
        const params = new URLSearchParams(url.split("?")[1] || "");
        const code = params.get("code");
        const stateParam = params.get("state") || "";
        const error = params.get("error");

        if (error) {
          console.log(`[WAF] Auth error from TideCloak: ${error}`);
          redirect(res, `/login?error=failed`);
          return;
        }

        if (!code) {
          redirect(res, `/login?error=failed`);
          return;
        }

        try {
          const callbackUrl = getCallbackUrl(req, isTls);
          const tokens = await exchangeCode(
            serverEndpoints,
            clientId,
            code,
            callbackUrl
          );

          const state = parseState(stateParam);
          const cookies: string[] = [
            buildCookieHeader(
              "waf_access",
              tokens.access_token,
              tokens.expires_in
            ),
          ];

          if (tokens.refresh_token) {
            cookies.push(
              buildCookieHeader(
                "waf_refresh",
                tokens.refresh_token,
                tokens.refresh_expires_in || 1800,
                "Strict"
              )
            );
          }

          res.writeHead(302, {
            Location: state.redirect || "/",
            "Set-Cookie": cookies,
          });
          res.end();
        } catch (err) {
          console.error("[WAF] Token exchange failed:", err);
          redirect(res, `/login?error=failed`);
        }
        return;
      }

      // Session token — returns JWT from HttpOnly cookie so the page
      // can include it in WebRTC DataChannel requests (SW can't read cookies)
      if (path === "/auth/session-token") {
        const cookies = parseCookies(req.headers.cookie);
        const accessToken = cookies["waf_access"];
        if (!accessToken) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "No session" }));
          return;
        }
        const payload = await options.auth.verifyToken(accessToken);
        if (!payload) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid session" }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ token: accessToken }));
        return;
      }

      // OIDC: logout
      if (path === "/auth/logout") {
        const callbackUrl = getCallbackUrl(req, isTls);
        const proto = callbackUrl.split("/auth/callback")[0];
        const logoutUrl = buildLogoutUrl(
          getBrowserEndpoints(req),
          clientId,
          `${proto}/login`
        );

        res.writeHead(302, {
          Location: logoutUrl,
          "Set-Cookie": [
            clearCookieHeader("waf_access"),
            clearCookieHeader("waf_refresh"),
          ],
        });
        res.end();
        return;
      }

      // ── Backend switch (path-based routing) ──────────────
      // /__b/<name>/path sets waf_backend cookie and redirects to /path.
      // Cross-backend localhost:PORT refs in HTML are rewritten to these
      // paths, so clicking them switches backend context automatically.
      if (path.startsWith("/__b/")) {
        const rest = path.slice("/__b/".length);
        const slashIdx = rest.indexOf("/");
        const encodedName = slashIdx >= 0 ? rest.slice(0, slashIdx) : rest;
        const backendName = decodeURIComponent(encodedName);
        const targetPath = slashIdx >= 0 ? rest.slice(slashIdx) : "/";

        if (backendMap.has(backendName)) {
          const query = url.includes("?") ? url.slice(url.indexOf("?")) : "";
          res.writeHead(302, {
            Location: targetPath + query,
            "Set-Cookie": buildCookieHeader(
              "waf_backend",
              encodeURIComponent(backendName),
              86400
            ),
          });
          res.end();
          return;
        }
      }

      // ── Reverse-proxy TideCloak (/realms/*, /resources/*) ──
      // Public — TideCloak handles its own auth on these paths.
      // This keeps the browser on the WAF origin so DataChannel
      // and remote access don't break on auth redirects.
      if (path.startsWith("/realms/") || path.startsWith("/resources/")) {
        const tcProxyHeaders = { ...req.headers };
        tcProxyHeaders.host = tcProxyUrl.host;

        const tcProxyReq = makeTcRequest(
          {
            hostname: tcProxyUrl.hostname,
            port: tcProxyUrl.port || (tcProxyIsHttps ? 443 : 80),
            path: url,
            method: req.method,
            headers: tcProxyHeaders,
          },
          (tcProxyRes) => {
            const headers = { ...tcProxyRes.headers };
            rewriteRedirects(headers, tcProxyUrl.origin);

            const contentType = (headers["content-type"] || "") as string;
            if (contentType.includes("text/html")) {
              // Rewrite HTML so TideCloak's forms/links stay on WAF origin
              const chunks: Buffer[] = [];
              tcProxyRes.on("data", (chunk: Buffer) => chunks.push(chunk));
              tcProxyRes.on("end", () => {
                let html = Buffer.concat(chunks).toString("utf-8");
                html = html.replaceAll(tcProxyUrl.origin, "");
                delete headers["content-length"];
                res.writeHead(tcProxyRes.statusCode || 502, headers);
                res.end(html);
              });
            } else {
              res.writeHead(tcProxyRes.statusCode || 502, headers);
              tcProxyRes.pipe(res);
            }
          }
        );

        tcProxyReq.on("error", (err) => {
          console.error("[Proxy] TideCloak error:", err.message);
          if (!res.headersSent) {
            res.writeHead(502, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Auth server unavailable" }));
          }
        });

        req.pipe(tcProxyReq);
        return;
      }

      // ── Protected routes ─────────────────────────────────

      stats.totalRequests++;

      // Extract JWT: cookie first, then Authorization header
      const cookies = parseCookies(req.headers.cookie);
      let token = cookies["waf_access"] || null;

      if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader?.startsWith("Bearer ")) {
          token = authHeader.slice(7);
        }
      }

      // Validate JWT
      let payload = token ? await options.auth.verifyToken(token) : null;

      // If access token expired, try refreshing with refresh token
      if (!payload && cookies["waf_refresh"]) {
        try {
          const tokens = await refreshAccessToken(
            serverEndpoints,
            clientId,
            cookies["waf_refresh"]
          );

          payload = await options.auth.verifyToken(tokens.access_token);

          if (payload) {
            // Set updated cookies on the response
            token = tokens.access_token;
            const refreshCookies: string[] = [
              buildCookieHeader(
                "waf_access",
                tokens.access_token,
                tokens.expires_in
              ),
            ];
            if (tokens.refresh_token) {
              refreshCookies.push(
                buildCookieHeader(
                  "waf_refresh",
                  tokens.refresh_token,
                  tokens.refresh_expires_in || 1800,
                  "Strict"
                )
              );
            }
            // Store cookies to set on the proxied response
            (res as any).__refreshCookies = refreshCookies;
          }
        } catch (err) {
          console.log("[WAF] Token refresh failed:", err);
        }
      }

      // No valid token — redirect browser or 401 for API
      if (!payload) {
        stats.rejectedRequests++;

        if (isBrowserRequest(req)) {
          const redirectTarget = encodeURIComponent(url);
          redirect(res, `/login?redirect=${redirectTarget}&error=expired`);
        } else {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ error: "Missing or invalid authorization" })
          );
        }
        return;
      }

      stats.authorizedRequests++;

      // ── Proxy to backend ─────────────────────────────────

      const proxyHeaders = { ...req.headers };
      delete proxyHeaders.host;

      // Remove cookie auth headers (don't leak to backend)
      if (options.stripAuthHeader) {
        delete proxyHeaders.authorization;
      }

      proxyHeaders["x-forwarded-user"] = payload.sub || "unknown";
      proxyHeaders["x-forwarded-for"] =
        req.socket.remoteAddress || "unknown";

      const targetBackend = resolveBackend(req);
      const targetIsHttps = targetBackend.protocol === "https:";
      const makeBackendReq = targetIsHttps ? httpsRequest : httpRequest;

      // Strip x-waf-backend header (internal routing, not for backend)
      delete proxyHeaders["x-waf-backend"];

      const proxyReq = makeBackendReq(
        {
          hostname: targetBackend.hostname,
          port: targetBackend.port || (targetIsHttps ? 443 : 80),
          path: req.url,
          method: req.method,
          headers: proxyHeaders,
        },
        (proxyRes) => {
          const headers = { ...proxyRes.headers };

          // Rewrite redirects: TideCloak → relative, localhost:PORT → /__b/<name>
          rewriteRedirects(headers, tcProxyUrl.origin, portToBackend);

          // Append refresh cookies if token was refreshed
          const refreshCookies = (res as any).__refreshCookies as
            | string[]
            | undefined;
          if (refreshCookies) {
            const existing = headers["set-cookie"] || [];
            const existingArr = Array.isArray(existing)
              ? existing
              : [existing as string];
            headers["set-cookie"] = [...existingArr, ...refreshCookies];
          }

          // Buffer HTML to rewrite localhost URLs and inject WebRTC script
          const contentType = (headers["content-type"] || "") as string;
          if (contentType.includes("text/html")) {
            const chunks: Buffer[] = [];
            proxyRes.on("data", (chunk: Buffer) => chunks.push(chunk));
            proxyRes.on("end", () => {
              let html = Buffer.concat(chunks).toString("utf-8");
              // Rewrite localhost:PORT refs so they stay in DataChannel
              html = rewriteLocalhostInHtml(html);
              // Inject WebRTC upgrade script
              if (options.iceServers?.length) {
                const script = `<script src="/js/webrtc-upgrade.js" defer></script>`;
                if (html.includes("</body>")) {
                  html = html.replace("</body>", `${script}\n</body>`);
                } else {
                  html += script;
                }
              }
              delete headers["content-length"];
              res.writeHead(proxyRes.statusCode || 502, headers);
              res.end(html);
            });
          } else {
            res.writeHead(proxyRes.statusCode || 502, headers);
            proxyRes.pipe(res);
          }
        }
      );

      proxyReq.on("error", (err) => {
        console.error("[Proxy] Backend error:", err.message);
        if (!res.headersSent) {
          res.writeHead(502, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Backend unavailable" }));
        }
      });

      req.pipe(proxyReq);
    };

  const server = options.tls
    ? createHttpsServer({ key: options.tls.key, cert: options.tls.cert }, requestHandler)
    : createServer(requestHandler);

  const scheme = isTls ? "https" : "http";
  server.listen(options.listenPort, () => {
    console.log(`[Proxy] Listening on ${scheme}://localhost:${options.listenPort}`);
    if (options.backends && options.backends.length > 1) {
      for (const b of options.backends) {
        console.log(`[Proxy] Backend: ${b.name} → ${b.url}`);
      }
    } else {
      console.log(`[Proxy] Backend: ${options.backendUrl}`);
    }
    console.log(`[Proxy] Login: ${scheme}://localhost:${options.listenPort}/login`);
  });

  return {
    server,
    getStats: () => ({ ...stats }),
  };
}
