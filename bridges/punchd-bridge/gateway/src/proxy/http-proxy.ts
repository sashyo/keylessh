/**
 * HTTP auth gateway with server-side OIDC login flow.
 *
 * Public routes (no auth): /auth/*, /health
 * Protected routes: everything else → validate JWT → proxy to backend
 *
 * Auth is extracted from:
 *   1. `gateway_access` httpOnly cookie (browser sessions)
 *   2. `Authorization: Bearer <jwt>` header (API/programmatic access)
 *
 * When the access token expires, the gateway transparently refreshes
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
import { createHmac, randomBytes } from "crypto";
import { readFileSync, realpathSync } from "fs";
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
  backends?: { name: string; url: string; noAuth?: boolean; stripAuth?: boolean }[];
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
  /** Internal TideCloak URL for proxying (when KC_HOSTNAME is a public URL) */
  tcInternalUrl?: string;
  /** Gateway ID for dest: role enforcement */
  gatewayId?: string;
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
  sameSite: "Lax" | "Strict" | "None" = "Lax"
): string {
  // SameSite=None requires the Secure flag (browser requirement)
  const needsSecure = sameSite === "None" || _useSecureCookies;
  const secure = needsSecure ? "; Secure" : "";
  return `${name}=${value}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=${sameSite}${secure}`;
}

function clearCookieHeader(name: string): string {
  const secure = _useSecureCookies ? "; Secure" : "";
  return `${name}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${secure}`;
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
    const resolved = resolve(PUBLIC_DIR, filename);
    // Prevent path traversal and symlink escape — real path must be inside PUBLIC_DIR
    const realPath = realpathSync(resolved);
    if (!realPath.startsWith(PUBLIC_DIR + "/")) {
      res.writeHead(403, { "Content-Type": "text/plain" });
      res.end("Forbidden");
      return;
    }
    const content = readFileSync(realPath, "utf-8");
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

// ── Open redirect prevention ────────────────────────────────────

function sanitizeRedirect(url: string): string {
  if (!url || typeof url !== "string") return "/";
  const trimmed = url.trim();
  if (trimmed.startsWith("//") || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) return "/";
  if (!trimmed.startsWith("/")) return "/";
  return trimmed;
}

// ── HTTP method validation ──────────────────────────────────────

const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

// ── Request type detection ───────────────────────────────────────

function isBrowserRequest(req: IncomingMessage): boolean {
  const accept = req.headers.accept || "";
  return accept.includes("text/html");
}

/** Browser-initiated resource requests that don't contain sensitive data.
 *  Without this exemption they 401 before the session token is refreshed. */
function isPublicResource(path: string): boolean {
  const basename = path.split("/").pop() || "";
  return (
    basename === "manifest.json" ||
    basename.endsWith(".webmanifest") ||
    basename === "browserconfig.xml" ||
    basename === "robots.txt" ||
    basename.endsWith(".ico")
  );
}

function getCallbackUrl(req: IncomingMessage, isTls: boolean): string {
  const proto = isTls ? "https" : "http";
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
  portMap?: Map<string, string>,
  replacement?: string
): void {
  if (!headers.location || typeof headers.location !== "string") return;

  // Rewrite TideCloak origin → replacement origin (or relative path)
  if (tcOrigin && headers.location.startsWith(tcOrigin)) {
    headers.location = (replacement || "") + (headers.location.slice(tcOrigin.length) || "/");
    return; // Don't apply localhost regex — URL is already rewritten
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
      return replacement || "";
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

  // No-auth backends: skip gateway JWT validation (backend handles its own auth)
  const noAuthBackends = new Set<string>();
  // Strip-auth backends: remove Authorization header before proxying
  const stripAuthBackends = new Set<string>();
  if (options.backends?.length) {
    for (const b of options.backends) {
      if (b.noAuth) {
        noAuthBackends.add(b.name);
        console.log(`[Proxy] Backend "${b.name}" — auth disabled (noauth)`);
      }
      if (b.stripAuth) {
        stripAuthBackends.add(b.name);
        console.log(`[Proxy] Backend "${b.name}" — auth header stripped (stripauth)`);
      }
    }
  }

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

  /**
   * Prepend /__b/<name> prefix to absolute paths in HTML attributes
   * (href="/...", src="/...", action="/...") so links stay within
   * the correct backend namespace. Skips protocol-relative (//)
   * and already-prefixed (/__b/) paths.
   */
  function prependPrefix(html: string, prefix: string): string {
    return html.replace(
      /((?:href|src|action|formaction)\s*=\s*["'])(\/(?!\/|__b\/))/gi,
      `$1${prefix}$2`
    );
  }

  function resolveBackend(req: IncomingMessage, activeBackend?: string): URL {
    // 1. Path-based /__b/<name> prefix (highest priority)
    if (activeBackend) {
      const found = backendMap.get(activeBackend);
      if (found) return found;
    }
    // 2. x-gateway-backend header (set by STUN relay from /__b/ prefix in URL)
    const headerBackend = req.headers["x-gateway-backend"] as string | undefined;
    if (headerBackend) {
      const found = backendMap.get(headerBackend);
      if (found) return found;
    }
    return defaultBackendUrl;
  }

  // ── TideCloak cookie jar ──────────────────────────────────────
  // The STUN relay may not forward Set-Cookie headers to the browser,
  // so the gateway stores TC cookies server-side. A lightweight `tc_sess`
  // cookie on the browser maps to the stored TC cookies.
  interface TcSession { cookies: Map<string, string>; lastAccess: number; }
  const tcCookieJar = new Map<string, TcSession>();
  const TC_SESS_MAX_AGE = 3600; // 1 hour
  const TC_SESS_MAX_ENTRIES = 10000;

  /** Get or create a TC session ID from the browser's tc_sess cookie. */
  function getTcSessionId(req: IncomingMessage): { id: string; isNew: boolean } {
    const cookies = parseCookies(req.headers.cookie);
    const candidateId = cookies["tc_sess"];
    // Only accept existing session IDs that are in the jar (ignore client-supplied unknown IDs)
    if (candidateId && tcCookieJar.has(candidateId)) {
      const existing = tcCookieJar.get(candidateId)!;
      existing.lastAccess = Date.now();
      return { id: candidateId, isNew: false };
    }
    // Always generate a new server-side ID — never trust a client-supplied value
    const id = randomBytes(16).toString("hex");
    tcCookieJar.set(id, { cookies: new Map(), lastAccess: Date.now() });
    return { id, isNew: true };
  }

  /** Store TC's Set-Cookie values in the jar, return gateway's tc_sess cookie. */
  function storeTcCookies(
    sessionId: string,
    setCookieHeaders: string | string[] | undefined
  ): void {
    if (!setCookieHeaders) return;
    const session = tcCookieJar.get(sessionId);
    if (!session) return;
    session.lastAccess = Date.now();
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const h of headers) {
      const eq = h.indexOf("=");
      if (eq < 0) continue;
      const name = h.slice(0, eq).trim();
      // Extract just the value (up to first ';')
      const rest = h.slice(eq + 1);
      const semi = rest.indexOf(";");
      const value = semi >= 0 ? rest.slice(0, semi) : rest;
      // Ignore clearing (Max-Age=0 or empty value)
      if (!value || /Max-Age=0/i.test(h)) {
        session.cookies.delete(name);
      } else {
        session.cookies.set(name, value);
      }
    }
  }

  /** Build a Cookie header from the jar for proxied requests to TC. */
  function getTcCookieHeader(sessionId: string): string {
    const session = tcCookieJar.get(sessionId);
    if (!session || session.cookies.size === 0) return "";
    session.lastAccess = Date.now();
    return Array.from(session.cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  }

  // Periodically evict stale sessions (every 10 min)
  setInterval(() => {
    const now = Date.now();
    const maxAge = TC_SESS_MAX_AGE * 1000;
    // Evict expired entries
    for (const [id, session] of tcCookieJar) {
      if (now - session.lastAccess > maxAge) {
        tcCookieJar.delete(id);
      }
    }
    // If still over limit, evict oldest (LRU)
    if (tcCookieJar.size > TC_SESS_MAX_ENTRIES) {
      const sorted = [...tcCookieJar.entries()].sort((a, b) => a[1].lastAccess - b[1].lastAccess);
      const toRemove = sorted.slice(0, tcCookieJar.size - TC_SESS_MAX_ENTRIES);
      for (const [id] of toRemove) {
        tcCookieJar.delete(id);
      }
    }
  }, 600_000).unref();

  // ── Backend cookie jar ─────────────────────────────────────────
  // DataChannel requests (WebRTC) bypass the browser's cookie handling:
  // - Set-Cookie is a forbidden header in SW's new Response()
  // - HttpOnly cookies can't be read from JS
  // So the gateway stores backend cookies server-side, keyed by JWT sub.
  // Key format: "userId:backendName" to prevent cross-backend cookie leakage
  interface BackendSession { cookies: Map<string, string>; lastAccess: number; }
  const backendCookieJar = new Map<string, BackendSession>();
  const BACKEND_SESS_MAX_AGE = 7 * 24 * 3600; // 7 days (match backend session)
  const BACKEND_SESS_MAX_ENTRIES = 10000;

  /** Store backend Set-Cookie values in the jar for DataChannel sessions. */
  function storeBackendCookies(
    userId: string,
    setCookieHeaders: string | string[] | undefined
  ): void {
    if (!setCookieHeaders || !userId) return;
    let session = backendCookieJar.get(userId);
    if (!session) {
      session = { cookies: new Map(), lastAccess: Date.now() };
      backendCookieJar.set(userId, session);
    }
    session.lastAccess = Date.now();
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const h of headers) {
      const eq = h.indexOf("=");
      if (eq < 0) continue;
      const name = h.slice(0, eq).trim();
      const rest = h.slice(eq + 1);
      const semi = rest.indexOf(";");
      const value = semi >= 0 ? rest.slice(0, semi) : rest;
      if (!value || /Max-Age=0/i.test(h)) {
        session.cookies.delete(name);
      } else {
        session.cookies.set(name, value);
      }
    }
  }

  /** Build a Cookie header from the backend jar. */
  function getBackendCookieHeader(userId: string): string {
    const session = backendCookieJar.get(userId);
    if (!session || session.cookies.size === 0) return "";
    session.lastAccess = Date.now();
    return Array.from(session.cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
  }

  // Evict stale backend sessions (piggyback on TC timer interval)
  setInterval(() => {
    const now = Date.now();
    const maxAge = BACKEND_SESS_MAX_AGE * 1000;
    for (const [id, session] of backendCookieJar) {
      if (now - session.lastAccess > maxAge) {
        backendCookieJar.delete(id);
      }
    }
    if (backendCookieJar.size > BACKEND_SESS_MAX_ENTRIES) {
      const sorted = [...backendCookieJar.entries()].sort((a, b) => a[1].lastAccess - b[1].lastAccess);
      const toRemove = sorted.slice(0, backendCookieJar.size - BACKEND_SESS_MAX_ENTRIES);
      for (const [id] of toRemove) {
        backendCookieJar.delete(id);
      }
    }
  }, 600_000).unref();

  // TideCloak internal URL for reverse-proxying and server-side requests.
  // When KC_HOSTNAME is a public URL, TC_INTERNAL_URL points to the actual
  // TideCloak instance (e.g. http://localhost:8080).
  const tcInternalUrl = options.tcInternalUrl || options.tcConfig["auth-server-url"];
  const tcProxyUrl = new URL(tcInternalUrl);
  const tcProxyIsHttps = tcProxyUrl.protocol === "https:";
  const makeTcRequest = tcProxyIsHttps ? httpsRequest : httpRequest;

  // KC_HOSTNAME-based public URL (from adapter config). TideCloak generates
  // redirects and URLs using this, so we need to rewrite it too.
  const tcPublicOrigin = options.tcConfig["auth-server-url"]
    ? new URL(options.tcConfig["auth-server-url"]).origin
    : null;

  console.log(`[Proxy] TideCloak internal URL: ${tcInternalUrl}`);
  console.log(`[Proxy] TideCloak public origin: ${tcPublicOrigin}`);
  console.log(`[Proxy] TideCloak config auth-server-url: ${options.tcConfig["auth-server-url"]}`);
  if (!options.tcInternalUrl && !tcInternalUrl.includes("localhost")) {
    console.warn(`[Proxy] WARNING: TC_INTERNAL_URL not set — token exchange will use public URL: ${tcInternalUrl}`);
    console.warn(`[Proxy]   Set TC_INTERNAL_URL=http://localhost:8080 if TideCloak runs locally`);
  }

  // Browser-facing endpoints use public URL if explicitly set;
  // otherwise derived per-request from Host header (see getBrowserEndpoints)
  const fixedBrowserEndpoints: OidcEndpoints | null = options.authServerPublicUrl
    ? getOidcEndpoints(options.tcConfig, options.authServerPublicUrl)
    : null;
  // Server-side endpoints (token exchange, refresh) always use internal URL
  const serverEndpoints: OidcEndpoints = getOidcEndpoints(options.tcConfig, tcInternalUrl);
  const clientId = options.tcConfig.resource;

  // ── Refresh token dedup cache ─────────────────────────────────
  // When the access token expires, multiple concurrent requests (manifest.json,
  // DC requests, session-token refresh) may all try to use the same refresh
  // token simultaneously. TideCloak rotates refresh tokens on use, so the
  // second concurrent refresh fails (old token consumed). Fix: deduplicate
  // concurrent refreshes and cache the result briefly.
  interface RefreshResult {
    accessToken: string;
    expiresIn: number;
    refreshToken?: string;
    refreshExpiresIn?: number;
    timestamp: number;
  }
  let lastRefreshResult: RefreshResult | null = null;
  let refreshInFlight: Promise<RefreshResult | null> | null = null;

  async function deduplicatedRefresh(refreshToken: string): Promise<RefreshResult | null> {
    // Reuse a recent result (< 60 seconds) — prevents hammering TideCloak
    // when multiple requests trigger refresh simultaneously or in quick succession
    if (lastRefreshResult && Date.now() - lastRefreshResult.timestamp < 60_000) {
      return lastRefreshResult;
    }
    // If a refresh is already in flight, wait for it
    if (refreshInFlight) {
      return refreshInFlight;
    }
    refreshInFlight = (async () => {
      try {
        const tokens = await refreshAccessToken(
          serverEndpoints,
          clientId,
          refreshToken
        );
        const result: RefreshResult = {
          accessToken: tokens.access_token,
          expiresIn: tokens.expires_in,
          refreshToken: tokens.refresh_token,
          refreshExpiresIn: tokens.refresh_expires_in,
          timestamp: Date.now(),
        };
        lastRefreshResult = result;
        return result;
      } catch (err) {
        console.log("[Gateway] Deduplicated refresh failed:", err);
        return null;
      } finally {
        refreshInFlight = null;
      }
    })();
    return refreshInFlight;
  }

  const isTls = !!options.tls;
  _useSecureCookies = isTls;

  /** Get browser-facing OIDC endpoints.
   *  Uses authServerPublicUrl if explicitly set, otherwise returns relative
   *  paths (/realms/...) so auth traffic stays on the gateway origin.
   *  The /realms/* proxy forwards these to the real TideCloak server. */
  function getBrowserEndpoints(_req: IncomingMessage): OidcEndpoints {
    if (fixedBrowserEndpoints) return fixedBrowserEndpoints;
    // Use relative paths so auth URLs route through the gateway's TideCloak proxy
    return getOidcEndpoints(options.tcConfig, "");
  }

  const requestHandler = async (req: IncomingMessage, res: ServerResponse) => {
      // ── Security headers ──────────────────────────────────────────
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "SAMEORIGIN");
      res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data: blob:; media-src 'self' blob:; worker-src 'self' blob:; frame-ancestors 'self'"
      );
      if (isTls) {
        res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
      }

      let url = req.url || "/";
      let path = url.split("?")[0];
      let backendPrefix = ""; // e.g. "/__b/MediaBox"
      let activeBackend = ""; // e.g. "MediaBox"

      // ── Path-based backend routing ──────────────────────
      // Strip /__b/<name>/ prefix so all routes work normally.
      // The backend is determined by path, not cookies.
      if (path.startsWith("/__b/")) {
        const rest = path.slice("/__b/".length);
        const slashIdx = rest.indexOf("/");
        const encodedName = slashIdx >= 0 ? rest.slice(0, slashIdx) : rest;
        const name = decodeURIComponent(encodedName);
        if (backendMap.has(name)) {
          activeBackend = name;
          backendPrefix = `/__b/${encodedName}`;
          const stripped = slashIdx >= 0 ? rest.slice(slashIdx) : "/";
          const query = url.includes("?") ? url.slice(url.indexOf("?")) : "";
          url = stripped + query;
          path = stripped;
          req.url = url;
        }
      }

      // ── TideCloak /_idp prefix stripping ─────────────────
      // The proxy rewrites TC's localhost URLs to {publicOrigin}/_idp/…
      // so the Tide SDK enclave iframe can reach TC through the relay.
      // Strip the /_idp prefix here so the request hits the /realms/*
      // or /resources/* handler below.
      if (path.startsWith("/_idp/")) {
        url = url.slice("/_idp".length);
        path = path.slice("/_idp".length);
        req.url = url;
      }

      // ── Public routes ────────────────────────────────────

      // Favicon — return empty 204 to avoid falling through to backend role check
      if (path === "/favicon.ico") {
        res.writeHead(204);
        res.end();
        return;
      }

      // Static JS files
      if (path.startsWith("/js/") && path.endsWith(".js")) {
        // Allow SW to control root scope even though it lives under /js/
        if (path === "/js/sw.js") {
          res.setHeader("Service-Worker-Allowed", "/");
          res.setHeader("Cache-Control", "no-cache");
        }
        serveFile(res, path.slice(1), "application/javascript; charset=utf-8");
        return;
      }

      // WebRTC config — tells the browser how to connect for P2P upgrade
      // TURN credentials require valid JWT to prevent bandwidth abuse
      if (path === "/webrtc-config") {
        const proto = isTls ? "https" : "http";
        const host = req.headers.host || "localhost";
        const wsProto = isTls ? "wss" : "ws";
        const webrtcConfig: Record<string, unknown> = {
          signalingUrl: `${wsProto}://${host}`,
          stunServer: options.iceServers?.[0]
            ? `stun:${options.iceServers[0].replace("stun:", "")}`
            : null,
          targetGatewayId: options.gatewayId || undefined,
        };
        if (options.turnServer && options.turnSecret) {
          // Only serve TURN credentials to authenticated users
          const wrtcCookies = parseCookies(req.headers.cookie);
          const wrtcToken = wrtcCookies["gateway_access"];
          const wrtcPayload = wrtcToken ? await options.auth.verifyToken(wrtcToken) : null;
          if (wrtcPayload) {
            const expiry = Math.floor(Date.now() / 1000) + 3600;
            const turnUsername = `${expiry}`;
            const turnPassword = createHmac("sha1", options.turnSecret)
              .update(turnUsername)
              .digest("base64");
            webrtcConfig.turnServer = options.turnServer;
            webrtcConfig.turnUsername = turnUsername;
            webrtcConfig.turnPassword = turnPassword;
          }
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(webrtcConfig));
        return;
      }

      // OIDC: initiate login
      if (path === "/auth/login") {
        const params = new URLSearchParams(url.split("?")[1] || "");
        const originalUrl = sanitizeRedirect(params.get("redirect") || "/");
        const callbackUrl = getCallbackUrl(req, isTls);
        const { url: authUrl, state } = buildAuthUrl(
          getBrowserEndpoints(req),
          clientId,
          callbackUrl,
          originalUrl
        );
        // Store state nonce in a short-lived cookie for CSRF validation on callback
        const parsedState = parseState(state);
        res.writeHead(302, {
          Location: authUrl,
          "Set-Cookie": `oidc_nonce=${parsedState.nonce}; HttpOnly; Path=/auth/callback; Max-Age=600; SameSite=Lax${isTls ? "; Secure" : ""}`,
        });
        res.end();
        return;
      }

      // OIDC: callback from TideCloak
      if (path === "/auth/callback") {
        const params = new URLSearchParams(url.split("?")[1] || "");
        const code = params.get("code");
        const stateParam = params.get("state") || "";
        const error = params.get("error");
        const errorDesc = params.get("error_description");

        if (error) {
          console.log(`[Gateway] Auth error from TideCloak: ${error} — ${errorDesc || "no description"}`);
          redirect(res, `/auth/login?error=${encodeURIComponent(error)}`);
          return;
        }

        if (!code) {
          console.log("[Gateway] Auth callback missing code parameter");
          redirect(res, `/auth/login?error=no_code`);
          return;
        }

        // CSRF validation: compare state nonce against oidc_nonce cookie
        const callbackCookies = parseCookies(req.headers.cookie);
        const state = parseState(stateParam);
        const expectedNonce = callbackCookies["oidc_nonce"];
        if (!expectedNonce || expectedNonce !== state.nonce) {
          console.log("[Gateway] OIDC CSRF check failed: nonce mismatch");
          redirect(res, `/auth/login?error=csrf_failed`);
          return;
        }

        try {
          const callbackUrl = getCallbackUrl(req, isTls);
          console.log(`[Gateway] Token exchange:`);
          console.log(`[Gateway]   endpoint: ${serverEndpoints.token}`);
          console.log(`[Gateway]   client_id: ${clientId}`);
          console.log(`[Gateway]   redirect_uri: ${callbackUrl}`);
          console.log(`[Gateway]   code: ${code.slice(0, 8)}...`);
          const tokens = await exchangeCode(
            serverEndpoints,
            clientId,
            code,
            callbackUrl
          );
          console.log(`[Gateway] Token exchange succeeded (expires_in=${tokens.expires_in})`);

          const cookies: string[] = [
            buildCookieHeader(
              "gateway_access",
              tokens.access_token,
              tokens.expires_in
            ),
          ];

          if (tokens.refresh_token) {
            cookies.push(
              buildCookieHeader(
                "gateway_refresh",
                tokens.refresh_token,
                tokens.refresh_expires_in || 1800,
                "Strict"
              )
            );
          }

          // Clear the one-time CSRF nonce cookie
          cookies.push("oidc_nonce=; HttpOnly; Path=/auth/callback; Max-Age=0");

          const safeRedirect = sanitizeRedirect(state.redirect || "/");
          console.log(`[Gateway] Auth complete, redirecting to: ${safeRedirect}`);
          res.writeHead(302, {
            Location: safeRedirect,
            "Set-Cookie": cookies,
          });
          res.end();
        } catch (err) {
          console.error("[Gateway] Token exchange failed:", err);
          redirect(res, `/auth/login?error=token_exchange`);
        }
        return;
      }

      // Session token — returns JWT from HttpOnly cookie so the page
      // can include it in WebRTC DataChannel requests (SW can't read cookies).
      // Requires X-Requested-With header to prevent simple cross-origin requests
      // (XSS in a proxied backend can still call this, but it blocks CSRF from
      // external origins since custom headers trigger a CORS preflight).
      if (path === "/auth/session-token") {
        if (!req.headers["x-requested-with"]) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing X-Requested-With header" }));
          return;
        }
        const cookies = parseCookies(req.headers.cookie);
        let accessToken = cookies["gateway_access"];
        // Also accept Authorization: Bearer token (relay flow has no cookies)
        if (!accessToken) {
          const authHeader = req.headers.authorization;
          if (authHeader?.startsWith("Bearer ")) {
            accessToken = authHeader.slice(7);
          }
        }

        let payload = accessToken
          ? await options.auth.verifyToken(accessToken)
          : null;

        // Always refresh when the session-token endpoint is called.
        // This endpoint is only called by the client's periodic refresh
        // (every 2 min), so it's not excessive. It ensures the client
        // always gets a token with full lifetime and the browser's
        // gateway_access cookie is renewed (preventing expiry-based 401s
        // on non-DC requests like manifest.json).
        const setCookies: string[] = [];
        if (cookies["gateway_refresh"]) {
          const refreshResult = await deduplicatedRefresh(cookies["gateway_refresh"]);
          if (refreshResult) {
            const refreshedPayload = await options.auth.verifyToken(refreshResult.accessToken);
            if (refreshedPayload) {
              payload = refreshedPayload;
              accessToken = refreshResult.accessToken;
              setCookies.push(
                buildCookieHeader("gateway_access", refreshResult.accessToken, refreshResult.expiresIn)
              );
              if (refreshResult.refreshToken) {
                setCookies.push(
                  buildCookieHeader("gateway_refresh", refreshResult.refreshToken, refreshResult.refreshExpiresIn || 1800, "Strict")
                );
              }
            }
          }
        }

        if (!payload) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid session" }));
          return;
        }

        const headers: Record<string, string | string[]> = {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          "Pragma": "no-cache",
        };
        if (setCookies.length > 0) {
          headers["Set-Cookie"] = setCookies;
        }
        res.writeHead(200, headers);
        res.end(JSON.stringify({ token: accessToken }));
        return;
      }

      // OIDC: logout
      if (path === "/auth/logout") {
        // Clear backend cookie jar for this user before logout
        const cookies = parseCookies(req.headers.cookie);
        const logoutToken = cookies["gateway_access"];
        if (logoutToken) {
          const logoutPayload = await options.auth.verifyToken(logoutToken);
          if (logoutPayload?.sub) {
            // Clear all backend-scoped entries for this user
            const prefix = `${logoutPayload.sub}:`;
            for (const key of backendCookieJar.keys()) {
              if (key.startsWith(prefix)) backendCookieJar.delete(key);
            }
          }
        }

        const callbackUrl = getCallbackUrl(req, isTls);
        const proto = callbackUrl.split("/auth/callback")[0];
        const logoutUrl = buildLogoutUrl(
          getBrowserEndpoints(req),
          clientId,
          `${proto}/auth/login`
        );

        // Clear tc_sess from jar and cookie
        const logoutCookies = parseCookies(req.headers.cookie);
        if (logoutCookies["tc_sess"]) {
          tcCookieJar.delete(logoutCookies["tc_sess"]);
        }

        res.writeHead(302, {
          Location: logoutUrl,
          "Set-Cookie": [
            clearCookieHeader("gateway_access"),
            clearCookieHeader("gateway_refresh"),
            clearCookieHeader("tc_sess"),
          ],
        });
        res.end();
        return;
      }

      // ── Reverse-proxy TideCloak (/realms/*, /resources/*) ──
      // Public — TideCloak handles its own auth on these paths.
      // This keeps the browser on the gateway origin so DataChannel
      // and remote access don't break on auth redirects.
      //
      // Cookie jar: TC's cookies are stored server-side and injected
      // into proxied requests. This avoids relying on the STUN relay
      // to forward Set-Cookie headers to the browser.
      //
      // Note: CORS is NOT handled here — the STUN relay is the final
      // hop to the browser and adds CORS headers there. Adding CORS at
      // both levels causes duplicate Access-Control-Allow-Origin headers
      // which makes the browser reject the response entirely.
      if (path.startsWith("/realms/") || path.startsWith("/resources/") || path.startsWith("/admin")) {
        const publicProto = isTls ? "https" : "http";
        const publicHost = req.headers.host || "localhost";
        const publicBase = `${publicProto}://${publicHost}/_idp`;

        // Get or create a server-side TC session for cookie jar
        const tcSess = getTcSessionId(req);

        const tcProxyHeaders = { ...req.headers };
        tcProxyHeaders.host = tcProxyUrl.host;
        // Strip forwarded headers so TideCloak sees plain HTTP localhost
        // and doesn't redirect to KC_HOSTNAME based on protocol mismatch
        delete tcProxyHeaders["x-forwarded-proto"];
        delete tcProxyHeaders["x-forwarded-host"];
        delete tcProxyHeaders["x-forwarded-for"];
        delete tcProxyHeaders["x-forwarded-port"];
        // Request uncompressed so we can rewrite URLs in the response
        delete tcProxyHeaders["accept-encoding"];

        // Inject stored TC cookies into the proxied request
        const jarCookies = getTcCookieHeader(tcSess.id);
        if (jarCookies) {
          // Merge with any existing cookies from the browser
          const existing = tcProxyHeaders.cookie || "";
          tcProxyHeaders.cookie = existing ? `${existing}; ${jarCookies}` : jarCookies;
        }

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
            rewriteRedirects(headers, tcProxyUrl.origin, undefined, publicBase);

            // Remove any encoding header since we'll serve uncompressed
            delete headers["content-encoding"];
            delete headers["transfer-encoding"];

            // Strip CSP so rewritten cross-origin URLs aren't blocked
            delete headers["content-security-policy"];
            delete headers["content-security-policy-report-only"];

            // Store TC's cookies server-side instead of forwarding to browser
            const rawSC = headers["set-cookie"];
            storeTcCookies(tcSess.id, rawSC);
            // Replace TC's Set-Cookie with our tc_sess cookie.
            // SameSite=None so cross-site iframes (Tide SDK enclave on
            // sork1.tideprotocol.com) can send it back for tidevouchers.
            if (rawSC || tcSess.isNew) {
              headers["set-cookie"] = [
                buildCookieHeader("tc_sess", tcSess.id, TC_SESS_MAX_AGE, "None"),
              ];
            }

            const contentType = (headers["content-type"] || "") as string;
            const isText = contentType.includes("text/") ||
              contentType.includes("application/javascript") ||
              contentType.includes("application/json");
            if (isText) {
              const chunks: Buffer[] = [];
              let totalSize = 0;
              const MAX_RESPONSE = 50 * 1024 * 1024; // 50 MB
              tcProxyRes.on("data", (chunk: Buffer) => {
                totalSize += chunk.length;
                if (totalSize > MAX_RESPONSE) {
                  tcProxyRes.destroy();
                  if (!res.headersSent) {
                    res.writeHead(502, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ error: "Response too large" }));
                  }
                  return;
                }
                chunks.push(chunk);
              });
              tcProxyRes.on("end", () => {
                if (res.headersSent) return;
                let body = Buffer.concat(chunks).toString("utf-8");
                // Rewrite TC internal URLs → public gateway base
                body = body.replaceAll(tcProxyUrl.origin, publicBase);
                body = body.replaceAll(
                  tcProxyUrl.origin.replaceAll("/", "\\/"),
                  publicBase.replaceAll("/", "\\/")
                );
                body = body.replaceAll(
                  encodeURIComponent(tcProxyUrl.origin),
                  encodeURIComponent(publicBase)
                );
                // Rewrite KC_HOSTNAME public URLs in body so admin console
                // auth flow stays on the local gateway instead of going through
                // the STUN relay (different domain = broken cookies).
                // Note: NOT done for Location headers — only body content.
                if (tcPublicOrigin && tcPublicOrigin !== tcProxyUrl.origin) {
                  body = body.replaceAll(tcPublicOrigin, publicBase);
                  body = body.replaceAll(
                    tcPublicOrigin.replaceAll("/", "\\/"),
                    publicBase.replaceAll("/", "\\/")
                  );
                  body = body.replaceAll(
                    encodeURIComponent(tcPublicOrigin),
                    encodeURIComponent(publicBase)
                  );
                }

                delete headers["content-length"];
                res.writeHead(tcProxyRes.statusCode || 502, headers);
                res.end(body);
              });
            } else {
              res.writeHead(tcProxyRes.statusCode || 502, headers);
              tcProxyRes.pipe(res);
            }
          }
        );

        tcProxyReq.setTimeout(30000, () => {
          tcProxyReq.destroy();
          if (!res.headersSent) {
            res.writeHead(504, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Auth server timeout" }));
          }
        });

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

      // Check if this backend skips gateway-side JWT validation
      const isNoAuth = isPublicResource(path) || (activeBackend
        ? noAuthBackends.has(activeBackend)
        : false); // default backend always requires JWT

      let payload: any = null;

      if (isNoAuth) {
        // Backend handles its own auth — skip JWT validation
        stats.authorizedRequests++;
      } else {
        // Extract JWT: cookie first, then Authorization header
        const cookies = parseCookies(req.headers.cookie);
        let token = cookies["gateway_access"] || null;

        if (!token) {
          const authHeader = req.headers.authorization;
          if (authHeader?.startsWith("Bearer ")) {
            token = authHeader.slice(7);
          }
        }

        // Validate JWT
        payload = token ? await options.auth.verifyToken(token) : null;

        // If access token expired, try refreshing with refresh token
        if (!payload && cookies["gateway_refresh"]) {
          const refreshResult = await deduplicatedRefresh(cookies["gateway_refresh"]);
          if (refreshResult) {
            payload = await options.auth.verifyToken(refreshResult.accessToken);
            if (payload) {
              token = refreshResult.accessToken;
              const refreshCookies: string[] = [
                buildCookieHeader(
                  "gateway_access",
                  refreshResult.accessToken,
                  refreshResult.expiresIn
                ),
              ];
              if (refreshResult.refreshToken) {
                refreshCookies.push(
                  buildCookieHeader(
                    "gateway_refresh",
                    refreshResult.refreshToken,
                    refreshResult.refreshExpiresIn || 1800,
                    "Strict"
                  )
                );
              }
              (res as any).__refreshCookies = refreshCookies;
            }
          }
        }

        // No valid token — redirect browser or 401 for API
        if (!payload) {
          stats.rejectedRequests++;
          // Diagnostic: log why auth failed for DC requests
          if (req.headers["x-dc-request"]) {
            const tokenSnippet = token ? `${token.slice(0, 20)}...` : "null";
            console.log(`[Gateway] DC auth failed: url=${url} token=${tokenSnippet} hasRefreshCookie=${!!cookies["gateway_refresh"]}`);
          }

          if (isBrowserRequest(req)) {
            const fullUrl = backendPrefix + url;
            const redirectTarget = encodeURIComponent(fullUrl);
            // Redirect to TideCloak SSO — handles both fresh sessions
            // and expired ones (refresh failed or no refresh token)
            redirect(res, `/auth/login?redirect=${redirectTarget}`);
          } else {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({ error: "Missing or invalid authorization" })
            );
          }
          return;
        }

        stats.authorizedRequests++;

        // ── dest: role enforcement ─────────────────────────
        // Users must have an explicit dest:<gatewayId>:<backendName> role
        // to access any gateway backend. No matching role = 403.
        if (options.gatewayId && payload) {
          // dest:<gatewayId>:<backendName> — split on first and second ':'
          const realmRoles: string[] = (payload as any)?.realm_access?.roles ?? [];
          const clientId = options.tcConfig.resource;
          const clientRoles: string[] = (payload as any)?.resource_access?.[clientId]?.roles ?? [];
          const allRoles = [...realmRoles, ...clientRoles];

          const backend = activeBackend || options.backends?.[0]?.name || "Default";
          const gwIdLower = options.gatewayId!.toLowerCase();
          const backendLower = backend.toLowerCase();
          const hasAccess = allRoles.some((r: string) => {
            if (!/^dest:/i.test(r)) return false;
            // Split "dest:<gatewayId>:<backendName>" on first two colons
            const firstColon = r.indexOf(":");
            const secondColon = r.indexOf(":", firstColon + 1);
            if (secondColon < 0) return false;
            const gwId = r.slice(firstColon + 1, secondColon);
            const bk = r.slice(secondColon + 1);
            return gwId.toLowerCase() === gwIdLower && bk.toLowerCase() === backendLower;
          });
          if (!hasAccess) {
            const destRoles = allRoles.filter((r: string) => /^dest:/i.test(r));
            console.log(`[Gateway] dest role denied: gwId=${options.gatewayId} backend="${backend}" clientId="${clientId}" destRoles=${JSON.stringify(destRoles)} allRolesCount=${allRoles.length}`);
            stats.rejectedRequests++;
            res.writeHead(403, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Forbidden: no dest role for this backend" }));
            return;
          }
        }
      }

      // ── Proxy to backend ─────────────────────────────────

      // DC auth trace (opt-in via DEBUG_DC=true)
      if (process.env.DEBUG_DC && req.headers["x-dc-request"]) {
        console.log(`[Gateway] DC request: url=${req.url} authed=${!!payload} backend=${activeBackend || "default"}`);
      }

      // Validate HTTP method
      if (!ALLOWED_METHODS.has((req.method || "").toUpperCase())) {
        res.writeHead(405, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Method not allowed" }));
        return;
      }

      const proxyHeaders = { ...req.headers };
      delete proxyHeaders.host;

      // Remove auth header: globally (STRIP_AUTH_HEADER) or per-backend (;stripauth)
      if (options.stripAuthHeader || stripAuthBackends.has(activeBackend || "")) {
        delete proxyHeaders.authorization;
      }

      // ── Sanitize client-spoofable headers ─────────────────
      // Strip forwarded headers before setting them from trusted sources.
      // Prevents clients from injecting identities or spoofing IPs.
      // x-gateway-backend is stripped later (line ~998) before proxying —
      // it's needed by resolveBackend() above, and is already JWT-gated.
      delete proxyHeaders["x-forwarded-user"];
      delete proxyHeaders["x-forwarded-for"];
      delete proxyHeaders["x-forwarded-proto"];
      delete proxyHeaders["x-forwarded-host"];
      delete proxyHeaders["x-forwarded-port"];

      if (payload) {
        proxyHeaders["x-forwarded-user"] = payload.sub || "unknown";
      }
      proxyHeaders["x-forwarded-for"] =
        req.socket.remoteAddress || "unknown";

      const targetBackend = resolveBackend(req, activeBackend);
      const targetIsHttps = targetBackend.protocol === "https:";
      const makeBackendReq = targetIsHttps ? httpsRequest : httpRequest;

      // DataChannel requests: inject stored backend cookies (browser can't
      // attach HttpOnly cookies through the SW/DataChannel path)
      const isDcRequest = !!proxyHeaders["x-dc-request"];
      delete proxyHeaders["x-dc-request"]; // don't leak to backend
      delete proxyHeaders["x-gateway-backend"]; // don't leak routing header to backend
      // Request uncompressed responses so we can rewrite HTML (URL prefixing, script injection)
      delete proxyHeaders["accept-encoding"];
      const backendKey = activeBackend || options.backends?.[0]?.name || "default";
      if (isDcRequest && payload?.sub) {
        const jarCookies = getBackendCookieHeader(`${payload.sub}:${backendKey}`);
        if (jarCookies) {
          const existing = (proxyHeaders.cookie as string) || "";
          proxyHeaders.cookie = existing ? `${existing}; ${jarCookies}` : jarCookies;
        }
      }

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

          // Backend cookie jar: store Set-Cookie values server-side so that
          // DataChannel requests (where the browser can't set cookies) still
          // get the right session cookies. Store for ALL authenticated requests
          // — the initial page load (direct HTTP) seeds the jar before DC
          // takes over, preventing session mismatch.
          const cookieJarUser = payload?.sub || "";
          if (cookieJarUser && headers["set-cookie"]) {
            storeBackendCookies(`${cookieJarUser}:${backendKey}`, headers["set-cookie"] as string | string[]);
          }

          // Rewrite redirects: TideCloak → relative, localhost:PORT → /__b/<name>
          rewriteRedirects(headers, tcProxyUrl.origin, portToBackend);

          // Prepend /__b/<name> prefix to relative redirects so backend
          // redirects stay within the correct path namespace
          if (backendPrefix && headers.location && typeof headers.location === "string") {
            const loc = headers.location;
            if (loc.startsWith("/") && !loc.startsWith("/__b/")) {
              headers.location = backendPrefix + loc;
            }
          }

          // Append refresh cookies if token was refreshed
          const refreshCookies = (res as any).__refreshCookies as
            | string[]
            | undefined;
          if (refreshCookies) {
            const existing = headers["set-cookie"] || [];
            const existingArr = Array.isArray(existing)
              ? existing
              : existing ? [existing as string] : [];
            headers["set-cookie"] = [...existingArr, ...refreshCookies];
          }

          // Buffer HTML to rewrite URLs and inject scripts
          const contentType = (headers["content-type"] || "") as string;
          if (contentType.includes("text/html")) {
            const chunks: Buffer[] = [];
            let totalSize = 0;
            const MAX_RESPONSE = 50 * 1024 * 1024; // 50 MB
            proxyRes.on("data", (chunk: Buffer) => {
              totalSize += chunk.length;
              if (totalSize > MAX_RESPONSE) {
                proxyRes.destroy();
                if (!res.headersSent) {
                  res.writeHead(502, { "Content-Type": "application/json" });
                  res.end(JSON.stringify({ error: "Response too large" }));
                }
                return;
              }
              chunks.push(chunk);
            });
            proxyRes.on("end", () => {
              if (res.headersSent) return;
              let html = Buffer.concat(chunks).toString("utf-8");
              // Rewrite localhost:PORT refs → /__b/<name>
              html = rewriteLocalhostInHtml(html);
              // Prepend /__b/<name> to absolute paths in HTML attributes
              if (backendPrefix) {
                html = prependPrefix(html, backendPrefix);
                // Inject fetch/XHR interceptor so JS-initiated requests
                // with absolute paths (e.g. fetch("/api/data")) get the
                // /__b/<name> prefix prepended automatically.
                // Gateway-internal paths (/auth/*, /js/*, /realms/*, etc.) are
                // skipped — they work without the prefix.
                // Escape backendPrefix for safe JS string interpolation (prevents XSS if name contains quotes/backslashes).
                const safePrefix = backendPrefix.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/</g, "\\x3c");
                const patchScript = `<script>(function(){` +
                  `var P="${safePrefix}";` +
                  `var W=/^\\/(js\\/|auth\\/|login|webrtc-config|realms\\/|resources\\/|portal|health)/;` +
                  `function n(u){return typeof u==="string"&&u[0]==="/"&&u.indexOf("/__b/")!==0&&!W.test(u)}` +
                  `var F=window.fetch;window.fetch=function(u,i){` +
                    `if(n(u))u=P+u;` +
                    `else if(u instanceof Request){var r=new URL(u.url);if(r.origin===location.origin&&n(r.pathname)){r.pathname=P+r.pathname;u=new Request(r,u)}}` +
                    `return F.call(this,u,i)};` +
                  `var O=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){` +
                    `if(n(u))arguments[1]=P+u;` +
                    `return O.apply(this,arguments)};` +
                  // Intercept element.src setter (video, audio, img, source, script, iframe)
                  `["HTMLMediaElement","HTMLSourceElement","HTMLImageElement","HTMLScriptElement","HTMLIFrameElement"].forEach(function(c){` +
                    `var E=window[c];if(!E)return;` +
                    `var d=Object.getOwnPropertyDescriptor(E.prototype,"src");if(!d||!d.set)return;` +
                    `Object.defineProperty(E.prototype,"src",{get:d.get,set:function(v){d.set.call(this,n(v)?P+v:v)},configurable:true})` +
                  `});` +
                  // Intercept setAttribute for src/href
                  `var SA=Element.prototype.setAttribute;Element.prototype.setAttribute=function(a,v){` +
                    `if((a==="src"||a==="href")&&typeof v==="string"&&n(v))v=P+v;` +
                    `return SA.call(this,a,v)};` +
                  // Fix CSS url() breakage when /__b/<name> contains apostrophes or spaces:
                  // strip quotes from url('…') / url("…") and percent-encode chars that
                  // are invalid in unquoted CSS url() (spaces, quotes, parens, tabs).
                  // Uses a Proxy on HTMLElement.style for reliable interception.
                  `function q(v){if(typeof v!=="string"||v.indexOf("url(")===-1)return v;` +
                    `return v.replace(/url\\(([^)]*)\\)/g,function(m,i){` +
                      `var u=i.trim();` +
                      `if(u.length>1&&(u[0]==="'"||u[0]==='"')&&u[u.length-1]===u[0])u=u.slice(1,-1);` +
                      `return"url("+u.replace(/ /g,"%20").replace(/'/g,"%27").replace(/"/g,"%22").replace(/\\t/g,"%09")+")"` +
                    `})}` +
                  `var _sd=Object.getOwnPropertyDescriptor(HTMLElement.prototype,"style");` +
                  `if(_sd&&_sd.get){var _wm=new WeakMap();Object.defineProperty(HTMLElement.prototype,"style",{` +
                    `get:function(){var r=_sd.get.call(this),p=_wm.get(r);if(!p){p=new Proxy(r,{` +
                      `set:function(t,k,v){t[k]=q(v);return true},` +
                      `get:function(t,k){var v=t[k];if(typeof v!=="function")return v;` +
                        `if(k==="setProperty")return function(){if(arguments.length>1)arguments[1]=q(arguments[1]);return t.setProperty.apply(t,arguments)};` +
                        `return v.bind(t)}` +
                    `});_wm.set(r,p)}return p},` +
                    `set:_sd.set?function(v){_sd.set.call(this,q(v))}:void 0,` +
                    `configurable:true})}` +
                  `})()</script>`;
                if (html.includes("<head>")) {
                  html = html.replace("<head>", `<head>${patchScript}`);
                } else {
                  html = patchScript + html;
                }
              }
              // Inject WebRTC upgrade script
              if (options.iceServers?.length) {
                const script = `<script src="${backendPrefix}/js/webrtc-upgrade.js" defer></script>`;
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

      proxyReq.setTimeout(30000, () => {
        proxyReq.destroy();
        if (!res.headersSent) {
          res.writeHead(504, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Backend timeout" }));
        }
      });

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
    console.log(`[Proxy] Login: ${scheme}://localhost:${options.listenPort}/auth/login`);
  });

  return {
    server,
    getStats: () => ({ ...stats }),
  };
}
