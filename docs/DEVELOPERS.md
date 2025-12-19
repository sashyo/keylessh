# Developer Guide

This repo is a monorepo with three runtimes:

- `client/`: React + Vite UI (xterm.js terminal + browser SSH client)
- `server/`: Express REST API + WebSocket TCP bridge + SQLite storage
- `tcp-bridge/`: optional external WS↔TCP forwarder (stateless)

If you’re new to the codebase, start with the “Where to look” section.

## Quickstart

```bash
npm install
npm run dev
```

App: `http://localhost:3000`

## Where To Look (Important Files)

### Authentication + Roles

- `server/auth.ts`
  - `authenticate` middleware: verifies JWT via TideCloak JWKS and populates `req.user` and `req.tokenPayload`.
  - `requireAdmin`: checks `req.user.role === "admin"` (this is a normalized app role derived from TideCloak roles).
- `server/lib/auth/tideJWT.ts`
  - JWT verification (`verifyTideCloakToken`) using local JWKS from config.
- `shared/config/roles.ts`
  - Admin role names (e.g. `tide-realm-admin`, `realm-admin`) treated as “admin” in the app.

### SSH Username Authorization

SSH username access is token-based (applies to everyone, including admins).

- `server/lib/auth/sshUsers.ts`
  - Extracts allowed SSH usernames from token:
    - roles `ssh:<username>` or `ssh-<username>`
    - claims in `shared/config/claims.ts`
- `server/routes.ts`
  - `GET /api/servers*`: returns `allowedSshUsers` filtered by token
  - `POST /api/sessions`: denies session creation if requested `sshUser` isn’t allowed by token
- `server/wsBridge.ts`
  - Re-checks `sshUser` allowlist at the WebSocket layer (prevents bypass)

### WebSocket TCP Bridge (SSH Connectivity)

- `server/wsBridge.ts`
  - `/ws/tcp` WebSocket endpoint
  - Validates: JWT, session ownership, serverId→host/port mapping, sshUser allowlist
  - Local mode: opens TCP sockets directly
  - External mode: forwards to `tcp-bridge/` using a short-lived HMAC token (`BRIDGE_URL`, `BRIDGE_SECRET`)
- `tcp-bridge/src/index.ts`
  - Does not validate JWTs; only validates HMAC token from main server and forwards raw bytes.

### Browser SSH + Terminal (Client)

- `client/src/pages/Console.tsx`
  - xterm.js initialization, FitAddon sizing, UX for connect/disconnect
  - Buffers output until terminal is mounted (prevents “connected but blank terminal”)
- `client/src/hooks/useSSHSession.ts`
  - Wraps the browser SSH client lifecycle and persists initial PTY dimensions
- `client/src/lib/sshClient.ts`
  - `BrowserSSHClient`: creates session record, opens WS, runs SSH handshake via `@microsoft/dev-tunnels-ssh`

### Storage

- `server/storage.ts`
  - SQLite access for servers and sessions
- `shared/schema.ts`
  - Drizzle schema + shared types used on both client/server

### Admin UI (Pages)

- `client/src/pages/AdminDashboard.tsx` (overview)
- `client/src/pages/AdminServers.tsx` (server CRUD)
- `client/src/pages/AdminUsers.tsx` (assign existing roles to users)
- `client/src/pages/AdminRoles.tsx` (create roles, includes SSH role helper/auto-prefix)
- `client/src/pages/AdminSessions.tsx` (active sessions; terminate)
- `client/src/pages/AdminLogs.tsx` (Access + Sessions logs)
- `client/src/pages/AdminApprovals.tsx` (approvals; auto-refresh)

## Contributing Workflow

1. Keep changes tight and scoped to the requested behavior.
2. Prefer server-side enforcement for security controls (UI is not trusted).
3. After changing types shared across boundaries:
   - update `shared/schema.ts` first
   - then update `server/` and `client/` usages
4. Run:
   - `npm run check`
   - `npm run build` (may require permissions depending on your sandbox)

## Common Tasks

### Add a new API endpoint

- Add route in `server/routes.ts`
- If it needs auth, wrap with `authenticate` / `requireAdmin`
- Add client call in `client/src/lib/api.ts`
- Add UI in `client/src/pages/*`

### Add an admin action (mutations)

- Prefer `queryClient.invalidateQueries(...)` + `queryClient.refetchQueries(...)` after success so the UI updates immediately.

### Debug “can’t SSH as user X”

- Verify the JWT contains a role like `ssh:X` (or one of the supported claim names).
- Verify the server’s configured `sshUsers` includes that username.
- The backend filters `allowedSshUsers` returned to the UI, so if it’s missing, check the token first.

