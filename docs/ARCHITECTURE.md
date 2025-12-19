# Architecture

KeyleSSH is a browser-based SSH console. The browser performs the SSH protocol and encryption; the backend only brokers connectivity and authorization.

## High-Level Diagram

```
┌────────────────────────── Browser ──────────────────────────┐
│  React UI + xterm.js                                         │
│  @microsoft/dev-tunnels-ssh (SSH protocol + crypto)          │
│                                                             │
│  1) OIDC login via TideCloak → JWT                           │
│  2) POST /api/sessions (serverId + sshUser) → sessionId      │
│  3) WS /ws/tcp?serverId=…&sessionId=…&token=JWT              │
└───────────────────────────────────────┬─────────────────────┘
                                        │ encrypted SSH bytes (WS)
                                        ▼
┌──────────────────────── Express Server ──────────────────────┐
│ REST API (servers/sessions/admin/*)                          │
│ JWT validation (TideCloak JWKS)                              │
│ WebSocket TCP bridge (/ws/tcp)                               │
│  - validates JWT + sessionId + serverId                      │
│  - enforces serverId → host/port mapping                      │
│  - enforces sshUser allowlist (token roles/claims)           │
│  - forwards raw bytes to SSH server                          │
│                                                             │
│ Optional: forward bytes to external tcp-bridge/ via BRIDGE_URL│
└───────────────────────────────────────┬─────────────────────┘
                                        │ TCP
                                        ▼
┌────────────────────────── SSH Server ────────────────────────┐
│ Standard SSH daemon (sshd)                                   │
└──────────────────────────────────────────────────────────────┘
```

## Components

- `client/`: React app (UI, xterm.js, SSH client, session UX).
- `server/`: Express API + WebSocket bridge + SQLite storage.
- `tcp-bridge/` (optional deployment): stateless WS↔TCP forwarder.
- `shared/`: shared types + schema/config.

## SSH Connection Flow

1. User selects a server and SSH username in the UI.
2. Client creates a session record via `POST /api/sessions` (requires JWT).
3. Client opens a WebSocket to `/ws/tcp` including `sessionId` + JWT.
4. Server verifies:
   - JWT signature/issuer/expiry (local JWKS)
   - session exists and belongs to the token user + serverId
   - requested `host:port` matches the configured server (prevents arbitrary host connections)
   - requested `sshUser` is permitted by the token (roles/claims)
5. Server opens a TCP connection (locally or via external bridge) and forwards bytes.
6. Browser completes SSH handshake and opens a shell; xterm.js renders I/O.

## Security Model

### Private Key Handling

- Private keys are imported in the browser and never sent to the backend.
- The backend cannot decrypt SSH traffic; it only forwards raw bytes.

### JWT Verification

- HTTP routes use `server/auth.ts` middleware.
- WebSocket bridge uses `server/wsBridge.ts` and verifies JWTs before connecting.

### SSH Username Authorization (Token-Based)

KeyleSSH gates which OS usernames a user can SSH as using their JWT.

Supported mappings:

- **Roles (recommended):** `ssh:<username>` or `ssh-<username>` (example: `ssh:root`)
- **Claims:** `ssh_users`, `sshUsers`, `allowed_ssh_users`, `allowedSshUsers` (array or comma-separated string)

Enforced in:

- `POST /api/sessions` (session creation)
- `/ws/tcp` (WebSocket TCP bridge)

This applies to everyone (including admins). If the token does not include the requested SSH username, the connection is denied.

## Storage

- The server uses SQLite (`better-sqlite3`) for:
  - server configs
  - session records (active + historical)

## Embedded vs External TCP Bridge

KeyleSSH always requires a WebSocket→TCP bridge.

- **Default (embedded):** `/ws/tcp` opens the TCP socket itself.
- **External (optional):** set `BRIDGE_URL` and the server forwards encrypted bytes to `tcp-bridge/` using a short-lived HMAC-signed token (`BRIDGE_SECRET`).

The external bridge does **not** validate JWTs; JWT validation happens in the main server before forwarding.

## Local Testing

### Everything together (default)

```bash
npm install
npm run dev
```

### External bridge simulation

```bash
cd tcp-bridge
npm install
BRIDGE_SECRET=test-secret npm run dev

cd ..
BRIDGE_URL=ws://localhost:8080 BRIDGE_SECRET=test-secret npm run dev
```

## TideCloak Notes

- Client adapter config lives in `client/src/tidecloakAdapter.json`.
- Admin capability is derived from TideCloak roles (app normalizes this into `user.role = "admin"` in the backend).

## Deployment

See [docs/DEPLOYMENT.md](DEPLOYMENT.md).
