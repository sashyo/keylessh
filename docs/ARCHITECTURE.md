# Architecture

KeyleSSH is a browser-based SSH console with policy-based cryptographic authorization. The browser performs the SSH protocol; the backend brokers connectivity while ORKs (Orchestrated Recluded Keys - Tide's decentralised node network) handle cryptographic signing. Private keys never exist - signing is performed collaboratively across independent ORKs using threshold cryptography.

## High-Level Diagram

```
┌────────────────────────── Browser ──────────────────────────┐
│  React UI + xterm.js                                         │
│  @microsoft/dev-tunnels-ssh (SSH protocol + crypto)          │
│  heimdall-tide (Policy:1 signing via TideCloak enclave)      │
│                                                             │
│  1) OIDC login via TideCloak → JWT + Doken                   │
│  2) POST /api/sessions (serverId + sshUser) → sessionId      │
│  3) WS /ws/tcp?serverId=…&sessionId=…&token=JWT              │
│  4) SSH handshake → Policy:1 signing via Ork enclave         │
└───────────────────────────────────────┬─────────────────────┘
                                        │ encrypted SSH bytes (WS)
                                        ▼
┌──────────────────────── Express Server ──────────────────────┐
│ REST API (servers/sessions/admin/ssh-policies/*)             │
│ JWT validation (TideCloak JWKS)                              │
│ SSH policy management (create, approve, commit to Ork)       │
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
6. Browser initiates SSH handshake; during auth, triggers Policy:1 signing (see below).
7. Browser completes SSH handshake and opens a shell; xterm.js renders I/O.

## Policy:1 Authorization Flow

SSH signing uses the Tide Protocol's Policy:1 auth flow with Forseti contracts:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Policy:1 Signing Flow                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Admin Setup (one-time per role):                                       │
│  ┌──────────┐    ┌───────────────┐    ┌─────────────┐    ┌───────────┐ │
│  │ Template │───▶│ PolicySign    │───▶│ Ork Commit  │───▶│ Stored    │ │
│  │ (UI)     │    │ Request       │    │ (enclave)   │    │ Policy    │ │
│  └──────────┘    └───────────────┘    └─────────────┘    └───────────┘ │
│                                                                         │
│  SSH Sign (per connection):                                             │
│  ┌──────────┐    ┌───────────────┐    ┌─────────────┐    ┌───────────┐ │
│  │ SSH      │───▶│ Fetch Policy  │───▶│ Ork Sign    │───▶│ Signature │ │
│  │ Challenge│    │ + Doken       │    │ (enclave)   │    │ Returned  │ │
│  └──────────┘    └───────────────┘    └─────────────┘    └───────────┘ │
│                                                                         │
│  Ork validates:                                                         │
│  - Doken signature and claims                                           │
│  - Policy parameters (role, resource)                                   │
│  - Executes Forseti contract (C# code in sandbox)                       │
│  - Returns signature only if contract returns Allow()                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Model Patterns

KeyleSSH supports multiple signing patterns:

| Pattern | Model ID | Use Case |
|---------|----------|----------|
| Basic | `BasicCustom<SSH>:BasicCustom<1>` | Standard SSH challenge signing |
| Dynamic | `DynamicCustom<SSH>:DynamicCustom<1>` | When challenge data may change |
| Dynamic Approved | `DynamicApprovedCustom<SSH>:DynamicApprovedCustom<1>` | Requires explicit approval |

### Forseti Contract

The SSH contract validates role-based access:

```csharp
public class SshPolicy : IAccessPolicy
{
    public PolicyDecision Authorize(AccessContext ctx)
    {
        // Validate policy has required role parameter
        if (!policy.TryGetParameter<string>("role", out var requiredRole))
            return PolicyDecision.Deny("Missing role parameter");

        // Check user's doken contains the required role
        if (!doken.Payload.ResourceAccessRoleExists(resource, requiredRole))
            return PolicyDecision.Deny("User lacks required role");

        return PolicyDecision.Allow();
    }
}
```

Contracts are compiled using a standalone compiler container (`ghcr.io/tide-foundation/forseti-compiler`) and IL-vetted by ORK before execution. The compiler runs in Docker on the Keyle-SSH server to ensure hash consistency with ORK's compilation. See [DEPLOYMENT.md](DEPLOYMENT.md#forseti-contract-compiler) for configuration.

## Security Model

### Private Key Handling

- **No private keys exist.** SSH signing keys are mathematically split across Tide's decentralised ORK network using threshold cryptography.
- No single ORK holds a complete key; signing requires collaboration across multiple independent nodes.
- No private keys are ever imported, stored, or transmitted - not in the browser, not on servers, nowhere.
- The backend cannot decrypt SSH traffic; it only forwards raw bytes.
- All cryptographic signing is delegated to Tide's Policy:1 authorization flow.

### JWT Verification

- HTTP routes use `server/auth.ts` middleware.
- WebSocket bridge uses `server/wsBridge.ts` and verifies JWTs before connecting.

### Policy-Based Cryptographic Authorization

- SSH signing requires Policy:1 authorization from the ORK network.
- Policies are created via templates and committed to the ORK network.
- Each signing request includes the user's doken (delegated token) for validation.
- Forseti contracts (C# code) run in isolated sandbox processes on each ORK with:
  - IL vetting (blocks forbidden namespaces like System.IO, System.Net)
  - Process isolation (separate VmHost process per execution)
  - Gas metering (prevents infinite loops)
  - Memory/CPU limits

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
