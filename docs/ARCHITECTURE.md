# Architecture

KeyleSSH is a browser-based SSH console with policy-based cryptographic authorization. The browser performs the SSH protocol; the backend brokers connectivity, blindly, while ORKs (Orchestrated Recluder of Keys - Tide's decentralised network nodes) handle cryptographic signing. Private keys never exist - signing is performed collaboratively across independent ORKs using decentralized cryptography.

## High-Level Diagram

```
┌────────────────────────── Browser ──────────────────────────┐  OIDC login  ┌──── TideCloak Server ─────┐             ┌──── Tide ─────┐
│  React UI + xterm.js + SFTP FileBrowser                     ├─────────────>│                           │             │               │
│  @microsoft/dev-tunnels-ssh (SSH protocol + crypto)         │              │  Identity, Immunity and   │ JWT signing │ Decentralized │
│  heimdall-tide (Policy:1 signing via TideCloak enclave)     │  JWT / Doken │  Access Management Server │<──────────>>│ Cryptography  │
│                                                             │<─────────────┤                           │             │               │
│  1) Login via TideCloak → JWT + Doken                       │              └───────────────────────────┘             │               │
│  2) POST /api/sessions (serverId + sshUser) → sessionId     │             Decentralized authentication               │ Programmable  │
│  3) WS /ws/tcp?serverId=…&sessionId=…&token=JWT             │<─────────────────────────────────────────────────────>>│    Policy     │
│  4) SSH handshake → Policy:1 signing via ORKs               │               SSH authorization signing                │  enforcement  │
│  5) Optional: Open SFTP channel for file operations         │<─────────────────────────────────────────────────────>>│    Engine     │
└───────────────────────────────────────┬─────────────────────┘                                                        └───────────────┘
                                        │ encrypted SSH bytes (WS)
                                        │ (shell + SFTP channels multiplexed)
                                        ▼
┌──────────────────────── Express Server ───────────────────────┐
│ REST API (servers/sessions/admin/ssh-policies/*)              │
│ JWT validation (TideCloak JWKS)                               │
│ SSH policy management (create, approve, commit to Ork)        │
│ WebSocket TCP bridge (/ws/tcp)                                │
│  - validates JWT + sessionId + serverId                       │
│  - enforces serverId → host/port mapping                      │
│  - enforces sshUser allowlist (token roles/claims)            │
│  - forwards raw bytes to SSH server                           │
│                                                               │
│ Optional: forward bytes to external tcp-bridge via BRIDGE_URL │
└───────────────────────────────────────┬───────────────────────┘
                                        │ TCP
                                        ▼
┌────────────────────────── SSH Server ─────────────────────────┐
│ Standard SSH daemon (sshd) - Ed25519 public key auth          │
└───────────────────────────────────────────────────────────────┘
```

## Components

- `client/`: React app (UI, xterm.js, SSH client, SFTP browser, session UX).
- `server/`: Express API + WebSocket bridge + SQLite storage.
- `tcp-bridge/` (optional external deployment): stateless WS↔TCP forwarder.
- `shared/`: shared types + schema/config.

## SSH Connection Flow

1. User selects a server and SSH username in the UI.
2. Client creates a session record via `POST /api/sessions` (requires JWT).
3. Client opens a WebSocket to bridge's `/ws/tcp` including `sessionId` + JWT.
4. Bridge verifies:
   - JWT signature/issuer/expiry (local public JWKS)
   - session exists and belongs to the token user + serverId
   - requested `host:port` matches the configured server (prevents arbitrary host connections)
   - requested `sshUser` is permitted by the token (roles/claims)
5. Bridge opens a TCP connection and forwards bytes.
6. Browser initiates SSH handshake; during auth, triggers Policy:1 signing (see below).
7. Browser completes SSH handshake and opens a shell; xterm.js renders I/O.

## SFTP File Browser

KeyleSSH includes a built-in SFTP file browser that runs alongside the terminal. SFTP uses the same SSH session - no additional authentication required.

### Architecture

```
┌─────────────────────── Browser ────────────────────────────────────────────────┐
│                                                                                │
│  ┌─────────────────────────────────────────────────┐  ┌─────────────────────┐  │
│  │              SSH Session                        │  │    @TideCloak/SDK   │  │   ┌─ TideCloak Server ──┐
│  │  ┌─────────────────┐  ┌─────────────────────┐   │  │┌───────────────────┐│  │   │                     │
│  │  │  Shell Channel  │  │   SFTP Channel      │   │  ││   TideCloak SDK   ├┼──┼──>│        OIDC         │
│  │  │  (terminal I/O) │  │   (file ops)        │   │  │└───────────────────┘│  │   │                     │
│  │  └────────┬────────┘  └──────────┬──────────┘   │  │                     │  │   └─────────────────────┘
│  └───────────┼──────────────────────┼──────────────┘  │                     │  │   ┌─── Tide Network ────┐
│              │                      │                 │┌───────────────────┐│  │   │                     │
│  ┌───────────▼──────────────────────▼──────────────┐  ││Secure Web Enclave ├┼──┼─>>│     Tide's sMPC     │
│  │            @microsoft/dev-tunnels-ssh           │  │└───────────────────┘│  │   │                     │
│  │            (channel multiplexing)               │  │                     │  │   └─────────────────────┘
│  └────────────────────────┬────────────────────────┘  └─────────────────────┘  │
└───────────────────────────┼────────────────────────────────────────────────────┘
                            │ WebSocket (encrypted SSH bytes)
                            ▼
┌──────────────── TCP Blind Bridge ─────────────────────┐
│         Forwards bytes to SSH server                  │
└───────────────────────────┬───────────────────────────┘
                            │ TCP (SSH bytes)
                            ▼
┌────────────────── SSH Server ─────────────────────────┐
│              Terminates SSH session                   │
└───────────────────────────────────────────────────────┘
```

### How It Works

1. User clicks "Files" button in the terminal toolbar.
2. Client opens a new SSH channel on the existing session.
3. Client requests the "sftp" subsystem on that channel.
4. SFTP v3 protocol runs over the channel (same connection, different channel).
5. File operations are performed via SFTP protocol messages.

### SFTP Protocol Implementation

The client implements SFTP v3 (draft-ietf-secsh-filexfer-02) for maximum OpenSSH compatibility:

- **Protocol layer** (`client/src/lib/sftp/`): Constants, types, binary buffer utilities, SftpClient class
- **React hooks** (`client/src/hooks/useSftp.ts`): Directory state, navigation, file operations
- **UI components** (`client/src/components/sftp/`): FileBrowser, FileList, dialogs

### Features

- Browse directories with breadcrumb navigation
- Upload files (drag-drop or file picker)
- Download files
- Create, rename, delete files and folders
- Change permissions (chmod) via properties dialog
- File type icons based on extension
- Right-click context menu
- Resizable split-panel layout (file browser + terminal)

## Policy:1 Authorization Flow

SSH signing uses the Tide Protocol's Policy:1 auth flow with Forseti contracts:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Policy:1 Signing Flow                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Admin Setup (one-time per role):                                      │
│  ┌──────────┐    ┌───────────────┐    ┌─────────────┐    ┌───────────┐ │
│  │ Template │───>│ PolicySign    │───>│ Ork Commit  │───>│ Stored    │ │
│  │ (UI)     │    │ Request       │    │ (enclave)   │    │ Policy    │ │
│  └──────────┘    └───────────────┘    └─────────────┘    └───────────┘ │
│                                                                        │
│  SSH Sign (per connection):                                            │
│  ┌──────────┐    ┌───────────────┐    ┌─────────────┐    ┌───────────┐ │
│  │ SSH      │───>│ Fetch Policy  │───>│ Ork Sign    │───>│ Signature │ │
│  │ Challenge│    │ + Doken       │    │ (enclave)   │    │ Returned  │ │
│  └──────────┘    └───────────────┘    └─────────────┘    └───────────┘ │
│                                                                        │
│  ORK validates:                                                        │
│  - Doken signature and claims                                          │
│  - Policy parameters (role, resource)                                  │
│  - Executes Forseti contract (C# code in sandbox)                      │
│  - Returns signature only if contract returns Allow()                  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Model Patterns

KeyleSSH can support multiple signing patterns but currently only the `Basic` one is implemented:

| Pattern | Model ID | Use Case |
|---------|----------|----------|
| Basic | `BasicCustom<SSH>:BasicCustom<1>` | Standard SSH challenge signing |
| Dynamic | `DynamicCustom<SSH>:DynamicCustom<1>` | When challenge data may change |
| Dynamic Approved | `DynamicApprovedCustom<SSH>:DynamicApprovedCustom<1>` | Requires explicit approval |

### Forseti Contract

The contract entry type is fixed to `Contract`, so policies must declare `public class Contract : IAccessPolicy`.

The SSH contract validates role-based access and serializes the SSH authorization:

```csharp
public class Contract : IAccessPolicy
{
    [PolicyParam(Required = true, Description = "Role required for SSH access")]
    public string Role { get; set; }

    [PolicyParam(Required = true, Description = "Resource identifier for role check")]
    public string Resource { get; set; }

    public PolicyDecision ValidateData(DataContext ctx)
    {
        var parts = Role.Split(':', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[1].Length == 0)                              return PolicyDecision.Deny("Role must be in the form 'prefix:role'.");
        var userRole = parts[1];
        if (ctx == null || ctx.Data == null || ctx.Data.Length == 0)                return PolicyDecision.Deny("No data provided for SSH challenge validation");
        if (ctx.Data.Length < 24)                                                   return PolicyDecision.Deny($"Data too short to be an SSH publickey challenge: {ctx.Data.Length} bytes");
        if (ctx.Data.Length > 8192)                                                 return PolicyDecision.Deny($"Data too large for SSH challenge: {ctx.Data.Length} bytes (maximum 8192)");
        if (!SshPublicKeyChallenge.TryParse(ctx.Data, out var parsed, out var err)) return PolicyDecision.Deny(err);
        if (parsed.PublicKeyAlgorithm != "ssh-ed25519")                             return PolicyDecision.Deny("Only ssh-ed25519 allowed");
        if (parsed.Username != userRole)                                            return PolicyDecision.Deny("Not allowed to log in as " + parsed.Username);
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

    // ... SshPublicKeyChallenge validations implementation ...

}
```

Contract IDs are computed as SHA512 hashes of the C# source code. The actual contract compilation and IL vetting happens on ORKs during policy execution.

## Security Model

Security posture stipulates that no component in this SSH solution needs to be blindly trusted - and everything is verifiable. The KeyleSSH server, TideCloak server, SSH Bridge, SSH destination server, majority of Tide nodes (up to 70%) and majority of admins (up to 70%) can be compromised, and still no secret can be compromised.

> [!NOTE]
> These security levels far exceed industry standards or best possible practices

### Private Key Handling

- **No private keys exist.** The SSH signing key is mathematically split across Tide's decentralised network using Tide's Ineffable Cryptography.
- No single ORK ever holds a complete key; signing requires collaboration across multiple independent nodes.
- No private keys are ever imported, stored, or transmitted - not in the browser, not on servers, nowhere.
- The backend bridge cannot decrypt or modify the SSH traffic; it only forwards raw bytes.
- All cryptographic signing is delegated to Tide's Policy:1 authorization flow that are cryptographically locked.

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

### Remaining threats

- Compromised Tide decentralized network may collude to leak private key (requires over 70% of nodes)
- Compromised KeyleSSH web UI may perform MITM attack (protected and verifiable with Subresource Integrity check)
- Compromised quorum of admins may grant access to an attacker (requires over 70% of admins)

## Storage

- The server uses SQLite (`better-sqlite3`) for:
  - server configs
  - session records (active + historical)

## Embedded vs External TCP Bridge

KeyleSSH always requires a WebSocket→TCP bridge.

- **Default (embedded):** `/ws/tcp` opens the TCP socket itself.
- **External (optional):** set `BRIDGE_URL` and the server forwards the user's JWT to `tcp-bridge/`. Both endpoints independently verify JWTs against the same TideCloak JWKS.

## Local Testing

### Everything together (default)

```bash
npm install
npm run dev
```

### External bridge simulation

```bash
# Terminal 1: Start the bridge (needs data/tidecloak.json)
cd tcp-bridge
npm install
npm run dev

# Terminal 2: Start main server with bridge URL
cd ..
BRIDGE_URL=ws://localhost:8080 npm run dev
```

## TideCloak Notes

- Client adapter config lives in `client/src/tidecloakAdapter.json`.
- Admin capability is derived from TideCloak roles (app normalizes this into `user.role = "admin"` in the backend).

## Deployment

See [docs/DEPLOYMENT.md](DEPLOYMENT.md).
