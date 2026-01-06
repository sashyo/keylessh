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
  - Admin role names (e.g. `tide-realm-admin`, `realm-admin`) treated as "admin" in the app.

### SSH Policy Management (Policy:1 + Forseti)

SSH signing uses Tide Protocol's Policy:1 auth flow with Forseti contracts.

- `client/src/lib/sshPolicy.ts`
  - `SSH_FORSETI_CONTRACT`: The C# Forseti contract source code for SSH authorization
  - `SSH_MODEL_IDS`: Supported model patterns (Basic, Dynamic, DynamicApproved)
  - `createSshPolicyRequest()`: Creates a PolicySignRequest with contract compilation
  - `compileForsetiContract()`: Calls `POST /api/forseti/compile` to deterministically compile C# and return `contractId`
- `client/src/lib/tideSsh.ts`
  - `createTideSshSigner()`: Creates SSH signer using BasicCustomRequest pattern
  - `createDynamicTideSshSigner()`: Creates SSH signer using DynamicCustomRequest pattern
  - Both use `Policy:1` auth flow with doken validation
- `client/src/pages/AdminPolicyTemplates.tsx`
  - UI for creating/managing SSH policy templates
- `client/src/pages/AdminApprovals.tsx`
  - UI for reviewing and approving change requests (access, roles, policies)
  - Tabbed interface with pending counts on nav badge
- `server/routes.ts`
  - `POST /api/admin/ssh-policies/pending`: Creates pending policy from template
  - `POST /api/admin/ssh-policies/pending/:id/approve`: Approves and commits to Ork
  - `GET /api/ssh-policies/for-user/:sshUser`: Fetches committed policy for signing
  - `GET /api/admin/access-approvals`: User access change requests from TideCloak
  - `GET /api/admin/role-approvals`: Role change requests from TideCloak
  - `POST /api/admin/*/approve`, `/reject`, `/commit`, `/cancel`: Change request actions
- `server/storage.ts`
  - `sshPolicies`: Stores pending and committed policies
  - `policyTemplates`: Stores reusable policy templates

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
  - External mode: forwards JWT to `tcp-bridge/` with connection params (`BRIDGE_URL`)
- `tcp-bridge/src/index.ts`
  - Independently validates JWTs against TideCloak JWKS (same `tidecloak.json` config)
  - Forwards raw bytes between WebSocket and TCP socket

### Browser SSH + Terminal (Client)

- `client/src/pages/Console.tsx`
  - xterm.js initialization, FitAddon sizing, UX for connect/disconnect
  - Buffers output until terminal is mounted (prevents "connected but blank terminal")
- `client/src/hooks/useSSHSession.ts`
  - Wraps the browser SSH client lifecycle and persists initial PTY dimensions
  - Exposes `openSftp()`, `closeSftp()`, `sftpClient` for SFTP access
- `client/src/lib/sshClient.ts`
  - `BrowserSSHClient`: creates session record, opens WS, runs SSH handshake via `@microsoft/dev-tunnels-ssh`
  - `openSftp()`: opens SFTP channel on existing SSH session

### SFTP File Browser

SFTP runs over the same SSH session using a separate channel.

- `client/src/lib/sftp/`
  - `protocol.ts`: SFTP v3 constants, types, status codes, helper functions
  - `buffer.ts`: Binary read/write utilities for SFTP packets (SftpBufferWriter, SftpBufferReader)
  - `client.ts`: SftpClient class with all SFTP operations (list, upload, download, rename, delete, chmod, mkdir)
- `client/src/hooks/useSftp.ts`
  - Directory state management (currentPath, entries, loading, error)
  - Navigation (navigateTo, goUp, refresh)
  - File operations (download, upload, remove, rename, mkdir, chmod)
  - Selection management (selectedPaths, toggleSelection, selectAll)
- `client/src/components/sftp/`
  - `FileBrowser.tsx`: Main file browser panel (integrates all components)
  - `FileList.tsx`: File/folder list with context menu and selection
  - `FileIcon.tsx`: File type icons based on extension
  - `FileToolbar.tsx`: Upload, New Folder, Refresh, Delete buttons
  - `PathBreadcrumb.tsx`: Clickable path navigation
  - `NewFolderDialog.tsx`, `RenameDialog.tsx`, `PropertiesDialog.tsx`, `DeleteConfirmDialog.tsx`
- `client/src/components/TerminalSession.tsx`
  - Integrates FileBrowser with ResizablePanelGroup
  - "Files" button toggles split-panel view

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
- `client/src/pages/AdminPolicyTemplates.tsx` (create/manage SSH policy templates)
- `client/src/pages/AdminApprovals.tsx` (Change Requests - tabbed UI for access, role, and policy change requests with auto-refresh)

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

### Debug "can't SSH as user X"

- Verify the JWT contains a role like `ssh:X` (or one of the supported claim names).
- Verify the server's configured `sshUsers` includes that username.
- The backend filters `allowedSshUsers` returned to the UI, so if it's missing, check the token first.

### Work with SSH Policies

SSH policies require a Policy:1 flow through the ORK network:

1. **Create a template** - Admin creates a policy template in `AdminPolicyTemplates.tsx`
2. **Create pending policy** - Template generates a `PolicySignRequest` with contract code
3. **Approve policy** - Admin reviews and approves in Change Requests page (Policies tab)
4. **Commit to ORKs** - Approval commits the signed policy to the ORK network
5. **Sign requests** - When user SSHs, `tideSsh.ts` fetches the policy and sends to ORKs

Key debugging steps:
- Check browser console for `[TideSsh]` logs during signing
- Verify policy exists: `GET /api/ssh-policies/for-user/:sshUser`
- Check ORK logs for contract validation errors
- Ensure doken contains the required role for the policy's resource

### Modify the Forseti Contract

The SSH contract is in `client/src/lib/sshPolicy.ts` as `SSH_FORSETI_CONTRACT`.

To modify:
1. Edit the C# code in `SSH_FORSETI_CONTRACT`
2. Contract ID is computed via `POST /api/forseti/compile` on policy creation (SHA512 hash of source code)
3. ORKs compile and IL-vet the contract during policy execution (blocks forbidden namespaces)
4. Test with a new policy template to get the new contractId

## Related Docs

- Architecture: [docs/ARCHITECTURE.md](ARCHITECTURE.md)
- Deployment: [docs/DEPLOYMENT.md](DEPLOYMENT.md)
