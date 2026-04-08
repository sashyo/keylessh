<div align="center">
  <img src="client/public/favicon.svg" width="96" height="96" alt="KeyleSSH logo" />
  <h1>KeyleSSH</h1>
  <p><strong>Truly keyless SSH.</strong></p>
  <p>The world's first SSH client where private keys don't exist - not on servers, not in bastions, not in browsers, not even in memory. Powered by Tide's decentralised cryptography.</p>
</div>

<p align="center">
  <img src="docs/demo.gif" alt="KeyleSSH Demo" width="800" />
</p>

## What Makes KeyleSSH Different

Traditional SSH clients have a fundamental problem: private keys. Whether stored on a server, uploaded by users, or generated in the browser, private keys will always be the greatest security liability - they can be stolen, leaked, or compromised.

**KeyleSSH eliminates private keys entirely.**

Instead of managing keys, KeyleSSH uses [Tide technology](https://tide.org) for all its cryptographic operations. SSH authorization signing happens across a **decentralised network of independent nodes called ORKs** (Orchestrated Recluders of Keys) - no single point ever holds a complete key. This isn't just distributed, it's truly decentralised (the key never exists as a whole under any single organization).

### How It Works

1. **No key import, no key storage** - Users authenticate via TideCloak (OIDC), receiving a "doken" (delegated token)
2. **Policy-based authorization** - Admins define who can SSH as which SSH user under what role, via **Forseti** contracts (C# policies executed in sandboxed ORKs)
3. **Decentralised signing** - When SSH needs a authorization signature, ORKs validate against the policy and collaboratively sign the challenge
4. **Threshold cryptography** - The signing key exists mathematically split across multiple independent ORKs; no single node can sign alone
5. **Blind bastion tunneling** - All SSH session are tunneled through an oblivious jumpbox that has no access or knowledge of to the content of the session

The result: enterprise-grade SSH access control without any private keys to manage, rotate, or protect.

## Features

- **Browser-side SSH** via `@microsoft/dev-tunnels-ssh` + `xterm.js`, with no private keys anywhere
- **SFTP file browser** - Browse, upload, download, rename, delete files via split-panel UI
- **Quorum-based RBAC, zero-knowledge OIDC login** with TideCloak - no passwords, no keys
- **Programmable policy enforcement** with Forseti contracts for SSH access
- **Admin UX**: servers, users, roles, policy templates, change requests, sessions, logs
- **Browser-based RDP** - full Windows remote desktop in a browser tab via [IronRDP](https://github.com/sashyo/IronRDP/tree/feat/ironrdp-tls-wasm) WASM (forked to add e2e TLS in WASM via WebCrypto). No client install, no ports to open, no VPN. Passwordless login via TideSSP EdDSA certificates.
- **QUIC VPN** - native VPN client with TUN adapter, NAT hole-punching (LAN → direct → TURN relay fallback), per-user firewall rules from JWT roles, auto LAN route detection
- **P2P transport** - automatic upgrade from HTTP relay to direct peer-to-peer WebRTC DataChannels (browsers) or QUIC P2P (native VPN), with TURN relay fallback for restrictive NATs
- **Signal server** (`signal-server-rs/`) - Rust signaling hub coordinating P2P connections via WebSocket (SDP/ICE), HTTP relay, gateway registry, and ephemeral TURN credential generation. Deployed with a coturn sidecar for STUN/TURN.
- **Multi-backend routing** (`bridges/punchd-bridge-rs/`) - proxy to multiple HTTP backends and RDP servers from a single gateway, with per-backend auth flags (eddsa, noauth, stripauth)

## Downloads

Each [release](../../releases) includes pre-built binaries and installers:

| Artifact | Platform | Description |
|----------|----------|-------------|
| `PunchdEndpoint.msi` | Windows | **PunchdEndpoint** — Combined installer: TideSSP (passwordless RDP) + Punchd Gateway (Rust, runs as Windows service). Includes setup wizard for tidecloak.json and gateway.toml. Reboot required. |
| `punchd-gateway-linux.deb` | Linux | **Punchd Gateway** — NAT-traversing reverse proxy + QUIC VPN gateway. Runs on your private network, connects to signal server, proxies HTTP/RDP/VPN to local backends. |
| `punchd-gateway-macos-x64` | macOS x64 | Punchd Gateway for macOS Intel |
| `punchd-gateway-macos-arm64` | macOS | Punchd Gateway for macOS Apple Silicon |
| `punchd-vpn.msi` | Windows | **Punchd VPN** — Native VPN client with WebView2 DPoP auth, system tray, and auto-reconnect. |
| `ssh-bridge-linux-x64.tar.gz` | Linux | **SSH Bridge** (Rust) — WebSocket-to-TCP tunnel for browser SSH sessions. |

All components require a `tidecloak.json` exported from your TideCloak admin console. See the [Deployment Guide](docs/DEPLOYMENT.md) for step-by-step setup.

## Project Structure

```
keylessh/
├── client/                  # React UI (xterm.js, SSH client, SFTP browser, admin)
├── server/                  # Express API + WebSocket bridge + SQLite
├── shared/                  # Shared types + schema
├── signal-server-rs/        # Rust signal server (signaling, HTTP relay, TURN creds)
├── bridges/
│   ├── ssh-bridge-rs/       # Rust SSH bridge (WS↔TCP tunnel, JWT auth)
│   ├── punchd-bridge-rs/    # Punchd Gateway (Rust) — WebRTC, QUIC VPN, HTTP proxy
│   └── tcp-bridge/          # Stateless WS↔TCP forwarder (optional)
├── tide-ssp/                # Windows SSP for passwordless RDP (C + WiX MSI)
├── docs/                    # Architecture, deployment, developer guides
└── script/                  # TideCloak setup scripts
```

## Documentation

- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Deployment: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Developer guide: [docs/DEVELOPERS.md](docs/DEVELOPERS.md)

### Component docs

- [Punchd Gateway (Rust)](bridges/punchd-bridge-rs/README.md) — WebRTC + QUIC VPN gateway, multi-backend routing, RDCleanPath, VPN firewall, TURN relay
- [Signal Server (Rust)](signal-server-rs/deploy.sh) — WebSocket signaling, HTTP relay, gateway registry, TURN credential generation, coturn sidecar
- [TideSSP](tide-ssp/README.md) — Windows Security Support Provider for passwordless RDP via EdDSA JWT

## Quickstart (Local Dev)

### 1. Clone and start TideCloak

```bash
git clone https://github.com/sashyo/keylessh.git
cd keylessh/script/tidecloak
./start.sh
```

### 2. Activate your free Tide subscription

During initialization, you'll be prompted to:

1. **Enter an email to manage your license** - Provide a valid email address for your Tide subscription
2. **Accept the Terms & Conditions** - Review the terms at https://tide.org/legal and enter `y` or `yes` to agree

### 3. Link your Tide account

The script will generate an invite link:

```
INVITE LINK (use this one):
http://localhost:8080/realms/keylessh/login-actions/action-token?key=...
```

Open this link in your browser and either:
- Create a new  tide account, or
- Sign in with your existing Tide account

### 4. Wait for initialization

The script will detect when linking is complete and continue finishing the setup:

```
Tidecloak initialization complete!
```

### 5. Start the app

```bash
cd ../..  # back to keylessh root
npm install
npm run dev
```

Access the KeyleSSH app in your browser at: `http://localhost:3000`

Before you can test SSH, you need a target server. Follow the [Example SSH server setup](#example-ssh-server-setup) below to spin one up locally.

## Example SSH server setup

This guide spins up a minimal Alpine SSH server on your localhost and walks through configuring KeyleSSH to connect to it. Assumes you've already completed the [Quickstart](#quickstart-local-dev) above and have KeyleSSH running at `http://localhost:3000`.

> [!NOTE]
> This will create a Docker container listening on port 2222 with a `user` account configured for key-based (passwordless) authentication.

### Step 1: Spin up the SSH server

```bash
sudo docker run -d \
  -p 2222:22 \
  --name tinyssh \
  alpine sh -c "
    apk add --no-cache openssh && \
    ssh-keygen -A && \
    echo 'root:root' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    /usr/sbin/sshd -D
  "
```

### Step 2: Configure KeyleSSH

1. Go to [Servers](http://localhost:3000/admin/servers) > `Add Server`
   - Server Name: _myserver_
   - Host: _localhost_
   - Port: _2222_
   - SSH Users: _user_
   - Click `Add Server` — status should show `Online`

2. Go to [Roles](http://localhost:3000/admin/roles) > `Add Role`
   - Select `SSH` role type
   - Role Name: user (auto-changes to `ssh:user`)
   - Click `Create Role`

3. Go to [Users](http://localhost:3000/admin/users)
   - Click the `Action` button for the default admin user
   - Click the `ssh:user` tag in `Available Roles` to move it to `Assigned Roles`
   - Click `Save Changes`

4. Go to [Change Requests](http://localhost:3000/admin/approvals)
   - Click `Review` for the user admin > confirm with `Y` > `Submit Approvals` > `Commit`
   - Switch to the `Policies` tab (click `Refresh` if empty)
   - Click `Review` for `ssh:user` > confirm with `Y` > `Submit Approvals` > `Commit`

5. Expand your user profile (bottom-left icon) > click `Restart session`

### Step 3: Get the public key

6. Go to [Servers](http://localhost:3000/admin/servers) and click on `myserver`
   - Copy the "Tide SSH public key" shown on the server details page (click the `Copy` button)

### Step 4: Set up the SSH user

Connect to the Alpine container and create the `user` account with the copied public key:

```bash
ssh root@localhost -p 2222
# password: root
```

In the SSH session, run these commands (replace `blahblahblah` with your actual Tide SSH public key):

```bash
adduser -D -s /bin/sh user
passwd -d user
mkdir -p /home/user/.ssh
chmod 700 /home/user/.ssh
chown user:user /home/user/.ssh
echo "ssh-ed25519 blahblahblah user@keylessh" > /home/user/.ssh/authorized_keys
chmod 600 /home/user/.ssh/authorized_keys
chown user:user /home/user/.ssh/authorized_keys
```

### Step 5: Connect

1. Go to [Dashboard](http://localhost:3000/app)
2. Click on `myserver`
3. Select SSH user `user`
4. Click `Connect`
5. In the "Authorize SSH Session" dialog, click `Authorize & Connect`

Your SSH session to `myserver` will start.

> [!IMPORTANT]
> **CSP iframe error?** The secure enclave (TideCloak/Heimdall) is loaded in a hidden iframe to share the session ID. If you see a console error like `Framing 'http://localhost:XXXX/' violates the Content Security Policy directive: "frame-src ..."`, add the blocked origin to the `frame-src` list in [`server/index.ts`](server/index.ts). See [Troubleshooting](docs/DEVELOPERS.md#troubleshooting) for details.


## Scripts

- `npm run dev` - start server + Vite dev integration
- `npm run build` - build client + bundle server
- `npm start` - run production build from `dist/`
- `npm run check` - TypeScript typecheck

## Configuration

### Environment variables

```env
PORT=3000

# Optional external TCP bridge (for scaling)
# Bridge verifies JWTs against same tidecloak.json - no shared secret needed
BRIDGE_URL=ws://localhost:8080

# SQLite (file path)
DATABASE_URL=./data/keylessh.db
```

### TideCloak configuration

The KeyleSSH Server JWT verification config (holding the JWKS keychain) must be downloaded and put here: `data/tidecloak.json` .
See any of the [guides](https://docs.tidecloak.com/Languages/React/tidecloak-react-tutorial-quickstart?_highlight=Download%20adaptor%20configs#1-prepare-tidecloak) for instructions.

## Key Dependencies

- Authentication: `@tidecloak/react` (wraps/uses `@tidecloak/js`)
- Tide Protocol: `heimdall-tide` (Policy, PolicySignRequest, TideMemory for signing)
- Terminal: `@xterm/xterm`
- Browser SSH: `@microsoft/dev-tunnels-ssh` and `@microsoft/dev-tunnels-ssh-keys`
- API state: `@tanstack/react-query`
- Server: `express`, `ws`
- Storage: `better-sqlite3`, `drizzle-orm`

## Policy:1 Authorization

SSH signing uses the Tide Protocol's Policy:1 auth flow with Forseti contracts:

1. Admin creates SSH policies via policy templates (defines role, resource, approval type)
2. Policies are signed and committed to the ORK network
3. When a user connects via SSH, their doken is validated against the policy
4. ORKs execute the Forseti contract (C# code in sandbox) to authorize
5. If authorized, ORKs collaboratively produce a signature for the SSH challenge

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full flow diagram.

## Contributing

See [docs/DEVELOPERS.md](docs/DEVELOPERS.md).

## Deployment Options

KeyleSSH is **open source** and designed for flexible deployment:

### Self-Hosted (No Limits)
Deploy KeyleSSH for your organization with **no usage restrictions**. By default, there are no limits on users, servers, or features. Perfect for:
- Enterprise internal deployments
- Development teams
- Personal/homelab use

Just follow the [Deployment Guide](docs/DEPLOYMENT.md) - no licensing configuration needed.

### SaaS Mode (Tiered Billing)
If you want to offer KeyleSSH as a commercial service with subscription tiers, configure Stripe billing:
- Free tier: 5 users, 2 servers
- Pro tier: 25 users, 10 servers
- Enterprise tier: Unlimited

See [SaaS Configuration](docs/DEPLOYMENT.md#saas-mode-stripe-billing) in the deployment guide.

## License

MIT
