# Deployment Guide

KeyleSSH has several deployable components. This guide walks through deploying each one in order, since later components depend on configuration from earlier ones.

## Overview

| Component | What it does | Runs on | Required? |
|-----------|-------------|---------|-----------|
| **Main Server** | React UI + REST API + built-in SSH bridge | Linux VM / container | Yes |
| **TideCloak** | Authentication & authorization (OIDC) | Docker | Yes |
| **Signal Server** | WebRTC signaling + HTTP relay + STUN/TURN | Public-facing Linux VM | For remote access via Punchd |
| **Punchd Gateway** | NAT-traversing reverse proxy + QUIC VPN + SSH | Private network | For RDP / web app / SSH / VPN |
| **Punchd VPN** | QUIC P2P VPN client with WebView2 DPoP | User device | For VPN tunnel to gateway LAN |
| **TideSSP** | Passwordless RDP via Ed25519 SSP | Windows RDP target | For passwordless RDP |

**Deployment order:**

1. TideCloak (provides `tidecloak.json` used by everything else)
2. Signal Server (provides URL + secrets used by gateways) — optional for local-only deployments
3. Punchd Gateway (connects to signal server, or runs standalone in local/offline mode)
4. TideSSP (on each Windows RDP target machine) — optional, for passwordless RDP

---

## 1. TideCloak

TideCloak provides OIDC authentication. After setup, you'll create clients and export adapter configs.

### Create clients

You need **two clients** in your TideCloak realm:

1. **Application client** (e.g. `keylessh`) — used by the main server, gateways, and SSH bridge for JWT verification and OIDC login. This is the client whose roles (`dest:`, `ssh:`) control user access.

2. **Signal server client** (e.g. `keylessh-signal`) — used by the signal server for JWT verification of gateway registrations. This client needs either:
   - **Full scope mapping** enabled (so it can see all roles from the application client), or
   - The application client (`keylessh`) updated to include signal server role management (so `dest:` and `ssh:` roles appear in tokens issued for the signal server client too).

   If using the `keylessh` app client for all role management (recommended), set `TC_CLIENT_ID=keylessh` on the signal server so it looks up roles under `resource_access.keylessh` regardless of what `"resource"` is in the signal server's own `tidecloak.json`.

### Export tidecloak.json

For each client:

1. Open **TideCloak Admin Console**
2. Go to **Clients > the client > Action dropdown > Download adapter config**
3. Save as `tidecloak.json` (one per component that needs it)

The application client's `tidecloak.json` is used by gateways, SSH bridge, TideSSP, and the main server. The signal server client's `tidecloak.json` is used by the signal server.

### TC_CLIENT_ID override

If your `tidecloak.json` has a different `resource` value than the client ID used for roles in the token (e.g. the config says `"resource":"myclient"` but roles are under `resource_access.keylessh`), set `TC_CLIENT_ID` to override it:

```bash
TC_CLIENT_ID=keylessh  # overrides tidecloak.json's "resource" field
```

This is supported by both the Punch'd Bridge and SSH Bridge.

---

## 2. Signal Server

The signal server is the public entry point. It coordinates WebRTC connections between browsers and gateways, and relays HTTP traffic as a fallback.

**The signal server needs its own TideCloak client** (e.g. `keylessh-signal`) — see step 1. Use this client's `tidecloak.json` when deploying the signal server.

### Deploy with Docker

```bash
cd signal-server
./deploy.sh
```

The script will:
- Auto-generate `API_SECRET` and `TURN_SECRET` (saved to `.env`)
- Detect your public IP
- Build the Docker image
- Start the signal server (port 9090) and coturn (port 3478)
- Print connection details

### Save these values

After deployment, the script outputs:

```
Signal:     https://YOUR_IP:9090
Signaling:  wss://YOUR_IP:9090
STUN/TURN:  YOUR_IP:3478
API_SECRET: <generated>
TURN_SECRET: <generated>
```

**Save `API_SECRET` and `TURN_SECRET`** — you'll pass them to each Punch'd Bridge gateway.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 9090 | Listen port |
| `API_SECRET` | — | Shared secret for gateway registration |
| `TURN_SECRET` | — | Shared secret for TURN credentials |
| `TIDECLOAK_CONFIG_B64` | — | Base64-encoded `tidecloak.json` |
| `TLS_CERT_PATH` | — | TLS certificate (enables HTTPS/WSS) |
| `TLS_KEY_PATH` | — | TLS private key |
| `ICE_SERVERS` | — | STUN servers, e.g. `stun:YOUR_IP:3478` |
| `TURN_SERVER` | — | TURN server, e.g. `turn:YOUR_IP:3478` |
| `ALLOWED_ORIGINS` | same-origin | Comma-separated CORS origins |
| `TC_CLIENT_ID` | from `tidecloak.json` | Set to `keylessh` if using the app client for all role management |

### Firewall rules

Open these ports on the signal server VM:

| Port | Protocol | Purpose |
|------|----------|---------|
| 9090 | TCP | Signal server (HTTP + WebSocket) |
| 3478 | UDP + TCP | STUN/TURN |
| 49152–65535 | UDP | TURN relay range |

### Health check

```bash
curl https://YOUR_IP:9090/health
# {"status":"ok","gateways":0,"clients":0}
```

---

## 3. Punch'd Bridge (Gateway)

The gateway runs on your private network and connects outbound to the signal server. It proxies HTTP requests to local backends (web apps, RDP servers) and handles TideCloak authentication.

Available in two implementations:
- **Node.js** (`bridges/punchd-bridge/gateway`) — full-featured
- **Rust** (`bridges/punchd-bridge-rs`) — smaller footprint, same protocol

### Deploy (Docker)

```bash
docker build -t keylessh-gateway bridges/punchd-bridge/gateway

docker run -d --restart unless-stopped \
  --name keylessh-gateway \
  -p 7891:7891 -p 7892:7892 \
  -e STUN_SERVER_URL=wss://SIGNAL_SERVER_IP:9090 \
  -e API_SECRET=<from signal server deploy> \
  -e ICE_SERVERS=stun:SIGNAL_SERVER_IP:3478 \
  -e TURN_SERVER=turn:SIGNAL_SERVER_IP:3478 \
  -e TURN_SECRET=<from signal server deploy> \
  -e TIDECLOAK_CONFIG_B64=$(base64 -w0 data/tidecloak.json) \
  -e BACKENDS="MyApp=http://localhost:3000,RDP=rdp://rdp-host:3389" \
  keylessh-gateway
```

### Deploy (Rust, native binary)

```bash
cd bridges/punchd-bridge-rs
cargo build --release

STUN_SERVER_URL=wss://SIGNAL_SERVER_IP:9090 \
API_SECRET=<from signal server deploy> \
ICE_SERVERS=stun:SIGNAL_SERVER_IP:3478 \
TURN_SERVER=turn:SIGNAL_SERVER_IP:3478 \
TURN_SECRET=<from signal server deploy> \
TIDECLOAK_CONFIG_B64=$(base64 -w0 data/tidecloak.json) \
BACKENDS="MyApp=http://localhost:3000" \
./target/release/punchd-bridge-rs
```

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STUN_SERVER_URL` | Yes | — | Signal server WebSocket URL (`wss://host:9090`) |
| `API_SECRET` | Yes | — | Must match signal server's `API_SECRET` |
| `BACKENDS` | Yes | — | Backend mapping: `Name=http://host:port,RDP=rdp://host:3389` |
| `TIDECLOAK_CONFIG_B64` | — | — | Base64-encoded `tidecloak.json` |
| `TIDECLOAK_CONFIG_PATH` | — | `data/tidecloak.json` | Path to config file (fallback) |
| `ICE_SERVERS` | — | — | STUN servers: `stun:host:3478` |
| `TURN_SERVER` | — | — | TURN fallback: `turn:host:3478` |
| `TURN_SECRET` | — | — | Must match signal server's `TURN_SECRET` |
| `LISTEN_PORT` | — | 7891 | Gateway proxy port |
| `HEALTH_PORT` | — | 7892 | Health check port |
| `GATEWAY_DISPLAY_NAME` | — | auto | Name shown in portal |
| `GATEWAY_DESCRIPTION` | — | — | Description shown in portal |
| `HTTPS` | — | true | Generate self-signed TLS |
| `QUIC_PORT` | — | 7893 | QUIC/VPN UDP port (STUN + P2P) |
| `TC_CLIENT_ID` | — | from `tidecloak.json` | Override client ID for role lookups in `resource_access` |

### Backend format

```
BACKENDS="Name=<scheme>://<host>:<port>[;flag1][;flag2]"
```

Multiple backends are comma-separated. Each backend has a name, a URL, and optional suffix flags.

**Protocol schemes:**

| Scheme | Description |
|--------|-------------|
| `http://` or `https://` | HTTP reverse proxy (default) |
| `rdp://` | RDP via RDCleanPath protocol |

**Suffix flags** (append to the URL, order-independent, stackable):

| Flag | Applies to | Description |
|------|-----------|-------------|
| `;noauth` | HTTP + RDP | Skip JWT validation — the backend handles its own auth |
| `;stripauth` | HTTP | Gateway still validates the JWT, but strips the `Authorization` header before proxying. Prevents token leakage to backends that don't need it. |
| `;eddsa` | RDP | Use Ed25519 passwordless auth via TideSSP instead of NTLM. Patches the RDP connection to use Restricted Admin mode and sends the JWT through CredSSP/NLA. Requires TideSSP installed on the target. |

**Examples:**

```bash
# Single web app
BACKENDS="App=http://localhost:3000"

# Multiple backends
BACKENDS="App=http://localhost:3000,Admin=http://localhost:8080"

# Public backend — no JWT required
BACKENDS="Public=http://localhost:4000;noauth"

# Strip auth header before proxying
BACKENDS="Legacy=http://localhost:5000;stripauth"

# RDP with traditional NTLM password
BACKENDS="Desktop=rdp://win-server:3389"

# RDP with TideSSP passwordless auth
BACKENDS="Desktop=rdp://win-server:3389;eddsa"

# Mixed — web app + passwordless RDP
BACKENDS="App=http://localhost:3000,RDP=rdp://win-server:3389;eddsa"
```

### Health check

```bash
curl http://localhost:7892/health
```

### Verify connection

After starting the gateway, check the signal server health endpoint — the gateway count should increase:

```bash
curl https://SIGNAL_SERVER_IP:9090/health
# {"status":"ok","gateways":1,"clients":0}
```

---

## 4. Punchd VPN Client

Native VPN client that tunnels IP traffic through the gateway over QUIC P2P. Authenticates via an embedded WebView2 browser running the full TideCloak + Heimdall DPoP flow.

### Build

```bash
cd bridges/punchd-bridge-rs

# Windows with WebView2 DPoP (recommended)
cargo build --release --target x86_64-pc-windows-gnu --features webview --bin punchd-vpn

# Linux/macOS
cargo build --release --bin punchd-vpn
```

### VPN Roles (TideCloak)

Assign these roles to users in TideCloak:

| Role | Description |
|------|-------------|
| `vpn:<gatewayId>` | Basic VPN access to the gateway |
| `vpn:<gw>:allow:<cidr>:<ports>` | Allow traffic to subnet/ports |
| `vpn:<gw>:deny:<cidr>:<ports>` | Deny traffic to subnet/ports |

Without the `vpn:<gatewayId>` role, the connection is rejected.

### Firewall

Open UDP port 7893 on the gateway for QUIC P2P. If behind symmetric NAT, configure TURN:

| Port | Protocol | Purpose |
|------|----------|---------|
| 7893 | UDP | QUIC VPN (gateway side) |
| 3478 | UDP + TCP | STUN/TURN (signal server side) |
| 49152–65535 | UDP | TURN relay range |

### Offline Mode (No Signal Server)

The VPN client can connect directly to a gateway without a signal server:
1. Add the gateway URL in the **Gateways** tab on the Dashboard
2. The client connects directly to the gateway's QUIC port
3. No signaling or STUN required for same-network connections

---

## 5. Punchd Gateway — Local/Offline Mode

The Punchd Gateway can run without a signal server for local network access. This replaces the standalone SSH Bridge — the gateway handles SSH, HTTP, and RDP backends.

### Minimal gateway.toml (no auth)

```toml
gateway_id = "local-gateway"
backends = "MyServer=ssh://192.168.1.10:22;noauth,WebApp=http://localhost:3000;noauth"
listen_port = 7891
health_port = 7892
https = false
```

No `tidecloak.json` needed when all backends use `;noauth`. Add it later to enable authentication.

### Install (Windows MSI)

1. Download `PunchdGateway.msi` from [releases](../../releases)
2. Run the installer — installs as a Windows service
3. Place `gateway.toml` in `C:\ProgramData\punchd-gateway\`
4. Restart the service: `sc.exe stop PunchdGateway && sc.exe start PunchdGateway`

### Install (Linux .deb)

```bash
sudo apt install ./punchd-gateway-linux-x64.deb
sudo cp gateway.toml /etc/punchd-gateway/
punchd-bridge-rs
```

### Install (Docker)

```bash
docker run -d --restart unless-stopped \
  --name punchd-gateway \
  -p 7891:7891 -p 7892:7892 -p 7893:7893/udp \
  -v $(pwd)/gateway.toml:/etc/punchd-gateway/gateway.toml \
  keylessh-punchd-bridge-rs
```

### Install (native binary)

```bash
cd bridges/punchd-bridge-rs
cargo build --release --bin punchd-bridge-rs
./target/release/punchd-bridge-rs --console
```

### Add to KeyleSSH UI

In the Dashboard → **Local Gateways** tab → **Add Gateway** → enter `http://YOUR_IP:7891`.
The gateway's `/api/info` endpoint auto-discovers backends.

### Backend flags

| Flag | Description |
|------|-------------|
| `;noauth` | Skip JWT verification (backend handles its own auth) |
| `;eddsa` | Passwordless RDP via TideSSP (requires `tidecloak.json`) |
| `;stripauth` | Remove Authorization header before proxying |

### With authentication

Add `tidecloak.json` to enable JWT-based auth:

```toml
gateway_id = "office-gateway"
backends = "WebApp=http://localhost:3000,RDP=rdp://192.168.1.100:3389;eddsa"
listen_port = 7891
health_port = 7892
https = false
tidecloak_config_b64 = "<base64 of tidecloak.json>"
```

Or place `tidecloak.json` next to `gateway.toml`.

### Health check

```bash
curl http://localhost:7892/health
# {"status":"ok"}

# View logs
curl http://localhost:7892/logs       # browser-friendly HTML
curl http://localhost:7892/logs/buffer # JSON array
```

---

## 6. TideSSP (Windows — Passwordless RDP)

TideSSP is a Windows Security Support Provider that enables passwordless RDP. It verifies Ed25519 JWT signatures from TideCloak and creates Windows logon sessions without passwords.

Install this on each **Windows machine that will be an RDP target**.

### Prerequisites

- Windows Server 2016+ or Windows 10/11 Pro
- Administrator access
- `tidecloak.json` from TideCloak (see step 1)

### Build the MSI installer

On a Windows machine with Visual Studio Build Tools:

1. Install build tools:
   ```powershell
   # WiX Toolset
   dotnet tool install --global wix
   wix extension add -g WixToolset.UI.wixext/6.0.2

   # Ensure CMake is available (VS component: "C++ CMake tools for Windows")
   ```

2. Open a **Developer Command Prompt for VS** and build:
   ```cmd
   cd tide-ssp
   installer\build.bat
   ```

3. The MSI is output to `tide-ssp\out\TideSSP.msi`

### Install

#### Option A: MSI installer (recommended)

Double-click `TideSSP.msi` or run:

```powershell
msiexec /i TideSSP.msi TIDE_CONFIG_FILE="C:\path\to\tidecloak.json"
```

The installer:
- Copies `TideSSP.dll` and `TideSubAuth.dll` to `System32`
- Copies `tidecloak.json` to `System32`
- Registers TideSSP as an LSA Security Package
- Registers TideSubAuth as an MSV1_0 subauthentication package
- Enables Restricted Admin mode (required for passwordless RDP)

**Reboot required** to activate.

#### Option B: PowerShell (manual)

```powershell
.\install.ps1 -ConfigFile C:\path\to\tidecloak.json
```

Then reboot.

### Uninstall

Via **Add/Remove Programs** > TideSSP > Uninstall, or:

```powershell
msiexec /x TideSSP.msi
```

This removes the DLLs, cleans up registry entries, and clears `UF_MNS_LOGON_ACCOUNT` flags from local users. **Reboot required.**

### Updating the public key

If the TideCloak realm signing key is rotated:

1. Export a new `tidecloak.json` from TideCloak admin console
2. Replace the file in System32:
   ```powershell
   Copy-Item tidecloak.json $env:SystemRoot\System32\tidecloak.json -Force
   ```
3. Reboot (the SSP reads the key once at LSA startup)

### What the MSI installs

| What | Where |
|------|-------|
| `TideSSP.dll` | `%SystemRoot%\System32\` |
| `TideSubAuth.dll` | `%SystemRoot%\System32\` |
| `tidecloak.json` | `%SystemRoot%\System32\` |
| Security Package registration | `HKLM\...\Lsa\SecurityPackages` (appends `TideSSP`) |
| SubAuth registration | `HKLM\...\Lsa\MSV1_0\Auth0 = TideSubAuth` |
| Restricted Admin mode | `HKLM\...\Lsa\DisableRestrictedAdmin = 0` |

---

## Main Server

### Build and run

```bash
npm install
npm run build
NODE_ENV=production PORT=3000 npm start
```

### Persistent data

Mount `./data` as a persistent volume. It contains:
- SQLite DB: `DATABASE_URL` (defaults to `./data/keylessh.db`)
- TideCloak config: `./data/tidecloak.json`

### Environment variables

```env
PORT=3000
NODE_ENV=production
DATABASE_URL=./data/keylessh.db

# Optional: Stripe SaaS billing
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_PRO=price_...
STRIPE_PRICE_ID_ENTERPRISE=price_...
APP_URL=https://your-domain.com
```

The main server includes a built-in SSH bridge — no external bridge needed for basic SSH.
For remote access (NAT traversal, RDP, VPN), deploy a Punchd Gateway.

### Reverse proxy / TLS

Put the main server behind TLS (nginx, Caddy, or a cloud load balancer). WebSockets must be enabled for `/ws/*`.

---

## End-to-End Example

Here's a typical deployment for passwordless RDP through a browser:

```
Browser
  │
  ├─ HTTPS ──→ Signal Server (public VM, port 9090)
  │               │
  │               ├─ WebRTC P2P (or HTTP relay fallback)
  │               │
  │               └─ coturn (same VM, port 3478) ─── STUN/TURN
  │
  └─ WebRTC ──→ Punch'd Bridge (private network, port 7891)
                    │
                    ├─ RDP ──→ Windows Server (TideSSP installed)
                    │             └─ Verifies JWT, creates logon session
                    │
                    └─ HTTP ──→ Web App (localhost:3000)

VPN Client (punchd-vpn)
  │
  ├─ WebView2 ──→ TideCloak (OIDC + Heimdall DPoP)
  │
  ├─ Signal Server (signaling + STUN address exchange)
  │
  └─ QUIC P2P ──→ Punch'd Bridge (port 7893/UDP, NAT hole-punched)
                    │
                    └─ TUN ──→ LAN (192.168.x — IP forwarding)
```

### Quick start

1. **Deploy signal server** on a public VM → save `API_SECRET`, `TURN_SECRET`
2. **Deploy punch'd bridge** on private network → point at signal server, configure backends
3. **Install TideSSP MSI** on each Windows RDP target → provide `tidecloak.json`, reboot
4. **Open the portal** at `https://SIGNAL_SERVER:9090` → select gateway → authenticate → connect

---

## Ports Reference

| Component | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Signal Server | 9090 | TCP | HTTP + WebSocket signaling |
| coturn | 3478 | UDP + TCP | STUN/TURN |
| coturn | 49152–65535 | UDP | TURN relay range |
| Punchd Gateway | 7891 | TCP | Proxy (HTTP/HTTPS) |
| Punchd Gateway | 7892 | TCP | Health check + logs |
| Punchd Gateway | 7893 | UDP | QUIC VPN (P2P + STUN) |
| Main Server | 3000 | TCP | UI + API + built-in SSH bridge |

---

## Troubleshooting

- **"No policy found"**: Create and commit a policy for the SSH role (`ssh:<username>`) in the admin UI
- **Gateway not appearing**: Check `API_SECRET` matches between signal server and gateway
- **WebRTC failing**: Ensure STUN/TURN ports (3478, 49152–65535/udp) are open on the signal server
- **TideSSP not active after install**: Reboot is required — LSA loads security packages at startup
- **"Breaking changes made to Policies"**: Update policy version to `"3"` in `sshPolicy.ts`

## Tide Fabric / Policy Requirements

SSH signing requires the Tide Fabric (Tide's decentralised network) for Policy authorization:

### Prerequisites

- **TideCloak** must be set up and configured
- **ORKs** (Tide's network nodes) must be accessible from the browser

### Policy Lifecycle

1. Admin creates SSH policy templates in the UI
2. Contract ID is computed (SHA512 hash of source code) and policy is committed to the Tide Fabric
3. Committed policies are stored in SQLite (`sshPolicies` table)
4. During SSH, the browser fetches the policy and sends to Tide for signing
5. Tide ORKs validate the doken and run the Forseti contract before collaboratively signing

### Contract ID Computation

Contract IDs are computed as a SHA512 hash of the C# source code. This is done server-side when creating policies - no external compiler or Docker container is required.

### Troubleshooting

- **"No policy found"**: Ensure a policy exists for the SSH role (`ssh:<username>`)
- **"Contract validation failed"**: Check ORK logs for IL vetting errors
- **"Doken validation failed"**: Ensure the user's doken contains the required role
- **Connection timeouts**: Verify Tide ORK endpoints are reachable from the browser

## SaaS Mode (Stripe Billing)

KeyleSSH can be offered as a commercial SaaS with tiered subscriptions. By default, KeyleSSH runs with **no usage limits** - this section only applies if you want to monetize your deployment.

### How It Works

When Stripe is **not configured**:
- No usage limits (unlimited users, servers)
- License page hidden from admin navigation
- All tier-based restrictions disabled

When Stripe **is configured**:
- License page appears in admin settings
- Tier-based limits enforced:
  - **Free**: 5 users, 2 servers
  - **Pro**: 25 users, 10 servers
  - **Enterprise**: Unlimited
- Users can upgrade via Stripe Checkout
- Subscription webhooks update tier automatically

### Stripe Configuration

1. Create a Stripe account and get your API keys from [dashboard.stripe.com](https://dashboard.stripe.com)

2. Create subscription products and prices in Stripe:
   - Create a "Pro" product with a recurring price
   - Create an "Enterprise" product with a recurring price (or use contact-only)

3. Set up a webhook endpoint in Stripe Dashboard:
   - URL: `https://your-domain.com/api/webhooks/stripe`
   - Events: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`

4. Configure environment variables:

```env
# Required for SaaS mode
STRIPE_SECRET_KEY=sk_live_...

# Webhook signing secret (from Stripe Dashboard)
STRIPE_WEBHOOK_SECRET=whsec_...

# Price IDs (must be price_*, not prod_*)
STRIPE_PRICE_ID_PRO=price_...
STRIPE_PRICE_ID_ENTERPRISE=price_...

# Base URL for Stripe redirect URLs
APP_URL=https://your-domain.com

# Optional: Enterprise contact page (if not using Stripe for Enterprise)
VITE_ENTERPRISE_CONTACT_URL=https://your-company.com/contact
```

### Testing with Stripe Test Mode

For development, use Stripe test keys (`sk_test_...`) and test card numbers:
- `4242 4242 4242 4242` - Successful payment
- `4000 0000 0000 0002` - Card declined

Use the Stripe CLI to forward webhooks locally:

```bash
stripe listen --forward-to localhost:3000/api/webhooks/stripe
```

### Subscription Lifecycle

1. **New user signs up**: Starts on Free tier
2. **User clicks upgrade**: Redirected to Stripe Checkout
3. **Payment succeeds**: Webhook updates user's tier in database
4. **Subscription changes**: Webhook updates tier (upgrade/downgrade/cancel)
5. **Subscription ends**: User reverts to Free tier
