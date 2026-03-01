# Punch'd

NAT-traversing authenticated reverse proxy gateway. Access private web applications and remote desktops from anywhere through hole-punched WebRTC DataChannels — no port forwarding, no VPN, no public IP required.

## How it works

```
Browser → Signal Server (relay) → Gateway → Backend App (HTTP)
   │              ↕ coturn             │  └→ RDP Server (RDCleanPath)
   └──── WebRTC DataChannel (P2P) ────┘
         (after hole punch)
```

The system has three components:

1. **Signal Server** (public) — signaling hub, HTTP relay, portal & admin dashboard. Run by the infrastructure operator. Lives in the main repo as `signal-server/`.
2. **coturn** (public, sidecar) — STUN/TURN server for NAT traversal and relay fallback. Runs alongside the signal server with `--network host`.
3. **Gateway** (private) — authenticating reverse proxy that registers with the signal server. Run by anyone who wants to expose a local app.

The signal server and gateway can be run by **different operators**. Clients connect through the signal server's HTTP relay, then upgrade to peer-to-peer WebRTC DataChannels via NAT hole punching (using coturn for STUN binding and TURN relay fallback). A Service Worker transparently routes browser fetches through the DataChannel.

## Features

### Connection Lifecycle

Connections progress through four phases automatically — the user just opens a URL:

1. **Portal selection** — pick a gateway and backend from the signal server's portal page
2. **HTTP relay** — all traffic tunneled through the signal server's WebSocket until WebRTC is ready
3. **WebRTC upgrade** — injected `webrtc-upgrade.js` performs ICE/STUN hole punching for a direct P2P DataChannel, with TURN relay fallback
4. **Service Worker takeover** — a Service Worker transparently intercepts browser fetches and routes them through the DataChannel instead of HTTP relay

See [Connection Lifecycle](docs/ARCHITECTURE.md#connection-lifecycle) for sequence diagrams.

### Multi-Backend Routing

A single gateway can proxy to multiple backends using path-based routing (`/__b/<name>/`). The gateway rewrites HTML responses (links, scripts, fetch/XHR calls) to maintain correct routing across backends. Backends can be marked `;noauth` to skip JWT validation.

```bash
BACKENDS="App=http://localhost:3000,Auth=http://localhost:8080;noauth"
```

See [Multi-Backend Routing](docs/ARCHITECTURE.md#multi-backend-routing) for path prefix system and HTML rewriting details.

### RDP Remote Desktop

Browser-based RDP via [IronRDP](https://github.com/Devolutions/IronRDP) WASM. The gateway implements the **RDCleanPath protocol** — it handles TLS termination with the RDP server so IronRDP WASM (which can't do raw TCP/TLS from a browser) can perform CredSSP/NLA authentication. RDP traffic flows through the same WebRTC DataChannel as HTTP. No WebSocket server needed — the DataChannel carries RDCleanPath PDUs directly using a virtual WebSocket shim.

```bash
BACKENDS="Web App=http://localhost:3000,My PC=rdp://localhost:3389"
```

Navigate to `/rdp?backend=My%20PC`, enter Windows credentials, and connect.

See [RDP Architecture](docs/ARCHITECTURE.md#rdp-remote-desktop-ironrdp-wasm--rdcleanpath) for the RDCleanPath protocol, ASN.1 wire format, and IronRDP WASM build instructions.

### Authentication

Gateway-side OIDC authentication via TideCloak. TideCloak traffic is reverse-proxied through the gateway so it never needs direct browser access. Features transparent token refresh, server-side cookie jars for both TideCloak and backend sessions (needed because DataChannel responses can't set cookies), and `dest:<gatewayId>:<backendName>` role-based access control.

See [Authentication Flow](docs/ARCHITECTURE.md#authentication-flow) for the OIDC login flow, token validation, and endpoint reference.

### Signal Server API

The signal server exposes HTTP endpoints for portal interaction, gateway listing, admin actions, and TideCloak SSO — plus WebSocket signaling for gateway registration, client pairing, ICE candidate exchange, and HTTP relay.

See [Signal Server API Routes](docs/ARCHITECTURE.md#signal-server-api-routes) and [Signaling Message Reference](docs/ARCHITECTURE.md#signaling-message-reference) for the full endpoint and message catalog.

### Security

JWT-validated requests at every entry point (relay, DataChannel, backend proxy). HTTP method whitelist, open redirect prevention, body size limits, CORS origin validation, timing-safe secret comparison, rate limiting per IP (20 connections, 100 msg/s), and automatic reconnection with exponential backoff.

See [Security](docs/ARCHITECTURE.md#security) for headers, rate limits, capacity, and resilience details.

## Quick start

```bash
./start.sh
```

On first run this will:
1. Start TideCloak (Docker) and walk you through realm initialization
2. Prompt for `API_SECRET` and `TURN_SECRET` (get these from the signal server operator)
3. Install dependencies, build, and start the gateway

On subsequent runs, TideCloak and secrets are reused automatically.

### Options

```bash
./start.sh --skip-tc                                  # skip TideCloak, gateway only
API_SECRET=xxx TURN_SECRET=yyy ./start.sh             # pass secrets directly
SIGNAL_SERVER_URL=wss://signal.example.com:9090 ./start.sh  # custom signal server
BACKEND_URL=http://localhost:4000 ./start.sh          # custom backend
```

### Gateway only (without TideCloak)

```bash
script/gateway/start.sh
```

Prompts for secrets on first run and saves them to `script/gateway/.env`.

### Docker Compose (all services)

```bash
docker compose up --build
```

This starts coturn, the signal server, and the gateway together. Set `TURN_SECRET`, `API_SECRET`, and `EXTERNAL_IP` in your environment or a `.env` file.

## Secrets

| Secret | Generated by | Shared with | Purpose |
|--------|-------------|-------------|---------|
| `API_SECRET` | Signal server operator | Gateway operators | Authenticates gateway registration (timing-safe) |
| `TURN_SECRET` | Signal server operator | Gateway operators | Generates ephemeral TURN credentials (HMAC-SHA1) |

**Secret flow:**
1. Signal server operator deploys and generates secrets (or sets them manually)
2. Signal server operator shares `API_SECRET` + `TURN_SECRET` with gateway operators
3. Gateway operator sets them as env vars or pastes them when `./start.sh` prompts

The start scripts load secrets in this order:
1. Environment variables (if already set)
2. `script/gateway/.env` (saved from a previous run)
3. `signal-server/.env` (only if you run both locally)
4. Prompts you to paste them (saves to `script/gateway/.env` for next time)

## Environment variables

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#configuration-reference) for the full configuration reference.

### Key variables

| Variable | Component | Description |
|----------|-----------|-------------|
| `SIGNAL_SERVER_URL` | Gateway | WebSocket URL of the signal server |
| `BACKEND_URL` | Gateway | Backend to proxy to |
| `BACKENDS` | Gateway | Multiple backends: `"App=http://host:3000,Desktop=rdp://host:3389"` |
| `API_SECRET` | Both | Shared secret for gateway registration |
| `TURN_SECRET` | Both + coturn | Shared secret for TURN credentials (HMAC-SHA1) |
| `EXTERNAL_IP` | coturn | Public IP for TURN relay addresses |
| `TIDECLOAK_CONFIG_B64` | Both | Base64 TideCloak config for authentication |
| `TC_INTERNAL_URL` | Gateway | Internal TideCloak URL when `KC_HOSTNAME` is public |
| `GATEWAY_DISPLAY_NAME` | Gateway | Name shown in the portal |
| `GATEWAY_DESCRIPTION` | Gateway | Description shown in the portal |

## Ports

| Component | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| coturn | 3478 | UDP + TCP | STUN/TURN |
| Signal server | 9090 | HTTP/WS | Signaling, portal, admin, HTTP relay |
| coturn | 49152-65535 | UDP | TURN relay sockets |
| Gateway | 7891 | HTTP/HTTPS | Proxy server |
| Gateway | 7892 | HTTP | Health check |

## Documentation

- [Architecture & Protocol Details](docs/ARCHITECTURE.md) — full system docs with diagrams
- [PlantUML sources](docs/diagrams/) — editable sequence diagrams

## License

Proprietary
