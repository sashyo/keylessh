# KeyleSSH Punchd Bridge (Rust)

NAT-traversing authenticated reverse proxy gateway. Rust port of the Node.js punchd-bridge — same protocol, same auth, smaller binary, lower memory.

## What it does

```
Browser ──WebRTC DataChannel──▶ STUN Server ──signaling──▶ Gateway ──proxy──▶ Local Backends
Browser ──STUN HTTP relay───▶ STUN Server ──WebSocket──▶ Gateway ──proxy──▶ Local Backends
```

The gateway:
1. Registers with a public STUN/TURN signaling server as a gateway instance
2. Accepts WebRTC DataChannel connections from browsers (NAT-traversed via ICE)
3. Falls back to HTTP relay through the STUN server WebSocket when P2P fails
4. Authenticates users via TideCloak OIDC (server-side login flow)
5. Verifies JWTs and DPoP proofs (RFC 9449)
6. Proxies authorized HTTP requests to local backends (multi-backend routing)
7. Tunnels WebSocket and raw TCP connections (RDP via RDCleanPath protocol)
8. Rewrites HTML for path-based backend routing over DataChannel

## Features

- **WebRTC dual DataChannels**: control (JSON) + bulk (binary streaming) with backpressure
- **RDCleanPath protocol**: ASN.1 DER-encoded PDUs for RDP connection negotiation
- **Server-side OIDC**: TideCloak login/callback/logout/session-token endpoints
- **Cookie jars**: Server-side TideCloak and backend cookie storage (DataChannel can't set cookies)
- **Token refresh dedup**: Prevents concurrent refresh token race conditions
- **Path-based routing**: `/__b/<name>/` prefix system with HTML URL rewriting
- **TURN ephemeral credentials**: HMAC-SHA1 REST API credentials
- **Self-signed TLS**: In-memory cert generation via rcgen

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `STUN_SERVER_URL` | WebSocket URL of the STUN signaling server | Yes |
| `API_SECRET` | Shared secret for STUN server API auth | Yes |
| `BACKENDS` | Backend list: `name1=http://host:port,name2=rdp://host:3389` | Yes* |
| `BACKEND_URL` | Single backend URL (alternative to BACKENDS) | Yes* |
| `TIDECLOAK_CONFIG_B64` | Base64-encoded TideCloak config | No** |
| `TIDECLOAK_CONFIG_PATH` | Path to tidecloak.json | No** |
| `LISTEN_PORT` | HTTP/HTTPS proxy port | No (default: 7891) |
| `HEALTH_PORT` | Health check port | No (default: 7892) |
| `HTTPS` | Enable HTTPS with self-signed cert | No (default: true) |
| `TLS_HOSTNAME` | Hostname for self-signed cert | No (default: localhost) |
| `GATEWAY_ID` | Unique gateway identifier | No (auto-generated) |
| `TURN_SERVER` | TURN server URL (e.g. `turn:host:3478`) | No |
| `TURN_SECRET` | Shared secret for TURN REST API credentials | No |
| `ICE_SERVERS` | Comma-separated ICE servers | No (derived from STUN URL) |
| `AUTH_SERVER_PUBLIC_URL` | Public TideCloak URL for browser redirects | No |
| `TC_INTERNAL_URL` | Internal TideCloak URL for server-side requests | No |
| `STRIP_AUTH_HEADER` | Remove Authorization header before proxying | No |
| `GATEWAY_DISPLAY_NAME` | Display name for portal | No |
| `GATEWAY_DESCRIPTION` | Description for portal | No |
| `GATEWAY_ADDRESS` | Override advertised address | No |

\* Either `BACKENDS` or `BACKEND_URL` is required.
\** Defaults to `data/tidecloak.json` if neither is set.

### Backend flags

Append flags to backend URLs with `;`:
- `;noauth` — skip JWT validation (backend handles its own auth)
- `;stripauth` — remove Authorization header before proxying

Example: `BACKENDS=app=http://localhost:3000,admin=http://localhost:8080;stripauth,rdp=rdp://192.168.1.100:3389`

## Local Development

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- `data/tidecloak.json` — TideCloak client adapter config
- A running STUN signaling server

### Build and run

```bash
cd bridges/punchd-bridge-rs

# Symlink data directory from main project
ln -s ../../data data

# Development
STUN_SERVER_URL=ws://localhost:3478 \
API_SECRET=your-secret \
BACKENDS=myapp=http://localhost:3000 \
cargo run

# Production build
cargo build --release
./target/release/punchd-bridge-rs
```

## Docker Deployment

### Build

```bash
docker build --no-cache -t keylessh-punchd-bridge-rs .
```

### Run

```bash
docker run --rm -d \
  --name keylessh-punchd-bridge \
  -p 7891:7891 -p 7892:7892 \
  -v $(pwd)/../../data:/app/data \
  -e STUN_SERVER_URL=ws://stun-server:3478 \
  -e API_SECRET=your-secret \
  -e BACKENDS=myapp=http://host.docker.internal:3000 \
  keylessh-punchd-bridge-rs
```

Or with config as env var:

```bash
docker run --rm -d \
  --name keylessh-punchd-bridge \
  -p 7891:7891 -p 7892:7892 \
  -e "TIDECLOAK_CONFIG_B64=$(base64 -w0 ../../data/tidecloak.json)" \
  -e STUN_SERVER_URL=ws://stun-server:3478 \
  -e API_SECRET=your-secret \
  -e BACKENDS=myapp=http://host.docker.internal:3000 \
  keylessh-punchd-bridge-rs
```

## Deploy to Azure

### One-command deploy

```bash
STUN_SERVER_URL=wss://stun.example.com \
API_SECRET=your-secret \
TURN_SECRET=your-turn-secret \
./azure/deploy.sh
```

### Azure configuration

The Container App is configured with:
- **CPU:** 0.5 vCPU, **Memory:** 1 Gi
- **Scale:** 0 to 100 replicas based on 10 concurrent HTTP connections per instance
- **Health:** Liveness and readiness probes on port 7892 `/health`
- **Secrets:** TideCloak config, API secret, TURN secret stored as Azure secrets

## Health Check

```bash
curl http://localhost:7892/health
# {"status":"ok"}
```
