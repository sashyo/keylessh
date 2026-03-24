# KeyleSSH SSH Bridge (Rust)

Stateless, content-blind, WebSocket-to-TCP bridge microservice for SSH connections. Rust port of the Node.js ssh-bridge — same protocol, same auth, smaller binary, lower memory.

## What it does

```
Browser -(SSH-over-WebSocket)-> SSH Bridge -(SSH-over-TCP)-> SSH Server
```

The bridge:
1. Accepts WebSocket connections with a JWT token
2. Verifies the JWT against statically-set TideCloak JWKS configuration
3. Verifies DPoP proofs when present (RFC 9449)
4. Opens TCP socket to the specified destination SSH server
5. Pipes bytes bidirectionally (terminal I/O + SFTP file operations share the same connection)
6. Closes both connections when either side disconnects

**Note:** Both SSH terminal and SFTP file browser use the same WebSocket connection. The SSH protocol multiplexes channels internally.

## Cloud Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Azure Container Apps                    │
│                                                             │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐       │
│   │  Instance 1 │   │  Instance 2 │   │  Instance N │  ...  │
│   │  y conns    │   │  y conns    │   │  y  conns   │       │
│   └─────────────┘   └─────────────┘   └─────────────┘       │
│                                                             │
│   Auto-scales 0 → N based on max concurrent y connections   │
│   (by default, y=10 )                                       │
└─────────────────────────────────────────────────────────────┘
```

## Security

Designed to provide resiliency against a fully compromised bridge.

- **JWT tokens** verified against TideCloak JWKS (no shared secrets)
- **DPoP proofs** verified when present (header or query param) — RFC 9449 compliant
- Token verification checks: signature (EdDSA/ECDSA), issuer, expiry, and authorized party (azp)
- DPoP verification checks: signature, method/URL binding, timestamp, JTI replay protection, JWK thumbprint
- Bridge has no visibility or access to the signed SSH handshake or encrypted SSH stream it routes

Remaining threats:
- A compromised bridge can cause denial of service

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | HTTP/WebSocket port | No (default: 8081) |
| `client_adapter` | TideCloak config as JSON string (highest priority) | No |
| `TIDECLOAK_CONFIG_B64` | Base64-encoded TideCloak config (for Azure secrets) | No |

If neither env var is set, the bridge looks for `data/tidecloak.json` relative to the working directory.

## Local Development

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- `data/tidecloak.json` — same TideCloak client adapter config used by the main server

### Build and run

```bash
cd bridges/ssh-bridge-rs

# Development (debug build)
cargo run

# Or with custom port
PORT=8088 cargo run

# Production (optimized, ~5MB binary)
cargo build --release
PORT=8088 ./target/release/ssh-bridge-rs
```

### Using the config from the main server

```bash
# Symlink or copy the data directory
ln -s ../../data data

# Or pass config inline
export client_adapter=$(cat ../../data/tidecloak.json)
cargo run
```

## Docker Deployment

### Build

```bash
docker build --no-cache -t keylessh-bridge-rs .
```

### Run

```bash
docker run --rm -d \
  --name keylessh-bridge-rs \
  -p 8088:8080 \
  -v $(pwd)/../../data:/app/data \
  keylessh-bridge-rs
```

Or with config as env var (no volume mount needed):

```bash
docker run --rm -d \
  --name keylessh-bridge-rs \
  -p 8088:8080 \
  -e "client_adapter=$(cat ../../data/tidecloak.json)" \
  keylessh-bridge-rs
```

### Logs

```bash
docker logs keylessh-bridge-rs
```

### Stop

```bash
docker stop keylessh-bridge-rs
```

## Deploy to Azure

### One-command deploy

```bash
./azure/deploy.sh
```

This script will:
1. Create the resource group and container registry (if needed)
2. Build the Docker image in Azure Container Registry
3. Deploy as an Azure Container App with scale-to-zero
4. Output the bridge URL

### Manual deploy

```bash
# Ensure you're logged in
az login

# Set your config path
export TIDECLOAK_CONFIG=../../data/tidecloak.json

# Run the deployment
cd azure && ./deploy.sh
```

### Azure configuration

The Container App is configured with:
- **CPU:** 0.25 vCPU, **Memory:** 0.5 Gi (Rust uses ~3MB vs ~50MB for Node.js)
- **Scale:** 0 to 100 replicas based on 10 concurrent HTTP connections per instance
- **Health:** Liveness and readiness probes on `/health`
- **Secret:** TideCloak config stored as base64-encoded Azure secret

## Health Check

```bash
curl http://localhost:8088/health
# {"status":"ok","tcpConnections":0}
```

## Deploy as a Debian Deb repo

Build the deb package for Debian12:

```bash
sudo docker buildx build -f Dockerfile-build-deb -o out .
```

Then copy the deb file to the target machine and install it like this:

```bash
sudo apt install ./ssh-bridge-rs_0.1.0_amd64.deb
```

Check service status:
```bash
systemctl status ssh-bridge-rs
journalctl -u ssh-bridge-rs -n 100 --no-pager
```

Configure Place the TideCloak adaptor in the bridge config webpage:
1. Open the bridge server address in a web browser on port 7893 (i.e. http://localhost:7893)
2. Set the `TIDECLOAK AUTHENTICATION` toggle to `Paste JSON`
3. Paste the TideCloak adaptor config to the `TideCloak Config JSON` input field.
4. Press `Save & Start`
5. You should see a message "SSH Bridge Starting!"

If you refresh this page, you'll notice that temporary web portal has been shut down - which is intended. If you even need to make changes in that adaptor, you can do it directly on the server under `/var/lib/ssh-bridge-rs/.keylessh/ssh-bridge.toml`.

For debugging connectivity, you can access the bridge's log console on it's default port (as defined in the config webpage) under `/logs` route (e.g https://localhost:8081/logs).

## Protocol

### Connection

```
WebSocket URL: wss://bridge-host/?token=<jwt>&host=<ssh-host>&port=<ssh-port>&sessionId=<session-id>
```

With DPoP (query param — WebSocket can't set custom headers):
```
WebSocket URL: wss://bridge-host/?token=<jwt>&host=<ssh-host>&port=<ssh-port>&sessionId=<session-id>&dpop=<proof>
```

### Messages

**From bridge to client:**
```json
{"type": "connected"}  // TCP connection established
{"type": "error", "message": "..."}  // Error occurred
```

**Binary data** is forwarded as-is in both directions.

## Comparison with Node.js bridge

| | Node.js (`ssh-bridge`) | Rust (`ssh-bridge-rs`) |
|---|---|---|
| Docker image | ~150 MB | ~15 MB |
| Memory usage | ~50 MB idle | ~3 MB idle |
| Startup time | ~500 ms | ~5 ms |
| Binary size | N/A (interpreted) | ~5 MB |
| Dependencies | 50+ npm packages | 20 crates |
| Cold start (Azure) | 2-3 seconds | <1 second |
