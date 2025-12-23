# KeyleSSH TCP Bridge

Stateless WebSocket-TCP bridge microservice for SSH connections. Designed to run on Azure Container Apps with auto-scaling.

## What it does

```
Browser (WebSocket) → TCP Bridge → SSH Server (TCP)
```

The bridge:
1. Accepts WebSocket connections with a JWT token
2. Verifies the JWT against TideCloak JWKS
3. Opens TCP socket to the specified SSH server
4. Pipes bytes bidirectionally (terminal I/O + SFTP file operations share the same connection)
5. Closes both connections when either side disconnects

**Note:** Both SSH terminal and SFTP file browser use the same WebSocket connection. The SSH protocol multiplexes channels internally - no bridge changes needed for SFTP support.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     Azure Container Apps                        │
│                                                                 │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐         │
│   │  Instance 1 │   │  Instance 2 │   │  Instance N │   ...   │
│   │  10 conns   │   │  10 conns   │   │  10 conns   │         │
│   └─────────────┘   └─────────────┘   └─────────────┘         │
│                                                                 │
│   Auto-scales 0 → 100 based on concurrent connections          │
└────────────────────────────────────────────────────────────────┘
```

## Security

- **JWT tokens** are verified against TideCloak JWKS (no shared secrets)
- Token verification checks: signature, issuer, expiry, and authorized party (azp)
- Connection parameters (host, port, serverId) are passed as query parameters
- The bridge independently validates tokens using the same JWKS as the main server

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | HTTP/WebSocket port | No (default: 8080) |
| `TIDECLOAK_CONFIG_PATH` | Path to tidecloak.json config | No (default: ./data/tidecloak.json) |

## Local Development

```bash
npm install
npm run dev
```

Make sure `data/tidecloak.json` exists with your TideCloak client adapter config (same file as main server).

## Deploy to Azure

```bash
# Deploy (ensure tidecloak.json is available to the container)
./azure/deploy.sh
```

## Health Check

```bash
curl http://localhost:8080/health
# {"status":"ok","connections":0}
```

## Protocol

### Connection

```
WebSocket URL: wss://bridge-host/?token=<jwt>&host=<ssh-host>&port=<ssh-port>&serverId=<server-id>
```

### Messages

**From bridge to client:**
```json
{"type": "connected"}  // TCP connection established
{"type": "error", "message": "..."}  // Error occurred
```

**Binary data** is forwarded as-is in both directions.
