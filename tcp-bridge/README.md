# KeyleSSH Oblivious Bridge

Stateless, content-blind, WebSocket-to-TCP bridge microservice for SSH connections. Designed to run on Azure Container Apps with auto-scaling.

## What it does

```
Browser -(SSH-over-WebSocket)-> TCP Bridge -(SSH-over-TCP)-> SSH Server
```

The bridge:
1. Accepts WebSocket connections with a JWT token
2. Verifies the JWT against statically-set TideCloak JWKS configuration
3. Opens TCP socket to the specified destination SSH server
4. Pipes bytes bidirectionally (terminal I/O + SFTP file operations share the same connection)
5. Closes both connections when either side disconnects

**Note:** Both SSH terminal and SFTP file browser use the same WebSocket connection. The SSH protocol multiplexes channels internally - no bridge changes needed for SFTP support.

## Cloud Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     Azure Container Apps                      │
│                                                               │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐         │
│   │  Instance 1 │   │  Instance 2 │   │  Instance N │   ...   │
│   │  y conns    │   │  y conns    │   │  y  conns   │         │
│   └─────────────┘   └─────────────┘   └─────────────┘         │
│                                                               │
│   Auto-scales 0 → N based on max concurrent y connections     │
│   (by default, y=10 )                                         │
└───────────────────────────────────────────────────────────────┘
```

## Security

Postude designed to provide resiliancy against a fully compromised bridge.

- **JWT tokens** are verified against TideCloak JWKS (no shared secrets)
- Token verification checks: signature, issuer, expiry, and authorized party (azp)
- Connection parameters (host, port, serverId) are passed as query parameters
- The bridge independently validates tokens using the same JWKS as the main server
- Bridge has no visibility or access to the signed SSH handshake or encrypted SSH stream it routes

Remaining threats:

- A compromised bridge can cause denial of service

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | HTTP/WebSocket port | No (default: 8080) |
| `TIDECLOAK_CONFIG_PATH` | Path to tidecloak.json config | No (default: ./data/tidecloak.json) |

## Local Development

```bash
export PORT=8088 # prevents port colision with TideCloak if running a local test
export TIDECLOAK_CONFIG_PATH="../data/tidecloak.json" # When testing locally with KeyleSSH server 
npm install
npm run dev
```

Make sure `data/tidecloak.json` exists with your TideCloak client adapter config (same file as main server).

## Docker deployment

**Build the docker image**

```bash
docker build --no-cache -t keylessh-bridge .
```

**Run the docker image**

```bash
docker start --rm -d --name keylessh-bridge -p 8088:8080 -v ../data:/data keylessh-bridge
```

Switches:
- `--rm` - Remove docker once stopped
- `-d` - Run in silent mode
- `--name` - Give the docker a name
- `-p` - Expose port 8088 and redirect it to port 8080 inside
- `-v` - Map an external folder with the database files and tidecloak adapter for consistency.

**Check console logs**

```bash
sudo docker logs keylessh-bridge
```

**Stop the docker**

```bash
sudo docker stop keylessh-bridge
```


## Deploy to Azure

```bash
# Deploy (ensure tidecloak.json is available to the container)
./azure/deploy.sh
```

## Health Check

```bash
curl http://localhost:8088/health
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
