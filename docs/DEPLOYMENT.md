# Deployment (Production)

This app has two deployable services:

1. **Main server** (required): serves the React app + REST API + `/ws/tcp` WebSocket bridge.
2. **TCP bridge** (optional): `tcp-bridge/` as a separate, auto-scaling WS↔TCP forwarder (recommended for high concurrency).

For most deployments you run **one main server** with a persistent `data/` volume, and optionally an external `tcp-bridge/`.

## Main Server (Required)

### Build and run

```bash
npm install
npm run build
NODE_ENV=production PORT=3000 npm start
```

The production server serves static assets from `dist/public` and the API/WS from the same origin.

### Persistent data

The server stores:

- SQLite DB: `DATABASE_URL` (defaults to `./data/keylessh.db`)
- TideCloak JWKS config: `./data/tidecloak.json` (required for JWT verification)

In production you should mount `./data` as a persistent volume.

### Required TideCloak files

There are two configs:

- **Client (browser):** `client/src/tidecloakAdapter.json`
- **Server (JWT verification):** `data/tidecloak.json` (must include a `jwk.keys` set)

The server reads `data/tidecloak.json` from the working directory (`process.cwd()`).

### Environment variables

```env
PORT=3000

# SQLite path (file path, not a DSN)
DATABASE_URL=./data/keylessh.db

# Optional external TCP bridge
BRIDGE_URL=wss://<your-bridge-fqdn>
BRIDGE_SECRET=<shared-secret>
```

### Reverse proxy / TLS

Put the main server behind TLS (nginx, Caddy, or a cloud load balancer). WebSockets must be enabled for `/ws/*`.

## TCP Bridge on Azure Container Apps (Optional, Recommended)

The external bridge is stateless and can scale independently. The main server still validates JWTs and then forwards encrypted bytes to the bridge using a short-lived HMAC token.

### Prerequisites

- Azure CLI installed (`az`)
- Logged in (`az login`)

### Deploy

```bash
cd tcp-bridge

# Choose or generate the shared secret
export BRIDGE_SECRET=$(openssl rand -base64 32)

# Deploy (creates RG + ACR + Container Apps env + app)
./azure/deploy.sh
```

The script prints:

- Bridge URL: `wss://...`
- `BRIDGE_SECRET`

### Configure the main server

Set these env vars on the main server:

```env
BRIDGE_URL=wss://<bridge-fqdn>
BRIDGE_SECRET=<same secret used for tcp-bridge>
```

### Scaling

The provided Azure Container Apps config (`tcp-bridge/azure/container-app.yaml`) scales based on concurrent requests (WebSocket upgrades are HTTP):

- `minReplicas: 0` (scales to zero)
- `maxReplicas: 100`
- `concurrentRequests: 10` (≈ 10 SSH sessions per instance)

Tune these for your workload.

## Production Notes / Caveats

- The current storage is SQLite. If you run multiple main server instances, you’ll need shared storage and coordination (not currently supported out of the box).
- The external bridge does **not** validate JWTs; it only validates the HMAC token from the main server.
- Ensure `/ws/tcp` is reachable from browsers; if you change ports/origins, update your proxy rules accordingly.

