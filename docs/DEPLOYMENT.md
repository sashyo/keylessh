# Deployment (Production)

This app has two deployable services and requires connectivity to the ORK network:

1. **Main server** (required): serves the React app + REST API + `/ws/tcp` WebSocket bridge.
2. **TCP bridge** (optional): `tcp-bridge/` as a separate, auto-scaling WS↔TCP forwarder (recommended for high concurrency).
3. **ORK network** (required): Tide's decentralised node network for Policy:1 authorization and SSH signing.

For most deployments you run **one main server** with a persistent `data/` volume, connectivity to the ORK network, and optionally an external `tcp-bridge/`.

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

# Ork connectivity (for Policy:1 authorization)
# The browser connects to Ork via TideCloak's enclave proxy
# Ensure TideCloak is configured with Ork endpoints
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

- The current storage is SQLite. If you run multiple main server instances, you'll need shared storage and coordination (not currently supported out of the box).
- The external bridge does **not** validate JWTs; it only validates the HMAC token from the main server.
- Ensure `/ws/tcp` is reachable from browsers; if you change ports/origins, update your proxy rules accordingly.

## ORK Network / Policy:1 Requirements

SSH signing requires the ORK network (Tide's decentralised nodes) for Policy:1 authorization:

### Prerequisites

- **TideCloak** must be configured with ORK endpoints (enclave proxy)
- **ORKs** must be accessible from the browser (via TideCloak's enclave proxy)
- **Forseti contracts** are compiled and validated by each ORK (requires Ork.Forseti.VmHost)

### Policy Lifecycle

1. Admin creates SSH policy templates in the UI
2. Policies are compiled (C# → DLL) and committed to the ORK network
3. Committed policies are stored in SQLite (`sshPolicies` table)
4. During SSH, the browser fetches the policy and sends to ORKs for signing
5. ORKs validate the doken and run the Forseti contract before collaboratively signing

### Troubleshooting

- **"No policy found"**: Ensure a policy exists for the SSH role (`ssh:<username>`)
- **"Contract validation failed"**: Check ORK logs for IL vetting errors
- **"Doken validation failed"**: Ensure the user's doken contains the required role
- **Connection timeouts**: Verify ORK endpoints are reachable from the browser

