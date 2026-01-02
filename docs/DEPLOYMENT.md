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

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Available variables:

```env
PORT=3000
NODE_ENV=development

# SQLite path (file path, not a DSN)
DATABASE_URL=./data/keylessh.db

# Forseti compiler (choose one)
COMPILER_IMAGE=ghcr.io/tide-foundation/forseti-compiler:latest  # Published image (default)
COMPILER_CONTAINER=Ork-1  # Or use local ORK container

# Optional external TCP bridge (uses same tidecloak.json for JWT verification)
BRIDGE_URL=wss://<your-bridge-fqdn>

# Debug logging
DEBUG=true
```

For local development with ORK containers:

```env
# .env
PORT=3000
NODE_ENV=development
DATABASE_URL=./data/keylessh.db
COMPILER_CONTAINER=Ork-1
```

### Reverse proxy / TLS

Put the main server behind TLS (nginx, Caddy, or a cloud load balancer). WebSockets must be enabled for `/ws/*`.

## TCP Bridge on Azure Container Apps (Optional, Recommended)

The external bridge is stateless and can scale independently. Both the main server and the bridge independently verify JWTs against the same TideCloak JWKS - no shared secrets required.

### Prerequisites

- Azure CLI installed (`az`)
- Logged in (`az login`)
- `data/tidecloak.json` with your TideCloak client adapter config

### Deploy

```bash
cd tcp-bridge

# Deploy (creates RG + ACR + Container Apps env + app)
# The script reads tidecloak.json and passes it to the container
./azure/deploy.sh
```

The script prints the Bridge URL: `wss://...`

### Configure the main server

Set this env var on the main server:

```env
BRIDGE_URL=wss://<bridge-fqdn>
```

### Scaling

The provided Azure Container Apps config (`tcp-bridge/azure/container-app.yaml`) scales based on concurrent requests (WebSocket upgrades are HTTP):

- `minReplicas: 0` (scales to zero)
- `maxReplicas: 100`
- `concurrentRequests: 10` (≈ 10 SSH sessions per instance)

Tune these for your workload.

## Production Notes / Caveats

- The current storage is SQLite. If you run multiple main server instances, you'll need shared storage and coordination (not currently supported out of the box).
- Both the main server and external bridge independently validate JWTs against the same TideCloak JWKS.
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

## Forseti Contract Compiler

Keyle-SSH uses a **standalone compiler container** (`ghcr.io/tide-foundation/forseti-compiler`) to compile Forseti contracts. This container is built from the same base as ORK containers to ensure hash consistency.

### Why It's Needed

When creating SSH policies, Keyle-SSH compiles the C# contract source code to get a `contractId` (SHA512 hash of the DLL). During signing, ORKs independently compile the same source and verify the hash matches. The standalone compiler uses identical:

- .NET runtime assemblies (same base image as ORK)
- SDK version metadata
- Compilation options

This guarantees hash consistency between Keyle-SSH and ORK without requiring an ORK container locally.

### Prerequisites

- Docker installed on the Keyle-SSH server host
- Internet access to pull `ghcr.io/tide-foundation/forseti-compiler:latest` (or pre-pulled image)

### Quick Start

```bash
# Just run it - Docker pulls automatically on first use
echo 'using Ork.Forseti.Sdk;
public class MyPolicy : IAccessPolicy {
    public PolicyDecision Authorize(AccessContext ctx) {
        return PolicyDecision.Allow();
    }
}' | docker run -i --rm ghcr.io/tide-foundation/forseti-compiler:latest --json
```

Output:
```json
{"Success":true,"ContractId":"66F795D1...","SdkVersion":"1.0.0","Validated":false}
```

### For App Developers

**No SDK or library needed** - just shell out to Docker from your app:

```typescript
// Simplest integration - one function
import { execSync } from "child_process";

function getContractId(source: string): string {
  const result = execSync(
    `echo '${source.replace(/'/g, "'\\''")}' | docker run -i --rm ghcr.io/tide-foundation/forseti-compiler:latest --json`,
    { encoding: "utf-8" }
  );
  return JSON.parse(result).ContractId;
}
```

Or configure via environment variable:

```env
COMPILER_IMAGE=ghcr.io/tide-foundation/forseti-compiler:latest
```

### Code Examples

#### Node.js / TypeScript

```typescript
import { spawn } from "child_process";

async function compileContract(source: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn("docker", [
      "run", "-i", "--rm",
      "ghcr.io/tide-foundation/forseti-compiler:latest",
      "--json"
    ]);

    let output = "";
    proc.stdout.on("data", (data) => output += data);
    proc.stderr.on("data", (data) => console.error(data.toString()));

    proc.on("close", (code) => {
      if (code !== 0) return reject(new Error(`Compiler exited with ${code}`));
      const result = JSON.parse(output);
      if (!result.Success) return reject(new Error(result.Error));
      resolve(result.ContractId);
    });

    proc.stdin.write(source);
    proc.stdin.end();
  });
}

// Usage
const contractId = await compileContract(`
  using Ork.Forseti.Sdk;
  public class MyPolicy : IAccessPolicy {
    public PolicyDecision Authorize(AccessContext ctx) {
      return PolicyDecision.Allow();
    }
  }
`);
console.log("Contract ID:", contractId);
```

#### Python

```python
import subprocess
import json

def compile_contract(source: str) -> str:
    result = subprocess.run(
        ["docker", "run", "-i", "--rm",
         "ghcr.io/tide-foundation/forseti-compiler:latest", "--json"],
        input=source.encode(),
        capture_output=True
    )
    data = json.loads(result.stdout)
    if not data["Success"]:
        raise Exception(data["Error"])
    return data["ContractId"]

# Usage
contract_id = compile_contract("""
using Ork.Forseti.Sdk;
public class MyPolicy : IAccessPolicy {
    public PolicyDecision Authorize(AccessContext ctx) {
        return PolicyDecision.Allow();
    }
}
""")
print(f"Contract ID: {contract_id}")
```

#### Bash / Shell

```bash
#!/bin/bash
compile_contract() {
  echo "$1" | docker run -i --rm ghcr.io/tide-foundation/forseti-compiler:latest --json
}

# Usage
CONTRACT_ID=$(compile_contract 'using Ork.Forseti.Sdk;
public class MyPolicy : IAccessPolicy {
  public PolicyDecision Authorize(AccessContext ctx) {
    return PolicyDecision.Allow();
  }
}' | jq -r '.ContractId')

echo "Contract ID: $CONTRACT_ID"
```

### Persistent Container (Faster)

For frequent compilations, run a persistent container to avoid Docker startup overhead:

```bash
# Start persistent container
docker run -d --name forseti-compiler --restart unless-stopped \
  ghcr.io/tide-foundation/forseti-compiler:latest sleep infinity

# Compile (faster - no container startup)
echo 'source code' | docker exec -i forseti-compiler dotnet ContractCompiler.dll --json

# Stop when done
docker stop forseti-compiler && docker rm forseti-compiler
```

### Building from Source (Alternative)

If you need to build locally:

```bash
# Build from the ork repository root
cd /path/to/ork
docker build -t forseti-compiler -f Tools/ContractCompiler/Dockerfile .

# Run
echo 'source code' | docker run -i --rm forseti-compiler --json
```

### Offline Deployment (No Internet)

For air-gapped environments without registry access:

```bash
# On machine with internet - save the image
docker pull ghcr.io/tide-foundation/forseti-compiler:latest
docker save ghcr.io/tide-foundation/forseti-compiler:latest | gzip > forseti-compiler.tar.gz

# Transfer to offline machine (USB, etc.)
# On offline machine - load and run
gunzip -c forseti-compiler.tar.gz | docker load
echo 'source' | docker run -i --rm ghcr.io/tide-foundation/forseti-compiler:latest --json
```

### Command-Line Options

```
OPTIONS:
    --json                Output result as JSON
    -f, --file <path>     Read source from file (inside container)
    -s, --source <code>   Provide source code directly
    -e, --entry-type      Entry type name (validates IAccessPolicy implementation)
    -v, --validate        Enable full IL vetting (forbidden namespaces, non-determinism)
    -h, --help            Show help
```

### Integration with Keyle-SSH

The server compiles contracts when creating SSH policies. Configure via environment:

```env
# Use published image (recommended)
COMPILER_IMAGE=ghcr.io/tide-foundation/forseti-compiler:latest

# Or use local ORK container (if running ORK locally, and it includes the compiler at /opt/forseti-compile/ContractCompiler.dll)
COMPILER_CONTAINER=Ork-1
```

Example integration:

```typescript
// server/compiler.ts
import { spawn } from "child_process";

const COMPILER_IMAGE = process.env.COMPILER_IMAGE || "ghcr.io/tide-foundation/forseti-compiler:latest";
const COMPILER_CONTAINER = process.env.COMPILER_CONTAINER;

export async function compileContract(source: string): Promise<{ contractId: string; sdkVersion: string }> {
  const args = COMPILER_CONTAINER
    ? ["exec", "-i", COMPILER_CONTAINER, "dotnet", "/opt/forseti-compile/ContractCompiler.dll", "--json"]
    : ["run", "-i", "--rm", COMPILER_IMAGE, "--json"];

  const proc = spawn("docker", args);

  let output = "";
  proc.stdout.on("data", (d) => output += d);

  return new Promise((resolve, reject) => {
    proc.on("close", (code) => {
      if (code !== 0) return reject(new Error(`Compiler failed`));
      const result = JSON.parse(output);
      if (!result.Success) return reject(new Error(result.Error));
      resolve({ contractId: result.ContractId, sdkVersion: result.SdkVersion });
    });
    proc.stdin.write(source);
    proc.stdin.end();
  });
}
```

### Hash Mismatch Errors

If you see errors like:

```
Policy refers to wrong contract. Expected 'ABC123...' but policy has 'DEF456...'
```

This means the compiler hash doesn't match what ORK computed. Common causes:

1. **Outdated compiler image**: Pull latest with `docker pull ghcr.io/tide-foundation/forseti-compiler:latest`
2. **Different source code**: Check for whitespace/encoding differences
3. **Using host .NET instead of Docker**: Always use the Docker container, not a local .NET install
4. **ORK container outdated**: If using `COMPILER_CONTAINER`, rebuild ORK with `docker-compose build ork`

### Using Local ORK Container (Alternative)

If you're running ORK containers locally for development, you can use them instead of the published image:

```env
# .env
COMPILER_CONTAINER=Ork-1
```

This uses `docker exec` to run the compiler inside your local ORK container. The ORK container must have the compiler at `/opt/forseti-compile/ContractCompiler.dll`.

### Verifying Hash Consistency

Test that the published image produces the same hash as ORK:

```bash
# Published compiler image
echo 'public class T : Ork.Forseti.Sdk.IAccessPolicy { public Ork.Forseti.Sdk.PolicyDecision Authorize(Ork.Forseti.Sdk.AccessContext c) { return Ork.Forseti.Sdk.PolicyDecision.Allow(); } }' \
  | docker run -i --rm ghcr.io/tide-foundation/forseti-compiler:latest --json

# ORK Compile API (if running locally)
curl -s -X POST http://localhost:8080/Forseti/Compile/preview \
  -H "Content-Type: application/json" \
  -d '{"source": "public class T : Ork.Forseti.Sdk.IAccessPolicy { public Ork.Forseti.Sdk.PolicyDecision Authorize(Ork.Forseti.Sdk.AccessContext c) { return Ork.Forseti.Sdk.PolicyDecision.Allow(); } }"}'
```

Both should return identical `contractId` values.

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
