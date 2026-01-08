# Deployment (Production)

This app has two deployable services and requires a TideCloak docker instance and connectivity to the Tide Decentralized Network (Tide Cybersecurity Fabric):

1. **Main server** (required): serves the React app + REST API + default local `/ws/tcp` WebSocket bridge.
2. **TideCloak server** (required): serves the authentication and authorization services.
3. **Blind bridge** (optional): `tcp-bridge` as a separate, auto-scaling WS↔TCP forwarder (recommended for high concurrency).
4. **Tide Fabric** (provided by Tide): Tide's Decentralized Network for Policy authorization and SSH signing.

For most deployments you run **one main server** with a persistent `data/` volume, connectivity to the Tide Fabric, and optionally an external `tcp-bridge`.

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
- TideCloak JWKS adaptor: `./data/tidecloak.json` (required for JWT verification)

In production you should mount `./data` as a persistent volume.

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

# Optional external TCP bridge (uses same tidecloak.json for JWT verification)
BRIDGE_URL=wss://<your-bridge-fqdn>

# Debug logging
DEBUG=true
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
