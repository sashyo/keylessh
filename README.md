<div align="center">
  <img src="client/public/favicon.svg" width="96" height="96" alt="KeyleSSH logo" />
  <h1>KeyleSSH</h1>
  <p><strong>Truly keyless SSH.</strong></p>
  <p>The world's first web SSH client where private keys don't exist - not on servers, not in browsers, not even in memory. Powered by Tide's decentralised threshold cryptography.</p>
</div>

<p align="center">
  <img src="docs/demo.gif" alt="KeyleSSH Demo" width="800" />
</p>

## What Makes KeyleSSH Different

Traditional web SSH clients have a fundamental problem: private keys. Whether stored on a server, uploaded by users, or generated in the browser, private keys are always a liability - they can be stolen, leaked, or compromised.

**KeyleSSH eliminates private keys entirely.**

Instead of managing keys, KeyleSSH uses [Tide Protocol](https://tide.org) and TideCloak for cryptographic operations. SSH signing happens across a **decentralised network of independent nodes called ORKs** (Orchestrated Recluded Keys) - no single point holds a complete key. This isn't just distributed (copies everywhere), it's truly decentralised (the key never exists as a whole).

### How It Works

1. **No key import, no key storage** - Users authenticate via TideCloak (OIDC), receiving a "doken" (delegated token)
2. **Policy-based authorization** - Admins define who can SSH as which user via Forseti contracts (C# policies executed in sandboxed ORKs)
3. **Decentralised signing** - When SSH needs a signature, ORKs validate the policy and collaboratively sign the challenge
4. **Threshold cryptography** - The signing key is mathematically split across multiple independent ORKs; no single node can sign alone

The result: enterprise-grade SSH access control without any private keys to manage, rotate, or protect.

## Features

- Browser-side SSH via `@microsoft/dev-tunnels-ssh` + `xterm.js`
- **SFTP file browser** - Browse, upload, download, rename, delete files via split-panel UI
- OIDC login with TideCloak - no passwords, no keys — https://tide.org
- **Policy:1 authorization** with Forseti contracts for SSH signing
- Role-based SSH access (e.g., only `ssh:root` role holders can SSH as root)
- Admin UX: servers, users, roles, policy templates, approvals, sessions, logs
- Optional external `tcp-bridge/` for scalable WS↔TCP forwarding

## Documentation

- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Deployment: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Developer guide: [docs/DEVELOPERS.md](docs/DEVELOPERS.md)

## Quickstart (Local Dev)

```bash
npm install
npm run dev
```

App: `http://localhost:3000`

## Scripts

- `npm run dev` - start server + Vite dev integration
- `npm run build` - build client + bundle server
- `npm start` - run production build from `dist/`
- `npm run check` - TypeScript typecheck

## Configuration

### Environment variables

```env
PORT=3000

# Optional external TCP bridge (for scaling)
# Bridge verifies JWTs against same tidecloak.json - no shared secret needed
BRIDGE_URL=ws://localhost:8080

# SQLite (file path)
DATABASE_URL=./data/keylessh.db
```

### TideCloak configuration

- Browser adapter config: `client/src/tidecloakAdapter.json`
- Server JWT verification config (JWKS): `data/tidecloak.json`

## Key Dependencies

- Authentication: `@tidecloak/react` (wraps/uses `@tidecloak/js`)
- Tide Protocol: `heimdall-tide` (Policy, PolicySignRequest, TideMemory for signing)
- Terminal: `@xterm/xterm`
- Browser SSH: `@microsoft/dev-tunnels-ssh` and `@microsoft/dev-tunnels-ssh-keys`
- API state: `@tanstack/react-query`
- Server: `express`, `ws`
- Storage: `better-sqlite3`, `drizzle-orm`

## Policy:1 Authorization

SSH signing uses the Tide Protocol's Policy:1 auth flow with Forseti contracts:

1. Admin creates SSH policies via policy templates (defines role, resource, approval type)
2. Policies are signed and committed to the ORK network
3. When a user connects via SSH, their doken is validated against the policy
4. ORKs execute the Forseti contract (C# code in sandbox) to authorize
5. If authorized, ORKs collaboratively produce a signature for the SSH challenge

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full flow diagram.

## Contributing

See [docs/DEVELOPERS.md](docs/DEVELOPERS.md).

## Deployment Options

KeyleSSH is **open source** and designed for flexible deployment:

### Self-Hosted (No Limits)
Deploy KeyleSSH for your organization with **no usage restrictions**. By default, there are no limits on users, servers, or features. Perfect for:
- Enterprise internal deployments
- Development teams
- Personal/homelab use

Just follow the [Deployment Guide](docs/DEPLOYMENT.md) - no licensing configuration needed.

### SaaS Mode (Tiered Billing)
If you want to offer KeyleSSH as a commercial service with subscription tiers, configure Stripe billing:
- Free tier: 5 users, 2 servers
- Pro tier: 25 users, 10 servers
- Enterprise tier: Unlimited

See [SaaS Configuration](docs/DEPLOYMENT.md#saas-mode-stripe-billing) in the deployment guide.

## License

MIT
