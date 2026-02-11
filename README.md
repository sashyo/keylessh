<div align="center">
  <img src="client/public/favicon.svg" width="96" height="96" alt="KeyleSSH logo" />
  <h1>KeyleSSH</h1>
  <p><strong>Truly keyless SSH.</strong></p>
  <p>The world's first SSH client where private keys don't exist - not on servers, not in bastions, not in browsers, not even in memory. Powered by Tide's decentralised cryptography.</p>
</div>

<p align="center">
  <img src="docs/demo.gif" alt="KeyleSSH Demo" width="800" />
</p>

## What Makes KeyleSSH Different

Traditional SSH clients have a fundamental problem: private keys. Whether stored on a server, uploaded by users, or generated in the browser, private keys will always be the greatest security liability - they can be stolen, leaked, or compromised.

**KeyleSSH eliminates private keys entirely.**

Instead of managing keys, KeyleSSH uses [Tide technology](https://tide.org) for all its cryptographic operations. SSH authorization signing happens across a **decentralised network of independent nodes called ORKs** (Orchestrated Recluders of Keys) - no single point ever holds a complete key. This isn't just distributed, it's truly decentralised (the key never exists as a whole under any single organization).

### How It Works

1. **No key import, no key storage** - Users authenticate via TideCloak (OIDC), receiving a "doken" (delegated token)
2. **Policy-based authorization** - Admins define who can SSH as which SSH user under what role, via **Forseti** contracts (C# policies executed in sandboxed ORKs)
3. **Decentralised signing** - When SSH needs a authorization signature, ORKs validate against the policy and collaboratively sign the challenge
4. **Threshold cryptography** - The signing key exists mathematically split across multiple independent ORKs; no single node can sign alone
5. **Blind bastion tunneling** - All SSH session are tunneled through an oblivious jumpbox that has no access or knowledge of to the content of the session

The result: enterprise-grade SSH access control without any private keys to manage, rotate, or protect.

## Features

- **Browser-side SSH** via `@microsoft/dev-tunnels-ssh` + `xterm.js`
- **SFTP file browser** - Browse, upload, download, rename, delete files via split-panel UI
- **Quorum-based RBAC, zero-knowledge OIDC login** with TideCloak - no passwords, no keys
- **Programmable policy encforcement** with Forseti contracts for SSH access
- **Simple, static, trustless SSH account access** (e.g., only `ssh:root` role holders can SSH as root)
- **Admin UX**: servers, users, roles, policy templates, change requests (access, roles, policies), sessions, logs
- **Optional external bastion** (`tcp-bridge`) for scalable WS↔TCP tunneling

## Documentation

- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Deployment: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Developer guide: [docs/DEVELOPERS.md](docs/DEVELOPERS.md)

## Quickstart (Local Dev)

### 1. Clone and start TideCloak

```bash
git clone https://github.com/sashyo/keylessh.git
cd keylessh/script/tidecloak
./start.sh
```

### 2. Activate your free Tide subscription

During initialization, you'll be prompted to:

1. **Enter an email to manage your license** - Provide a valid email address for your Tide subscription
2. **Accept the Terms & Conditions** - Review the terms at https://tide.org/legal and enter `y` or `yes` to agree

### 3. Link your Tide account

The script will generate an invite link:

```
🔗 INVITE LINK (use this one):
http://localhost:8080/realms/keylessh/login-actions/action-token?key=...
```

Open this link in your browser and either:
- Create a new  tide account, or
- Sign in with your existing Tide account

### 4. Wait for initialization

The script will detect when linking is complete and continue finishing the setup:

```
🎉 Tidecloak initialization complete!
```

### 5. Start the app

```bash
cd ../..  # back to keylessh root
npm install
npm run dev
```

Access the KeyleSSH app in your browser at: `http://localhost:3000`

## Example server set-up

Here's how you set up a locally-hosted SSH server and access it using KeyleSSH:

> [!NOTE]
> This guide will show you how to spin up a minimal Alpine docker image on your localhost, enable SSH on it on port 2222, set up a new user on it, and enable it for passwordless, key-base authentication.

1. Go to [servers](http://localhost:3000/admin/servers) -> `Add Server` -> 
   - Server Name: _myserver_
   - Host: _localhost_
   - Post: _2222_
   - SSH Users: _user_
   - Click `Add Server` button
   - Status should come up as `Online`
2. Go to [Roles](http://localhost:3000/admin/roles) -> `Add Role`
   - Role Name (SSH Role: ✅): user (it'll autochange it to `ssh:user`)
   - Click the `Create Role` button
3. Go to [Users](http://localhost:3000/admin/users) -> 
   - Click the `Action` button (✏️) for the default `admin user`
   - Click the `ssh:user` tag in `Available Roles` to move it to `Assigned Roles`
   - Click the `Save Changes` button
4. Go to [Change Requests](http://localhost:3000/admin/approvals) ->
   - Click the `Review` button (👁️) for the user `admin`
   - Confirm User Access Change by clicking the `Y` button
   - Click the `Submit Approvals` button
   - Click  the `Commit` button (📤) for the user `admin` 
   - Change over to the `Policies` tab
   - Click the `Review` button (👁️) for the policy role `ssh:user`
   - Confirm User Access Change by clicking the `Y` button
   - Click the `Submit Approvals` button
   - Click the `Commit` button (📤) for the policy role `ssh:user`
5. Expand your user profile (a `AD admin` icon at the bottom-left of your KeyleSSH browser windows) ->
   - Click `Restart session` to quickly log out and in again
5. Go to [Dashboard](http://localhost:3000/app) -> `myserver` -> SSH USER: `user` -> `Connect` ->
   - In the `Terminal Workspace`, click the `Connect` button
   - Copy the "Tide SSH public key" string (click the `Copy` button)

Spin up an Alpine server with SSH access allowed for user `root` (password `root` AS AN EXAMPLE ONLY!) by running this on your local machine's command-line:
```bash
sudo docker run -d \
  -p 2222:22 \
  --name tinyssh \
  alpine sh -c "
    apk add --no-cache openssh && \
    ssh-keygen -A && \
    echo 'root:root' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    /usr/sbin/sshd -D
  "
```

Connect to that new server via your command-line SSH:
```bash
ssh root@localhost -p 2222
```
(use `root` as your password)

In the newly created SSH session, enter the following commands - but use the "Tide SSH public key" you copied earlier instead of the "blahblah" one used in this example:
```bash
adduser -D -s /bin/sh user
passwd -d user
mkdir -p /home/user/.ssh
chmod 700 /home/user/.ssh
chown user:user /home/user/.ssh
echo "ssh-ed25519 blahblahblah user@keylessh" > /home/user/.ssh/authorized_keys
chmod 600 /home/user/.ssh/authorized_keys
chown user:user /home/user/.ssh/authorized_keys
```

Now return to the KeyleSSH `Dashboard` page where the "Authorize SSH Session" pop-up is opened, and click the `Authorize & Connect` button.

Your SSH session to your server `myserver` will commence.

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

The KeyleSSH Server JWT verification config (holding the JWKS keychain) must be downloaded and put here: `data/tidecloak.json` .
See any of the [guides](https://docs.tidecloak.com/Languages/React/tidecloak-react-tutorial-quickstart?_highlight=Download%20adaptor%20configs#1-prepare-tidecloak) for instructions.

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
