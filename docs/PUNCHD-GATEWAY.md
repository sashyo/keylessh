# Punchd Gateway: An Easy Guide

This is a beginner-friendly guide to **punchd**, KeyleSSH's NAT-traversal
gateway. It explains what punchd is, *when* you actually need it, and the
simplest path to standing one up.

If you already understand the concept and just want the full deployment
reference (every env var, TURN/coturn tuning, RDP/VPN options), jump to
[DEPLOYMENT.md](DEPLOYMENT.md) sections 2-5. This guide is the on-ramp; that
one is the manual.

---

## 1. What is punchd, in plain words?

Normally, when you open an SSH session in KeyleSSH, your browser's traffic
flows like this:

```
Browser  ──ws──▶  KeyleSSH server  ──TCP──▶  target SSH server
```

The KeyleSSH server opens a plain TCP connection straight to the target
(`server/wsBridge.ts` does this with `net.connect`). That works great **when
the KeyleSSH server can reach the target directly** — same network, or a target
with a public address.

But often the target sits **behind NAT / a firewall** on a private network
(an office LAN, a home network, a cloud VPC with no inbound ports). The
KeyleSSH server cannot dial into it. This is where **punchd** comes in.

A **punchd gateway** is a small daemon you run *inside* that private network,
next to the target. Instead of anyone dialing *in*, the gateway dials *out* to
a public **signal server** and stays connected. When you want to reach the
target, your browser and the gateway meet at the signal server and
"hole-punch" a direct peer-to-peer path (falling back to a relay if the NAT is
strict). The path becomes:

```
Browser  ◀──────▶  Signal server  ◀──────▶  Punchd gateway  ──▶  target SSH server
             (rendezvous / STUN)      (dials OUT, on the       (on the same
                                        private LAN)             private LAN)
```

So, in one sentence: **punchd lets you reach SSH (and RDP / web / VPN) targets
that live behind NAT, without opening any inbound ports on their network.**

### When do I need it?

| Situation | What to use |
|-----------|-------------|
| Target is directly reachable from the KeyleSSH server (same LAN, public IP) | Nothing — the built-in bridge (`/ws/tcp`) handles it. |
| Target is behind NAT / firewall, no inbound ports, but on YOUR network | A punchd gateway in **local/offline mode** (no signal server). |
| Target is behind NAT and you need to reach it across the internet | A punchd gateway **+ a signal server** (full NAT traversal). |

> **Note:** punchd also does RDP (passwordless via TideSSP) and a QUIC VPN.
> This guide focuses on the SSH gateway path. For RDP/VPN see
> [DEPLOYMENT.md](DEPLOYMENT.md) sections 4-6.

---

## 2. How KeyleSSH decides direct vs gateway

You don't have to trust magic here — the routing is a simple decision made per
server. When you start a session, the KeyleSSH server picks the path based on
the server's `bridgeId` (`server/routes.ts`, the `POST /api/sessions` handler):

| `bridgeId` value | Path taken | Browser connects to |
|------------------|------------|---------------------|
| *(none)* | Built-in embedded bridge (direct TCP) | `ws(s)://<keylessh>/ws/tcp` |
| a Bridge record UUID | External TCP bridge | that bridge's URL |
| `gateway:<url>` | **Punchd gateway** | `ws(s)://<gateway>/ws/ssh` |

The browser then builds the final WebSocket URL from that decision
(`client/src/lib/sshClient.ts`, `buildWebSocketUrl`). So "route this server
through my gateway" is literally just setting that server's connection method
to a `gateway:` entry (done from the **Servers** admin page).

---

## 3. The pieces

Two programs make up the punchd system. You may need one or both.

| Piece | Where it lives in the repo | What it does | Where it runs |
|-------|----------------------------|--------------|---------------|
| **Punchd gateway** | `bridges/punchd-bridge-rs/` (Rust) | Dials out to the signal server; proxies your SSH/HTTP/RDP backends | Inside the private network, next to the target |
| **Signal server** | `signal-server-rs/` (Rust) | Public rendezvous point: matches browsers with gateways, hands out STUN/TURN info | A public-facing VM (paired with a `coturn` STUN/TURN sidecar) |

**You can skip the signal server entirely** if the browser and gateway are on
the same network (local/offline mode). You only need the signal server for
NAT traversal across the internet.

### Gateway ports

| Port | Purpose | Env |
|------|---------|-----|
| `7891` | Proxy (`/ws/ssh`, HTTP, RDP) | `LISTEN_PORT` |
| `7892` | Health + logs | `HEALTH_PORT` |
| `7893` UDP | QUIC (P2P + VPN) | `QUIC_PORT` |

Signal server and coturn ports are in
[SIGNAL-SERVER.md](SIGNAL-SERVER.md) section 6.

---

## 4. The auth / trust model (why it's safe)

- **Users** authenticating to the gateway use the **same TideCloak (OIDC) JWT +
  DPoP** they already use everywhere in KeyleSSH. The gateway loads the realm's
  public keys (JWKS) from a `tidecloak.json` and verifies every JWT locally.
  Access to a backend is gated by TideCloak roles (e.g. `ssh:<user>`,
  `dest:<gatewayId>:<backend>`). No secret in the gateway can grant access on
  its own.
- **The gateway registering with the signal server** uses a shared secret,
  `API_SECRET`, checked at registration (`signal-server-rs/src/signaling/`).
  This just stops random daemons from registering as gateways; it is **not**
  user auth.
- **The signal server is a "dumb relay"** — it does not authenticate end users.
  It only pairs a browser with a gateway; the gateway does the real JWT check.
- **TLS** on the gateway is a **self-signed** cert used purely to encrypt the
  hop. Trust comes from the JWT/DPoP, not the cert chain.

### The `punchd.keylessh.com` origin and the `myclient-stun` client

You'll see `punchd.keylessh.com` in the config. When a gateway hosts its own
login portal, the browser logs in through a dedicated TideCloak **public
client** called `myclient-stun`, defined in
`script/tidecloak/realm.json` (realm template `keylessh`). It is bound to the
`punchd.keylessh.com` origin (and localhost dev origins) via redirect URIs /
web origins, and the live adapter config carries a matching Tide
`client-origin-auth-https://punchd.keylessh.com` origin-binding signature. In
short: `myclient-stun` is the gateway-portal login client; `punchd.keylessh.com`
is its expected public origin.

> **Assumption / check with your deployment:** the in-repo realm template names
> the realm `keylessh`, but the checked-in adapter config (`data/tidecloak.json`)
> is realm `s5` with app client `myclient`. Confirm which realm/clients your
> actual deployment uses before relying on `myclient-stun` existing there.

---

## 5. Quick start: local/offline SSH gateway (no signal server)

Use this when the target is behind NAT **but on a network your browser can also
reach** (e.g. same office LAN). This is the simplest possible setup.

### Step 1 — Create the gateway config

On the machine that will run the gateway (it must be able to reach the SSH
target), create `gateway.toml`:

```toml
gateway_id  = "office-gateway"
backends    = "MyServer=ssh://localhost:22;noauth"
listen_port = 7891
health_port = 7892
https       = false
```

- `backends` maps a **name** to a target. `ssh://localhost:22` means "SSH to
  port 22 on this machine"; change the host/port to point at your real target.
- `;noauth` tells the gateway not to require a JWT for that backend (the SSH
  server still does its own auth). Drop it to require a TideCloak JWT at the
  gateway too.
- `https = false` matters for local use — see the warning in Step 4.

Also drop a `tidecloak.json` next to it (TideCloak Admin Console → your client →
Action → Download adapter config). It's required even in offline mode, for JWT
verification.

### Step 2 — Run the gateway

Easiest is Docker (from the repo root, or clone the repo on the gateway host):

```bash
cd bridges/punchd-bridge-rs
docker build -t punchd-gateway .

docker run -d --restart unless-stopped \
  --name punchd-gateway \
  --network host \
  -v "$PWD/gateway.toml:/app/gateway.toml" \
  -v "$PWD/tidecloak.json:/app/data/tidecloak.json" \
  punchd-gateway
```

Prefer a native binary or a Windows/Linux installer? See
[DEPLOYMENT.md](DEPLOYMENT.md) section 5 ("Local/Offline Mode") for the
`.deb`, MSI, `cargo build`, and systemd variants.

### Step 3 — Confirm it's up

```bash
curl http://localhost:7892/health     # -> {"status":"ok"}
curl http://localhost:7891/api/info   # lists the backends it discovered
```

### Step 4 — Point KeyleSSH at it

1. In the KeyleSSH Dashboard, open the **Local Gateways** tab → **Add Gateway**
   and enter `http://YOUR_GATEWAY_IP:7891`. The gateway's `/api/info` endpoint
   auto-discovers its backends.
2. When adding/editing a **Server** in the admin UI, set its **Connection
   Method** to that gateway. (Under the hood this stores
   `bridgeId = "gateway:http://YOUR_GATEWAY_IP:7891"`, so sessions route through
   `/ws/ssh` on the gateway.)

> **Important (self-signed HTTPS gotcha):** for local gateways keep
> `https = false` in `gateway.toml` **and** open KeyleSSH over
> `http://localhost:3000`, not HTTPS. Browsers block background
> fetch/WebSocket calls to a self-signed HTTPS gateway even after you accept
> the cert manually. (Documented in DEPLOYMENT.md section 5.)

That's it. Open a session to that server and the traffic now flows
browser → gateway → target.

---

## 6. Going remote: adding a signal server

When the browser can't reach the gateway's network directly (true internet NAT
traversal), you add a signal server. High-level steps (full detail in
[DEPLOYMENT.md](DEPLOYMENT.md) sections 2-3):

1. **Deploy the signal server** on a public VM:
   ```bash
   cd signal-server
   ./deploy.sh
   ```
   It auto-generates `API_SECRET` and `TURN_SECRET`, starts the signal server
   (port `9090`) and a `coturn` sidecar (port `3478`), and prints the values.
   **Save `API_SECRET` and `TURN_SECRET`.**

2. **Tell the gateway about it** — add these to `gateway.toml`:
   ```toml
   gateway_id      = "office-gateway"
   stun_server_url = "wss://YOUR_SIGNAL_SERVER:9090"
   api_secret      = "<API_SECRET from step 1>"
   backends        = "MyServer=ssh://localhost:22;noauth"
   listen_port     = 7891
   health_port     = 7892
   https           = false
   ```
   (You can also pass these as env vars: `STUN_SERVER_URL`, `API_SECRET`,
   `TURN_SERVER`, `TURN_SECRET`, `ICE_SERVERS`.)

3. **Verify registration** — the gateway should now appear on the signal
   server:
   ```bash
   curl https://YOUR_SIGNAL_SERVER:9090/health
   # {"status":"ok","gateways":1,"clients":0}
   ```

The browser will now reach the gateway via the signal server (P2P when
possible, TURN relay when the NAT is strict).

---

## 7. Config / env reference (SSH-relevant subset)

These are the gateway settings you'll touch for an SSH gateway. Each `gateway.toml`
key has a matching UPPER_CASE env var. Verified against
`bridges/punchd-bridge-rs/src/config.rs`. Full table (RDP/VPN/TLS extras) is in
[DEPLOYMENT.md](DEPLOYMENT.md) section 3.

> **After the first install you rarely edit this file.** Saving under **Punchd →
> Gateways** pushes the change to the running gateway, which rewrites its own
> `gateway.toml` and reloads (rewritten from scratch, so comments don't survive).
> Doesn't apply to offline gateways, or to the TideCloak and identity settings —
> see [SIGNAL-SERVER.md](SIGNAL-SERVER.md) section 5a.

| `gateway.toml` key | Env var | Default | Meaning |
|--------------------|---------|---------|---------|
| `gateway_id` | `GATEWAY_ID` | auto `gateway-<hex>` | Unique id for this gateway |
| `backends` | `BACKENDS` | — | `Name=ssh://host:port[;noauth]`, comma-separated for multiple |
| `listen_port` | `LISTEN_PORT` | `7891` | Proxy / `/ws/ssh` port |
| `health_port` | `HEALTH_PORT` | `7892` | Health + logs port |
| `quic_port` | `QUIC_PORT` | `7893` | QUIC (P2P/VPN) UDP port |
| `https` | `HTTPS` | `true` | Self-signed TLS on the proxy (set `false` for local) |
| `tidecloak_config_path` | `TIDECLOAK_CONFIG_PATH` | `data/tidecloak.json` | JWKS source for JWT verification |
| `tidecloak_config_b64` | `TIDECLOAK_CONFIG_B64` | — | Base64 `tidecloak.json` (overrides the path) |
| `stun_server_url` | `STUN_SERVER_URL` | — (empty = offline) | Signal server WebSocket URL for remote mode |
| `api_secret` | `API_SECRET` | — | Must match the signal server's `API_SECRET` |
| `ice_servers` | `ICE_SERVERS` | derived | STUN servers, e.g. `stun:host:3478` |
| `turn_server` | `TURN_SERVER` | — | TURN fallback, e.g. `turn:host:3478` |
| `turn_secret` | `TURN_SECRET` | — | Must match the signal server's `TURN_SECRET` |

Backends take flags — `;noauth`, `;stripauth`, `;eddsa` — appended to the URL;
[DEPLOYMENT.md](DEPLOYMENT.md) section 3 explains each. The console's gateway
editor exposes them as checkboxes.

KeyleSSH-server side, `BRIDGE_URL` (in `.env`) is unrelated to punchd — it's the
fallback **external TCP bridge**, used only when a server has no `bridgeId` and
no default bridge is set (`server/routes.ts`).

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Session won't connect through a local gateway; browser console shows a blocked/CORS/mixed-content error | Self-signed HTTPS gotcha. Set `https = false` in `gateway.toml` and open KeyleSSH over `http://localhost:3000`. |
| `curl http://localhost:7892/health` fails | Gateway isn't running or `health_port` differs. Check `docker logs punchd-gateway` (or `systemctl status punchd-gateway`). |
| Gateway runs but the target never connects | Check `backends` points at a reachable host/port *from the gateway's* network, and the name you gave the backend matches the server you're routing. `curl http://localhost:7891/api/info` shows discovered backends. |
| Remote mode: signal server `/health` shows `"gateways":0` | Gateway didn't register. Verify `stun_server_url` (must be `wss://…:9090`) and that `api_secret` **exactly matches** the signal server's `API_SECRET`. |
| Connects but auth is rejected | JWT/roles. Confirm the user has the needed TideCloak role (e.g. `ssh:<user>`) and the gateway's `tidecloak.json` is for the right realm/client. Remove `;noauth` only if the backend enforces its own auth. |
| Strict NAT: P2P never establishes | TURN relay isn't configured. Set `turn_server` + `turn_secret` (matching the signal server) and open coturn's `3478` + `49152-65535/udp`. |
| Gateway logs | `curl http://localhost:7892/logs` (HTML) or `http://localhost:7892/logs/buffer` (JSON). |

---

## 9. Assumptions and things to verify with your deployment

The mechanism above is grounded in the repo's code and config. A few things are
deployment-specific and could not be confirmed from source alone — verify these
for your environment:

- **`punchd.keylessh.com` as a live host.** The domain appears only as a
  TideCloak origin / redirect binding and as the signal server's default
  `RELAY_HOST` (`signal-server-rs/src/config.rs`). Whether a real signal server
  is deployed there for your setup is not something the repo can tell you.
- **Realm/client mismatch.** The realm template (`script/tidecloak/realm.json`)
  is realm `keylessh` with clients `myclient` + `myclient-stun`; the checked-in
  adapter config (`data/tidecloak.json`) is realm `s5` / client `myclient`.
  Confirm which realm your deployment actually runs and whether `myclient-stun`
  exists there.
- **Exact SSH-over-QUIC/WebRTC transport selection.** For gateway sessions the
  client can use a WebRTC/QUIC data path in addition to the `/ws/ssh` WebSocket
  relay (`client/src/lib/sshClient.ts`). The plain `/ws/ssh` WebSocket path is
  the one documented here; the P2P upgrade details live in
  [flow-diagram.md](flow-diagram.md).
