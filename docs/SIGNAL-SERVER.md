# Signal Server (STUN): An Easy Guide

This is a beginner-friendly guide to the **signal server** and its **STUN/TURN
(coturn)** sidecar. The user-facing "stun server" is really these two pieces
working together. This is the companion to
[PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) — the signal server and a punchd gateway
are the two halves of **remote mode** (reaching a target across the internet
through NAT).

If you just want the full deployment reference (every env var, coturn tuning,
firewall detail), see [DEPLOYMENT.md](DEPLOYMENT.md) section 2. For the
under-the-hood WebRTC/STUN packet flow, see [flow-diagram.md](flow-diagram.md).
This guide is the on-ramp.

---

## 1. What is it, in plain words?

A **punchd gateway** lives inside a private network and dials *out*. But for a
browser on the internet to actually reach that gateway, the two need to (a)
find each other and (b) punch a path through both sides' NAT. That's what this
component does:

```
Punchd gateway  ──registers──▶  Signal server  ◀──asks for a gateway──  Browser
   (private LAN)                  (public 9090)                          (internet)
        │                              │                                      │
        └───────────── coturn (STUN/TURN, 3478) helps both sides ────────────┘
                        discover public addresses / relay if NAT is strict
```

Two jobs, two programs:

| Piece | What it does |
|-------|--------------|
| **Signal server** (port `9090`) | The **rendezvous + registry**. Gateways register with it; browsers ask it for a gateway; it relays the WebRTC SDP/ICE handshake between them and hands out fresh TURN credentials. It does NOT carry your SSH bytes once P2P is up. |
| **coturn** (STUN/TURN, port `3478`) | The **address discovery + relay**. STUN tells each side its own public IP:port so they can connect directly. TURN relays the media when the NAT is too strict for direct P2P. |

### When do I even need this?

Mirror of the decision in the gateway guide:

| Situation | Do you need the signal server? |
|-----------|-------------------------------|
| Target directly reachable from the KeyleSSH server | **No.** Built-in bridge handles it. |
| Target behind NAT, but browser + gateway share a network (local/offline gateway) | **No.** Run the gateway in local/offline mode. |
| Target behind NAT and you reach it **across the internet** | **Yes.** You need a signal server + coturn, plus a gateway pointed at it. |

So: **only deploy this when you're doing internet-wide NAT traversal.** For
same-network setups, skip it entirely and follow the local/offline steps in
[PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) section 5.

---

## 2. How the pieces talk

1. **Gateway registers.** On startup the gateway opens a WebSocket to the
   signal server and sends a `role: "gateway"` message. The signal server
   checks the shared **`API_SECRET`** (a timing-safe compare) before adding it
   to the registry. Wrong/missing secret → rejected. This only stops rogue
   daemons from registering; it is **not** end-user auth.
2. **Browser requests a gateway.** A browser (a `role: "client"`) asks for a
   gateway — either the least-loaded one or an explicit target id.
3. **Signal server relays the handshake.** It passes WebRTC SDP offers/answers
   and ICE candidates between the paired browser and gateway, and generates
   short-lived **TURN credentials** (HMAC of the `TURN_SECRET`) so both sides
   can use coturn.
4. **P2P forms.** Using STUN-discovered addresses the two connect directly
   (WebRTC DataChannel); if the NAT is symmetric they fall back to relaying
   through coturn (TURN). From here the signal server is out of the data path.

You can watch registration land on the health endpoint:

```bash
curl https://YOUR_SIGNAL_SERVER:9090/health
# {"status":"ok","gateways":1,"clients":0}   <- gateways went from 0 to 1
```

> **Trust model:** the signal server never authenticates end users — it only
> gatekeeps gateway registration and config pushes with `API_SECRET`. User auth
> happens at the gateway; see [PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) section 4.

---

## 3. The implementation

The signal server is `signal-server-rs/` (Rust) — binary `signal-server-rs`,
deployed with `signal-server-rs/deploy.sh`. It pairs with a `coturn` container
for STUN/TURN, and adds a QUIC/WebTransport relay (`RELAY_PORT`, default `7893`)
for the VPN path. This is the implementation to use; it matches the Rust gateway
documented in [PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md).

> `signal-server-rs` has its **own** deploy script and coturn setup — you do
> not need anything else to stand it up. Its `deploy.sh` builds a native binary
> (`cargo build --release`) and runs it with `nohup` (not Docker); coturn runs
> as a Docker container. See section 4.

---

## 4. Quick start: deploy signal server + coturn (Rust)

Run this on a **public-facing VM** (it needs a public IP and open ports).

### Prerequisites

- A VM with a public IP.
- `docker` (for coturn), `cargo`/`rustc` (to build the signal server),
  `openssl`, `curl`.
- A `tidecloak.json` for JWT config (auto-detected from `data/tidecloak.json`;
  see the assumptions note below about whether the Rust server actually
  consumes it).

### Step 1 — Run the deploy script

```bash
cd signal-server-rs
./deploy.sh
```

On the first run it:
- Generates `API_SECRET` and `TURN_SECRET` (each `openssl rand -hex 32`) and
  saves them to `signal-server-rs/.env` (chmod 600).
- Auto-detects your public IP (via `ifconfig.me`) as `EXTERNAL_IP` — if
  detection fails it writes `REPLACE_ME` and you must edit `.env`.
- Pulls `coturn/coturn:latest` and starts coturn (see the exact flags below).
- `cargo build --release` and starts `target/release/signal-server-rs` under
  `nohup` (PID in `/tmp/signal-server-rs.pid`, logs in
  `/tmp/signal-server-rs.log`).
- If `/etc/letsencrypt/live/<domain>/` exists, it wires TLS
  (`TLS_CERT_PATH`/`TLS_KEY_PATH`) and switches URLs to `https`/`wss`.

### Step 2 — Save the secrets it prints

The script prints a summary like:

```
  Signal:    http://YOUR_IP:9090
  Signaling: ws://YOUR_IP:9090
  Health:    http://YOUR_IP:9090/health
  Relay:     YOUR_IP:7893 (QUIC/WebTransport)
  STUN/TURN: YOUR_IP:3478
  API_SECRET: set
```

**Save `API_SECRET` and `TURN_SECRET`** (from `signal-server-rs/.env`). You'll
pass the same values to every gateway that registers here.

### Step 3 — Verify

```bash
curl -k http://YOUR_IP:9090/health
# {"status":"ok","gateways":0,"clients":0}
docker ps            # coturn should be running
tail /tmp/signal-server-rs.log
```

### Step 4 — Point a gateway at it

On the gateway host, add the signal server to its `gateway.toml` (from
[PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) section 6):

```toml
stun_server_url = "wss://YOUR_SIGNAL_SERVER:9090"   # ws:// if no TLS
api_secret      = "<API_SECRET from this deploy>"
turn_secret     = "<TURN_SECRET from this deploy>"   # only needed for TURN relay
```

Then re-check `/health` — `gateways` should tick up to `1`.

### coturn flags the script uses (verified, both deploy scripts)

```
--listening-port=3478
--external-ip=<EXTERNAL_IP>
--use-auth-secret
--static-auth-secret=<TURN_SECRET>
--realm=keylessh
--min-port=49152 --max-port=65535
--fingerprint --no-multicast-peers --no-cli
```

`--use-auth-secret` + `--static-auth-secret=<TURN_SECRET>` is what lets the
signal server mint short-lived TURN credentials that coturn accepts — this is
why the gateway's `TURN_SECRET` must match.

---

## 5. Config / env reference (Rust signal server)

Verified against `signal-server-rs/src/config.rs`.

| Env var | Default | Meaning |
|---------|---------|---------|
| `PORT` | `9090` | Signaling WebSocket + HTTP port |
| `RELAY_PORT` | `7893` | QUIC / WebTransport relay port (UDP) |
| `API_SECRET` | `""` (empty = open) | Shared secret gateways present to register |
| `TURN_SECRET` | `""` | Must match coturn's `--static-auth-secret` and the gateway's `TURN_SECRET` |
| `ICE_SERVERS` | `""` | STUN server list handed to clients, e.g. `stun:host:3478` |
| `TURN_SERVER` | unset | TURN fallback URL, e.g. `turn:host:3478` |
| `TLS_CERT_PATH` | unset | TLS cert (enables `https`/`wss`) |
| `TLS_KEY_PATH` | unset | TLS private key |
| `RELAY_HOST` | `punchd.keylessh.com` | Hostname advertised for the relay. The deploy script overrides this to your domain or `EXTERNAL_IP`. |
| `TIDECLOAK_URL` | unset | TideCloak base URL |
| `ALLOWED_ORIGINS` | `""` (empty = any) | Comma-separated origin allowlist for browser connections |
| `TRUSTED_PROXIES` | `""` | Comma-separated proxy IPs whose forwarded-for header is believed when determining a client's real address. Leave empty unless the signal server sits behind a load balancer. |

Two limits are compiled in rather than configurable: **20 connections per IP**
and **100 messages per second** per connection.

---

## 5a. HTTP API

Everything here is on the same port as the signaling WebSocket (`PORT`, default
`9090`).

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /health` | none | `{"status":"ok","gateways":N,"clients":N}` — the quickest check that a gateway registered |
| `GET /webrtc-config` | none | ICE/TURN details and short-lived TURN credentials for browsers |
| `GET /api/gateways` | none | Registered gateways, their backends, and the TideCloak issuer each one trusts |
| `POST /api/gateways/{id}/config` | `x-api-secret` | Push config to a running gateway |

### Filtering gateways by tenant

When one signal server is shared by two KeyleSSH deployments (demo and devops,
say), each console should see only its own gateways — the others could never
connect anyway, since a gateway on another realm can't verify its tokens.
Gateways advertise the issuer they trust, so:

```bash
curl "https://YOUR_SIGNAL_SERVER:9090/api/gateways?issuer=https://tc.example.com/realms/demo"
```

KeyleSSH passes its own issuer automatically. Gateways predating the field don't
advertise one and are always returned, so a staggered upgrade won't blank a list.

### Pushing config to a gateway

`POST /api/gateways/{id}/config` forwards config down the gateway's existing
WebSocket, so backends can be edited from the console instead of on the box.
Authenticated with `API_SECRET` via an `x-api-secret` header.

| Response | Meaning |
|----------|---------|
| `200`, `delivered: true` | Applied; `applied` and `rejected` list which fields |
| `202`, `pending: true` | Gateway offline — held until it next registers (newest push wins) |
| `401` | Wrong or missing `x-api-secret` |
| `504` | Delivered, but no confirmation within 15s |

The gateway refuses anything that would change which TideCloak it trusts
(`tidecloak_config_*`, `auth_server_public_url`, `tc_internal_url`) or its own
identity (`gateway_id`, `stun_server_url`, `api_secret`). Since `API_SECRET` is
one shared value, a pushable trust anchor would let anyone holding it repoint a
gateway at their own IdP.

---

## 6. Ports and firewall

Open these on the signal server VM (the deploy script prints the same list):

| Port | Protocol | Purpose |
|------|----------|---------|
| `9090` | TCP | Signal server (HTTP + WebSocket signaling) |
| `7893` | UDP | QUIC / WebTransport relay (Rust only) |
| `3478` | UDP + TCP | STUN + TURN (coturn) |
| `49152-65535` | UDP | TURN relay media range |

For the signal server to be reachable over the internet, `9090` and `3478`
must be publicly open, and the VM must have a real public IP set as
`EXTERNAL_IP` (coturn's `--external-ip`).

---

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `/health` shows `"gateways":0` after starting a gateway | Gateway didn't register. Check the gateway's `stun_server_url` is `ws(s)://YOUR_IP:9090` and its `api_secret` **exactly matches** the signal server's `API_SECRET`. Watch `/tmp/signal-server-rs.log`. |
| Deploy fails: `EXTERNAL_IP not set` / `REPLACE_ME` | Public IP auto-detect failed. Edit `signal-server-rs/.env`, set `EXTERNAL_IP` to the VM's public IP, re-run `./deploy.sh`. |
| coturn "failed to start" | Port `3478` already in use, or Docker can't bind with `--network host`. `docker logs coturn --tail 20`. |
| P2P connects on same LAN but not across the internet | STUN reachable but TURN relay not configured/open. Ensure `TURN_SERVER` + `TURN_SECRET` are set and `3478` + `49152-65535/udp` are open on the firewall. |
| Browser can't reach `wss://…:9090` (mixed content / cert error) | No TLS configured, or self-signed cert. For public use, put a Let's Encrypt cert under `/etc/letsencrypt/live/<domain>/` before running `deploy.sh` (it auto-wires `TLS_CERT_PATH`/`TLS_KEY_PATH` and switches to `wss`). |
| TURN credentials rejected | `TURN_SECRET` mismatch between the signal server, coturn (`--static-auth-secret`), and the gateway. All three must be the same value. |
| Not sure what's running | `docker ps` (coturn) + `pgrep -f signal-server-rs` (signal server) + `cat /tmp/signal-server-rs.pid`. |

---

## 8. Assumptions and things to verify with your deployment

Grounded in the repo's code/scripts. These are deployment-specific and could
not be confirmed from source alone — verify for your environment (some carry
over from the gateway guide):

- **Is a live signal server actually running at `punchd.keylessh.com`?** That
  hostname is only the built-in default for `RELAY_HOST`
  (`signal-server-rs/src/config.rs`) and a TideCloak origin binding. Whether a
  real signal server is deployed there for your setup is not something the repo
  can tell you — the deploy script points gateways at *your* VM's IP/domain, not
  `punchd.keylessh.com`.
- **Realm/client (`myclient-stun` vs `s5`).** As in the gateway guide: the
  realm template (`script/tidecloak/realm.json`) is realm `keylessh` with
  clients `myclient` + `myclient-stun`, but the checked-in adapter config
  (`data/tidecloak.json`) is realm `s5` / client `myclient`. Confirm which
  realm/clients your deployment uses.
- **Rust server + `tidecloak.json`.** The Rust config exposes `TIDECLOAK_URL`,
  and the Rust `deploy.sh` does not push a `tidecloak.json` into the signal
  server the way it configures coturn. Whether/how the signal server itself
  verifies JWTs (vs. leaving all JWT checks to the gateway) is a detail to
  confirm against `signal-server-rs/src/` for your version before relying on it.
- **TLS in practice.** The scripts only auto-wire TLS if
  `/etc/letsencrypt/live/` already contains a cert. Obtaining/renewing that
  cert is on you (not automated by `deploy.sh`).
