# Punchd VPN: An Easy Guide

This is a beginner-friendly guide to the **Punchd VPN** — KeyleSSH's native,
full-tunnel VPN. It explains what the VPN is, when you'd reach for it (vs SSH or
the HTTP/RDP gateway), and how to set up both sides.

This is a companion to [PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) and
[SIGNAL-SERVER.md](SIGNAL-SERVER.md) — the VPN **reuses the same punchd gateway
and signal-server/STUN infrastructure**, so read those first if you're new to
gateways. For the full deployment reference (build flags, firewall, roles), see
[DEPLOYMENT.md](DEPLOYMENT.md) section 4.

> **Name note:** the repo calls this the **Punchd VPN**. It is *not* WireGuard
> (the protocol) and it is *not* TideSSP (that's a separate passwordless-RDP
> feature). It's a custom IP tunnel that carries packets over the gateway's
> WebRTC/QUIC data path.

---

## 1. What is it, in plain words?

SSH and the gateway backends give you access to **one service at a time** (an
SSH server, a web app, an RDP host). The **VPN** instead gives your device a
**virtual network interface** and routes real IP traffic to a whole private
network — like being plugged into the office LAN from anywhere.

Your device runs a small **VPN client** (`punchd-vpn`) that creates a **TUN**
(virtual network) adapter. Packets that enter that adapter are tunnelled to a
**punchd gateway** sitting inside the target network; the gateway has its own
TUN device, gives your client an IP from a pool, and forwards your packets onto
the LAN.

```
Your device                         Punchd gateway (in the private LAN)
┌──────────────┐                    ┌───────────────────────────────┐
│ punchd-vpn   │  IP packets over   │ gateway TUN (10.66.0.1)        │
│ TUN adapter  │◀═ WebRTC/QUIC P2P ═▶│ + IP pool (10.66.0.0/24)      │──▶ LAN hosts
│ (10.66.0.x)  │  (via signal srv/  │   forwards packets to the LAN │    (192.168.x, etc.)
└──────────────┘   STUN, TURN fallbk)└───────────────────────────────┘
```

Verified data path (`bridges/punchd-bridge-rs/src/vpn/vpn_handler.rs`): the
gateway allocates a client IP from `10.66.0.0/24` (gateway is `10.66.0.1`),
creates a TUN device, and shuttles IP packets between the TUN and the WebRTC
**bulk DataChannel** (MTU 1400). It auto-detects the gateway's LAN subnets and
hands them to the client as routes.

### When do I use the VPN (vs SSH / gateway backends)?

| You want to… | Use |
|---|---|
| Shell into one SSH server | SSH (built-in bridge or a `ssh://` gateway backend) — see [PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) |
| Reach one web app / RDP host behind NAT | A gateway HTTP/`rdp://` backend |
| Reach **many hosts / arbitrary IPs+ports** on a private LAN as if you were on it | **The VPN** (this guide) |
| Passwordless RDP specifically | TideSSP (separate feature, not the VPN) |

So: **use the VPN when one-service access isn't enough and you need
network-level reach** into a private LAN.

---

## 2. The pieces (and which binary is which)

The VPN reuses the gateway + signal-server stack. There is **no separate VPN
server** — the gateway *is* the VPN server.

| Role | Component | What it is |
|------|-----------|------------|
| **VPN server** | `bridges/punchd-bridge-rs` (the **punchd gateway**) | Same Rust binary as the HTTP/SSH/RDP gateway. VPN is a built-in mode (`VpnState`), enabled by default. Runs the server TUN + IP pool + firewall. |
| **VPN client** | `punchd-vpn` (a second binary in the same crate, `src/bin/punchd_vpn.rs`) | The native client users run on their device. Creates the client TUN, does the login, connects to a gateway. |
| **Rendezvous** | `signal-server-rs` + coturn | The same signal server / STUN / TURN used for remote gateway access ([SIGNAL-SERVER.md](SIGNAL-SERVER.md)). Only needed for cross-internet NAT traversal. |

> **Not the VPN:** `TideSSP` (Windows passwordless RDP SSP, C/cmake, `tide-ssp/`)
> and `PunchdEndpoint` (a combined installer bundling TideSSP + the gateway) are
> RDP/gateway artifacts. They aren't the VPN client. The VPN client is
> `punchd-vpn`.

### Ports

The VPN rides on the gateway's QUIC port, `7893/UDP` (`quic_port` /
`QUIC_PORT`). Remote access additionally needs the signal server and coturn
ports — see [SIGNAL-SERVER.md](SIGNAL-SERVER.md) section 6.

---

## 3. The auth / access model

The VPN uses the **same TideCloak identity** as the rest of KeyleSSH — no
separate credentials.

- The client authenticates with a **TideCloak JWT** (obtained via an OIDC login;
  on Windows the MSI uses an embedded WebView2 running the full TideCloak +
  Heimdall **DPoP** flow).
- The gateway **verifies the JWT** and checks roles
  (`vpn_handler.rs` `authorize_vpn`): it collects roles from
  `realm_access.roles` + `resource_access.*.roles` and **rejects the connection
  unless the user has `vpn:<gatewayId>`** (or a `vpn:<gatewayId>:…` firewall
  role).
- **Per-user firewall from roles.** Extra `vpn:` roles become allow/deny rules
  applied to the client's traffic. With only the bare `vpn:<gatewayId>` role,
  all traffic is allowed.

| Role | Effect |
|------|--------|
| `vpn:<gatewayId>` | Grants VPN access to that gateway (required — no role, no tunnel) |
| `vpn:<gw>:allow:<proto>:<cidr>:<ports>:<priority>` | Allow matching traffic |
| `vpn:<gw>:deny:<proto>:<cidr>:<ports>:<priority>` | Deny matching traffic |

`<proto>` (`tcp`/`udp`/`icmp`/omitted=any) and `<priority>` are optional; an
older format without `<proto>` is auto-detected
(`FirewallRule::parse`, `vpn_handler.rs`). Example:
`vpn:office-gw:allow:tcp:192.168.10.0/24:22,443:10`.

---

## 4. Setup — the gateway (VPN server) side

Good news: **if you already run a punchd gateway, the VPN server is already on.**
The gateway starts `VpnState::new("10.66.0.0/24", true)` at boot
(`src/main.rs`), so the VPN mode is enabled by default.

1. **Stand up a punchd gateway** on the target network exactly as in
   [PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) (local/offline or with a signal server
   for remote access). Nothing VPN-specific is required in `gateway.toml`.

2. **Open the QUIC port.** Allow **UDP 7893** to the gateway (env `QUIC_PORT` /
   toml `quic_port` if you changed it). For remote clients behind strict NAT,
   also have the signal server's TURN reachable (`3478` + `49152-65535/udp`) —
   same as [SIGNAL-SERVER.md](SIGNAL-SERVER.md).

3. **Grant VPN roles in TideCloak.** Give each VPN user the
   `vpn:<gatewayId>` role (using the gateway's `gateway_id`). Add
   `vpn:<gw>:allow:…` / `vpn:<gw>:deny:…` roles to scope what they can reach.

4. (Optional) **Toggle VPN off/on.** Set env `VPN_ENABLED=false` to start with
   VPN disabled, or use the system-tray toggle on desktop builds
   (`src/tray.rs`, `src/main.rs`).

> The client subnet (`10.66.0.0/24`, gateway `.1`) and MTU (1400) are currently
> **hardcoded** in `vpn_handler.rs` — see the assumptions section.

---

## 5. Setup — the client (endpoint) side

The client is the `punchd-vpn` binary. Install the artifact for your OS, then
connect.

### Install

Grab the artifact from a [GitHub Release](../../releases) (built by
`.github/workflows/release.yml` from `bridges/punchd-bridge-rs`, all Rust):

| Artifact | OS | Notes |
|----------|-----|-------|
| `punchd-vpn.msi` | Windows | Native client with WebView2 DPoP login, system tray, auto-reconnect, optional Windows Service |
| `punchd-vpn-linux-deb` (`.deb`) | Linux | Built with webview feature |
| `punchd-vpn-macos-x64` / `-arm64` (`.tar.gz`) | macOS | Intel / Apple Silicon |

Or build it yourself (from [DEPLOYMENT.md](DEPLOYMENT.md) section 4):

```bash
cd bridges/punchd-bridge-rs
# Windows (WebView2 DPoP)
cargo build --release --target x86_64-pc-windows-gnu --features webview --bin punchd-vpn
# Linux / macOS
cargo build --release --bin punchd-vpn
```

### Connect

`punchd-vpn` is a CLI (`--help` lists everything). The core arguments
(`src/bin/punchd_vpn.rs`):

```bash
punchd-vpn \
  --stun-server wss://YOUR_SIGNAL_SERVER:9090 \
  --gateway-id office-gateway \
  --config /path/to/tidecloak.json
```

- `--stun-server` — the signal server WebSocket URL (remote/NAT traversal). Omit
  for a same-network gateway you can reach directly.
- `--gateway-id` — the `gateway_id` of the gateway you're connecting to.
- `--config` (or `--config-b64`) — the `tidecloak.json` for the OIDC login /
  JWT.
- On desktop MSI builds, login happens through the embedded WebView2 browser
  (the full TideCloak DPoP flow); on the CLI, `--standalone` runs a one-shot
  OIDC login + single connection, or pass `--token <access-token>` to skip login.

Once connected the gateway allocates you an IP (e.g. `10.66.0.2`), creates your
TUN adapter (default name `punchd-vpn0`), and installs routes for the gateway's
detected LAN subnets. Add `--default-route` to send **all** your traffic through
the VPN instead of only the gateway's LANs.

Other useful flags: `--ice-server` / `--turn-server` / `--turn-secret` (TURN
fallback), `--tun-name`, and on Windows `--install-service` / `--uninstall-service`.

By default `punchd-vpn` runs in **agent mode**: it exposes a small local control
API on `127.0.0.1:19877` (`GET /status`, `POST /connect`, `POST /disconnect`,
`GET /logs`) and can hold multiple gateway connections at once. Pass
`--standalone` for a single one-shot CLI connection instead.

---

## 6. Config / args reference (client)

Verified against `bridges/punchd-bridge-rs/src/bin/punchd_vpn.rs`. Most flags
also have a config-file equivalent (`VpnFileConfig`).

| Flag | Meaning |
|------|---------|
| `--stun-server <wss://…>` | Signal server WS URL (remote mode) |
| `--gateway-id <id>` | Target gateway's `gateway_id` |
| `--config <path>` / `--config-b64 <b64>` | `tidecloak.json` for login/JWT |
| `--ice-server <stun:host:3478>` | STUN server for ICE |
| `--turn-server <turn:host:3478>` / `--turn-secret <s>` | TURN relay fallback |
| `--tun-name <name>` | TUN device name (default `punchd-vpn0`) |
| `--default-route` | Route all traffic through the VPN (default: only gateway LANs) |
| `--standalone` | One-shot OIDC login + single connection (default is agent mode) |
| `--token <jwt>` | Use a pre-obtained access token, skip OIDC login |
| `--install-service` / `--uninstall-service` / `--service` | Windows Service management |

Gateway side (VPN-relevant): `QUIC_PORT`/`quic_port` (default `7893`),
`VPN_ENABLED` (default on). See [PUNCHD-GATEWAY.md](PUNCHD-GATEWAY.md) section 7
for the rest of the gateway config.

---

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Tunnel won't come up / no TUN device | On Linux/macOS run with privileges to create the TUN (`punchd-vpn0`); on Windows ensure the Wintun driver installed (the MSI handles it — a reboot may be required). |
| "access denied" / connection rejected right after login | Missing role. The user needs `vpn:<gatewayId>` in TideCloak (realm or client roles). Confirm the `<gatewayId>` matches the gateway's `gateway_id` exactly. |
| Connects but can't reach LAN hosts | Routes/firewall. Check the user's `vpn:<gw>:allow:…` roles actually cover the target `cidr`/ports; a `deny` rule may be winning on priority. With only `vpn:<gw>` all traffic is allowed — start there to isolate. |
| Can reach some hosts but not others | The gateway only advertises its **auto-detected** LAN subnets. For traffic outside those, use `--default-route` on the client. |
| Remote client never connects (strict NAT) | P2P couldn't form. Ensure `--stun-server` points at a live signal server and TURN is configured (`--turn-server` + `--turn-secret` matching the signal server), with `3478` + `49152-65535/udp` open. |
| Same-network client fails via signal server | Try direct mode: omit `--stun-server` and connect to a reachable gateway directly (offline mode, per DEPLOYMENT.md section 4). |
| Login window never appears (desktop) | WebView2 (Windows) not available — reinstall the MSI; or use the CLI `--standalone` / `--token` path. |
| Starts then quits without prompting, or won't reconnect and never asks for credentials | Build predating the stale-token fix: it reused the previous session's expired token and hid the login window. Upgrade; quitting from the tray was the old workaround. |

---

## 8. Assumptions and things to verify with your deployment

Grounded in the repo's code; these are deployment-specific or not fully pinnable
from source, so verify for your environment:

- **Not WireGuard-the-protocol.** The client uses a TUN adapter (the `tun`
  crate on Linux/macOS, WireGuard's **Wintun driver** on Windows), but the
  tunnel itself is a **custom IP-over-WebRTC/QUIC DataChannel**, not the
  WireGuard protocol. Don't expect `wg`/WireGuard-config interop.
- **Hardcoded VPN subnet/MTU/TUN name; IPv4 only.** The client subnet
  `10.66.0.0/24` (gateway `.1`), MTU 1400, and the gateway-side TUN name
  `punchd-vpn0` are hardcoded (`vpn_handler.rs` / `main.rs`) with no documented
  env/toml override. The tunnel is **IPv4 only**. Confirm before assuming you
  can re-address the VPN or carry IPv6.
- **Exact P2P vs relay path per platform.** The VPN rides the same
  WebRTC/QUIC + STUN/TURN machinery as the gateway; precise ICE/relay behavior
  per NAT type is environment-dependent (see [flow-diagram.md](flow-diagram.md)).
- **Live VPN endpoint.** Whether a real gateway/signal server is deployed for
  your users (and at what hostname) is not something the repo can tell you — the
  guide assumes you deploy your own gateway + (optionally) signal server.
- **`PunchdEndpoint` vs `punchd-vpn`.** `PunchdEndpoint.msi` bundles TideSSP +
  the gateway (an RDP endpoint that also runs a gateway). The VPN **client** is
  `punchd-vpn.msi`. If your users need the VPN, install `punchd-vpn`, not
  `PunchdEndpoint`. Confirm which artifact your rollout expects.
