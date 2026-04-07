#!/usr/bin/env bash
# Deploy the Rust signal server + coturn.
# Run on the VM: ./deploy.sh
#
# First run generates secrets and saves them to .env.
# Subsequent runs reuse existing secrets.
#
# Requires: docker (for coturn), cargo/rustc, openssl, curl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
# Also check the Node.js signal server .env for backward compat
NODE_ENV_FILE="${REPO_DIR}/signal-server/.env"
COTURN_CONTAINER="coturn"
COTURN_IMAGE="coturn/coturn:latest"
SIGNAL_PORT="${PORT:-9090}"
RELAY_PORT="${RELAY_PORT:-7893}"
SIGNAL_BIN="${SCRIPT_DIR}/target/release/signal-server-rs"
SIGNAL_PID_FILE="/tmp/signal-server-rs.pid"

# ── Load or generate secrets ─────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  echo "[Deploy] Loading existing secrets from .env"
  source "$ENV_FILE"
elif [ -f "$NODE_ENV_FILE" ]; then
  echo "[Deploy] Loading secrets from Node.js signal-server/.env"
  source "$NODE_ENV_FILE"
  # Copy to our .env
  cp "$NODE_ENV_FILE" "$ENV_FILE"
else
  echo "[Deploy] Generating new secrets..."
  API_SECRET=$(openssl rand -hex 32)
  TURN_SECRET=$(openssl rand -hex 32)

  # Auto-detect public IP
  EXTERNAL_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "")
  if [ -z "$EXTERNAL_IP" ]; then
    echo "[Deploy] WARNING: Could not detect public IP. Set EXTERNAL_IP in .env manually."
    EXTERNAL_IP="REPLACE_ME"
  else
    echo "[Deploy] Detected public IP: ${EXTERNAL_IP}"
  fi

  cat > "$ENV_FILE" <<EOF
API_SECRET=${API_SECRET}
TURN_SECRET=${TURN_SECRET}
EXTERNAL_IP=${EXTERNAL_IP}
EOF
  chmod 600 "$ENV_FILE"
  echo "[Deploy] Secrets saved to .env (chmod 600)"
fi

source "$ENV_FILE"

# ── Validate required values ─────────────────────────────────
EXTERNAL_IP="${EXTERNAL_IP:-}"
if [ -z "$EXTERNAL_IP" ] || [ "$EXTERNAL_IP" = "REPLACE_ME" ]; then
  echo "[Deploy] ERROR: EXTERNAL_IP not set. Edit ${ENV_FILE} and set your VM's public IP."
  exit 1
fi

# ── TLS certs (Let's Encrypt) ────────────────────────────────
TLS_CERT=""
TLS_KEY=""
if [ -d "/etc/letsencrypt/live" ]; then
  CERT_DIR=$(ls -d /etc/letsencrypt/live/*/ 2>/dev/null | head -1)
  if [ -n "$CERT_DIR" ]; then
    DOMAIN=$(basename "$CERT_DIR")
    CERTS_DIR="${HOME}/certs"
    mkdir -p "$CERTS_DIR"
    sudo cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERTS_DIR/"
    sudo cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERTS_DIR/"
    chmod 644 "$CERTS_DIR"/*.pem
    TLS_CERT="${CERTS_DIR}/fullchain.pem"
    TLS_KEY="${CERTS_DIR}/privkey.pem"
    echo "[Deploy] TLS: ${DOMAIN}"
  fi
fi

# ── Build signal server ──────────────────────────────────────
cd "$SCRIPT_DIR"
if [ -f "$SIGNAL_BIN" ] && command -v cargo &>/dev/null; then
  echo "[Deploy] Building Rust signal server..."
  cargo build --release 2>&1 | tail -3
elif command -v cargo &>/dev/null; then
  echo "[Deploy] Building Rust signal server..."
  cargo build --release 2>&1 | tail -3
else
  echo "[Deploy] cargo not found, skipping build — using existing binary"
fi

if [ ! -f "$SIGNAL_BIN" ]; then
  echo "[Deploy] ERROR: Binary not found at $SIGNAL_BIN"
  echo "  Build first with: cargo build --release"
  exit 1
fi

# ── Pull coturn ──────────────────────────────────────────────
echo "[Deploy] Pulling coturn image..."
docker pull "$COTURN_IMAGE" 2>&1 | tail -1

# ── Stop old processes ───────────────────────────────────────
# Stop old Node.js signal server (Docker)
if docker ps -a --format '{{.Names}}' | grep -q "^signal-server$"; then
  echo "[Deploy] Stopping old Node.js signal server..."
  docker rm -f signal-server 2>/dev/null || true
fi

# Stop old relay sidecar
pkill -f quic-relay 2>/dev/null || true

# Stop old Rust signal server
if [ -f "$SIGNAL_PID_FILE" ]; then
  OLD_PID=$(cat "$SIGNAL_PID_FILE")
  kill "$OLD_PID" 2>/dev/null || true
  rm -f "$SIGNAL_PID_FILE"
fi
pkill -f signal-server-rs 2>/dev/null || true

# Stop old coturn
if docker ps -a --format '{{.Names}}' | grep -q "^${COTURN_CONTAINER}$"; then
  echo "[Deploy] Stopping old coturn..."
  docker rm -f "$COTURN_CONTAINER" 2>/dev/null || true
fi

# Kill any rogue process on the signal port
if command -v fuser &>/dev/null; then
  fuser -k "${SIGNAL_PORT}/tcp" 2>/dev/null || true
  sleep 1
fi

# ── Start coturn ─────────────────────────────────────────────
echo "[Deploy] Starting coturn..."
docker run -d \
  --network host \
  --name "$COTURN_CONTAINER" \
  --restart unless-stopped \
  "$COTURN_IMAGE" \
  --listening-port=3478 \
  --external-ip="${EXTERNAL_IP}" \
  --use-auth-secret \
  --static-auth-secret="${TURN_SECRET}" \
  --realm=keylessh \
  --min-port=49152 \
  --max-port=65535 \
  --fingerprint \
  --no-multicast-peers \
  --no-cli \
  --log-file=stdout \
  --verbose

echo "[Deploy] coturn started on port 3478 (external-ip=${EXTERNAL_IP})"

# ── Start signal server ──────────────────────────────────────
echo "[Deploy] Starting Rust signal server..."

export PORT="$SIGNAL_PORT"
export API_SECRET="${API_SECRET}"
export ICE_SERVERS="stun:${EXTERNAL_IP}:3478"
export TURN_SERVER="turn:${EXTERNAL_IP}:3478"
export TURN_SECRET="${TURN_SECRET}"
export RELAY_PORT="${RELAY_PORT}"
export RELAY_HOST="${DOMAIN:-${EXTERNAL_IP}}"

if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  export TLS_CERT_PATH="$TLS_CERT"
  export TLS_KEY_PATH="$TLS_KEY"
fi

if [ -n "${TIDECLOAK_CONFIG_B64:-}" ]; then
  export TIDECLOAK_CONFIG_B64
fi

nohup "$SIGNAL_BIN" > /tmp/signal-server-rs.log 2>&1 &
echo $! > "$SIGNAL_PID_FILE"

echo "[Deploy] Waiting for server to start..."
sleep 3

# ── Verify ───────────────────────────────────────────────────
FAILED=0

if docker ps --format '{{.Names}}' | grep -q "^${COTURN_CONTAINER}$"; then
  echo "[Deploy] coturn: running"
else
  echo "[Deploy] ERROR: coturn failed to start"
  docker logs "$COTURN_CONTAINER" --tail 20 2>/dev/null || true
  FAILED=1
fi

if kill -0 "$(cat "$SIGNAL_PID_FILE" 2>/dev/null)" 2>/dev/null; then
  echo "[Deploy] signal-server-rs: running (PID $(cat "$SIGNAL_PID_FILE"))"
  tail -5 /tmp/signal-server-rs.log
else
  echo "[Deploy] ERROR: signal-server-rs failed to start"
  tail -20 /tmp/signal-server-rs.log
  FAILED=1
fi

# Determine scheme
if [ -n "$TLS_CERT" ]; then
  SCHEME="https"
  WS_SCHEME="wss"
  HEALTH_URL="https://127.0.0.1:${SIGNAL_PORT}/health"
  HOST="${DOMAIN:-${EXTERNAL_IP}}"
else
  SCHEME="http"
  WS_SCHEME="ws"
  HEALTH_URL="http://127.0.0.1:${SIGNAL_PORT}/health"
  HOST="${EXTERNAL_IP}"
fi

# Health check
if [ "$FAILED" -eq 0 ]; then
  echo ""
  HEALTH=$(curl -sk --max-time 3 "${HEALTH_URL}" 2>/dev/null || echo "")
  if [ -n "$HEALTH" ]; then
    echo "[Deploy] Health: ${HEALTH}"
  else
    echo "[Deploy] WARNING: Health check did not respond (may still be starting)"
  fi
fi

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "============================================"
echo " KeyleSSH Signal Server (Rust) deployed"
echo "============================================"
echo ""
echo "  Signal:    ${SCHEME}://${HOST}:${SIGNAL_PORT}"
echo "  Signaling: ${WS_SCHEME}://${HOST}:${SIGNAL_PORT}"
echo "  Health:    ${SCHEME}://${HOST}:${SIGNAL_PORT}/health"
echo "  Relay:     ${HOST}:${RELAY_PORT} (QUIC/WebTransport)"
echo "  STUN/TURN: ${EXTERNAL_IP}:3478"
echo ""
echo "  API_SECRET: set"
echo "  Binary: ${SIGNAL_BIN}"
echo "  Logs: /tmp/signal-server-rs.log"
echo ""
echo "Firewall: open ports ${SIGNAL_PORT}/tcp, ${RELAY_PORT}/udp, 3478/udp+tcp, 49152-65535/udp"
