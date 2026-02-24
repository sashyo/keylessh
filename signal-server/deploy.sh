#!/usr/bin/env bash
# Deploy the signal server + coturn Docker containers.
# Run on the VM: ./deploy.sh
#
# First run generates secrets and saves them to .env.
# Subsequent runs reuse existing secrets.
#
# Requires: docker, openssl, curl (for auto-detecting public IP)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
SIGNAL_CONTAINER="signal-server"
SIGNAL_IMAGE="keylessh-signal"
COTURN_CONTAINER="coturn"
COTURN_IMAGE="coturn/coturn:latest"
SIGNAL_PORT="${PORT:-9090}"

# ── Load or generate secrets ─────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  echo "[Deploy] Loading existing secrets from .env"
  source "$ENV_FILE"
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

  # Auto-detect tidecloak.json
  TIDECLOAK_CONFIG_B64=""
  for tc_candidate in \
    "${REPO_DIR}/data/tidecloak.json" \
    "${REPO_DIR}/bridges/punchd-bridge/gateway/data/tidecloak.json" \
    "${SCRIPT_DIR}/data/tidecloak.json"; do
    if [ -f "$tc_candidate" ]; then
      TIDECLOAK_CONFIG_B64=$(base64 -w0 < "$tc_candidate")
      echo "[Deploy] Auto-detected tidecloak.json: ${tc_candidate}"
      break
    fi
  done

  cat > "$ENV_FILE" <<EOF
API_SECRET=${API_SECRET}
TURN_SECRET=${TURN_SECRET}
EXTERNAL_IP=${EXTERNAL_IP}
TIDECLOAK_CONFIG_B64=${TIDECLOAK_CONFIG_B64}
EOF
  chmod 600 "$ENV_FILE"
  echo "[Deploy] Secrets saved to .env (chmod 600)"
  echo ""

  if [ -z "$TIDECLOAK_CONFIG_B64" ]; then
    echo "[Deploy] WARNING: No tidecloak.json found. Place it in ${REPO_DIR}/data/ and re-run,"
    echo "         or set TIDECLOAK_CONFIG_B64 in ${ENV_FILE}"
    echo ""
  fi

  source "$ENV_FILE"
fi

# ── Validate required values ─────────────────────────────────
EXTERNAL_IP="${EXTERNAL_IP:-}"
if [ -z "$EXTERNAL_IP" ] || [ "$EXTERNAL_IP" = "REPLACE_ME" ]; then
  echo "[Deploy] ERROR: EXTERNAL_IP not set. Edit ${ENV_FILE} and set your VM's public IP."
  exit 1
fi

if [ -z "${TIDECLOAK_CONFIG_B64:-}" ]; then
  echo "[Deploy] ERROR: TIDECLOAK_CONFIG_B64 not set. The signal server requires TideCloak config for JWT verification."
  echo "  Place tidecloak.json in ${REPO_DIR}/data/ and run: "
  echo "    echo \"TIDECLOAK_CONFIG_B64=\$(base64 -w0 < ${REPO_DIR}/data/tidecloak.json)\" >> ${ENV_FILE}"
  exit 1
fi

# ── Build signal server image ────────────────────────────────
echo "[Deploy] Building signal server image..."
docker build --network host -t "$SIGNAL_IMAGE" "$SCRIPT_DIR"

# ── Pull coturn ──────────────────────────────────────────────
echo "[Deploy] Pulling coturn image..."
docker pull "$COTURN_IMAGE"

# ── Stop old containers ──────────────────────────────────────
for cname in "$SIGNAL_CONTAINER" "$COTURN_CONTAINER"; do
  if docker ps -a --format '{{.Names}}' | grep -q "^${cname}$"; then
    echo "[Deploy] Stopping old container: ${cname}"
    docker rm -f "$cname" 2>/dev/null || true
  fi
done

# Kill any rogue process on the signal port (e.g. bare node, leaked container)
if command -v fuser &>/dev/null; then
  fuser -k "${SIGNAL_PORT}/tcp" 2>/dev/null || true
  sleep 1
fi

# ── TLS certs (optional — Let's Encrypt) ─────────────────────
TLS_ARGS=""
TLS_ENV=""
if [ -d "/etc/letsencrypt/live" ]; then
  CERT_DIR=$(ls -d /etc/letsencrypt/live/*/ 2>/dev/null | head -1)
  if [ -n "$CERT_DIR" ]; then
    DOMAIN=$(basename "$CERT_DIR")
    CERTS_DIR="${HOME}/certs"
    mkdir -p "$CERTS_DIR"
    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERTS_DIR/"
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERTS_DIR/"
    chmod 644 "$CERTS_DIR"/*.pem
    TLS_ARGS="-v ${CERTS_DIR}:/certs:ro"
    TLS_ENV="-e TLS_CERT_PATH=/certs/fullchain.pem -e TLS_KEY_PATH=/certs/privkey.pem"
    echo "[Deploy] TLS: ${DOMAIN}"
  fi
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
  --auth-secret-algorithm=sha256 \
  --fingerprint \
  --no-multicast-peers \
  --no-cli \
  --log-file=stdout \
  --verbose

echo "[Deploy] coturn started on port 3478 (external-ip=${EXTERNAL_IP})"

# ── Start signal server ──────────────────────────────────────
echo "[Deploy] Starting signal server..."
docker run -d \
  --network host \
  ${TLS_ARGS} \
  -e PORT="$SIGNAL_PORT" \
  -e TIDECLOAK_CONFIG_B64="${TIDECLOAK_CONFIG_B64}" \
  -e API_SECRET="${API_SECRET}" \
  -e ICE_SERVERS="stun:${EXTERNAL_IP}:3478" \
  -e TURN_SERVER="turn:${EXTERNAL_IP}:3478" \
  -e TURN_SECRET="${TURN_SECRET}" \
  ${TLS_ENV} \
  --name "$SIGNAL_CONTAINER" \
  --restart unless-stopped \
  "$SIGNAL_IMAGE"

echo "[Deploy] Waiting for containers to start..."
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

if docker ps --format '{{.Names}}' | grep -q "^${SIGNAL_CONTAINER}$"; then
  echo "[Deploy] signal-server: running"
  docker logs "$SIGNAL_CONTAINER" --tail 10
else
  echo "[Deploy] ERROR: signal-server failed to start"
  docker logs "$SIGNAL_CONTAINER" --tail 20 2>/dev/null || true
  FAILED=1
fi

# Determine scheme based on TLS
if [ -n "$TLS_ENV" ]; then
  SCHEME="https"
  WS_SCHEME="wss"
  HEALTH_URL="https://127.0.0.1:${SIGNAL_PORT}/health"
  # Use domain name if available, otherwise IP
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

# ── Generate test TURN credentials ──────────────────────────
if [ -n "${TURN_SECRET:-}" ]; then
  TURN_USER="$(date -d '+1 day' +%s 2>/dev/null || date -v+1d +%s):test"
  TURN_PASS=$(echo -n "$TURN_USER" | openssl dgst -sha256 -hmac "$TURN_SECRET" -binary | base64)
  sed -i '/^TURN_USER=/d; /^TURN_PASS=/d' "$ENV_FILE" 2>/dev/null || true
  echo "TURN_USER=${TURN_USER}" >> "$ENV_FILE"
  echo "TURN_PASS=${TURN_PASS}" >> "$ENV_FILE"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "============================================"
echo " KeyleSSH Signal Server deployed"
echo "============================================"
echo ""
echo "  Signal:    ${SCHEME}://${HOST}:${SIGNAL_PORT}"
echo "  Signaling: ${WS_SCHEME}://${HOST}:${SIGNAL_PORT}"
echo "  Health:    ${SCHEME}://${HOST}:${SIGNAL_PORT}/health"
echo "  STUN/TURN: ${EXTERNAL_IP}:3478"
echo ""
echo "  API_SECRET: set (use same value when starting gateways)"
echo ""
echo "To start a gateway pointing at this signal server:"
echo ""
echo "  cd bridges/punchd-bridge/gateway && \\"
echo "  STUN_SERVER_URL=${WS_SCHEME}://${HOST}:${SIGNAL_PORT} \\"
echo "  API_SECRET=${API_SECRET} \\"
echo "  ICE_SERVERS=stun:${EXTERNAL_IP}:3478 \\"
echo "  TURN_SERVER=turn:${EXTERNAL_IP}:3478 \\"
echo "  TURN_SECRET=${TURN_SECRET} \\"
echo "  TIDECLOAK_CONFIG_B64=${TIDECLOAK_CONFIG_B64} \\"
echo "  BACKENDS='MyApp=http://localhost:3000' \\"
echo "  npm start"
echo ""
echo "Firewall: open ports ${SIGNAL_PORT}/tcp, 3478/udp+tcp, 49152-65535/udp"
