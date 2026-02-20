#!/usr/bin/env bash
# Deploy the STUN server Docker container.
# Run on the VM: ./deploy.sh
#
# First run generates secrets and saves them to .env.
# Subsequent runs reuse existing secrets.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
CONTAINER_NAME="stun-server"
IMAGE_NAME="keylessh-stun"

# ── Load or generate secrets ─────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  echo "[Deploy] Loading existing secrets from .env"
  source "$ENV_FILE"
else
  echo "[Deploy] Generating new secrets..."
  API_SECRET=$(openssl rand -hex 32)
  TURN_SECRET=$(openssl rand -hex 32)
  # Auto-detect tidecloak.json
  TC_JSON="${SCRIPT_DIR}/../waf/data/tidecloak.json"
  if [ -f "$TC_JSON" ]; then
    TIDECLOAK_CONFIG_B64=$(base64 -w0 < "$TC_JSON")
    echo "[Deploy] Auto-detected tidecloak.json"
  fi
  cat > "$ENV_FILE" <<EOF
API_SECRET=${API_SECRET}
TURN_SECRET=${TURN_SECRET}
EXTERNAL_IP=${EXTERNAL_IP:-20.211.145.216}
TIDECLOAK_CONFIG_B64=${TIDECLOAK_CONFIG_B64:-}
EOF
  chmod 600 "$ENV_FILE"
  echo "[Deploy] Secrets saved to .env"
  echo "[Deploy] API_SECRET=${API_SECRET}"
  echo "[Deploy] TURN_SECRET=${TURN_SECRET}"
  echo ""
  echo "[Deploy] IMPORTANT: Copy API_SECRET to your WAF's start.sh or env vars."
  echo "[Deploy] To set TIDECLOAK_CONFIG_B64, run:"
  echo "  echo 'TIDECLOAK_CONFIG_B64='\"$(base64 -w0 < ../waf/data/tidecloak.json)\" >> ${ENV_FILE}"
  echo ""
  source "$ENV_FILE"
fi

# ── Required values ──────────────────────────────────────────
EXTERNAL_IP="${EXTERNAL_IP:-20.211.145.216}"
SIGNAL_PORT="${SIGNAL_PORT:-9090}"
STUN_PORT="${STUN_PORT:-3478}"
REALM="${REALM:-keylessh}"

# ── Build ────────────────────────────────────────────────────
echo "[Deploy] Building Docker image..."
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

# ── Stop old container ───────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "[Deploy] Stopping old container..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# ── TLS certs ────────────────────────────────────────────────
TLS_ARGS=""
TLS_ENV=""
if [ -d "/etc/letsencrypt/live" ]; then
  # Find the first cert directory
  CERT_DIR=$(ls -d /etc/letsencrypt/live/*/ 2>/dev/null | head -1)
  if [ -n "$CERT_DIR" ]; then
    DOMAIN=$(basename "$CERT_DIR")
    # Copy certs to accessible location
    mkdir -p /home/azureuser/certs
    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /home/azureuser/certs/
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" /home/azureuser/certs/
    chmod 644 /home/azureuser/certs/*.pem
    TLS_ARGS="-v /home/azureuser/certs:/certs:ro"
    TLS_ENV="-e TLS_CERT_PATH=/certs/fullchain.pem -e TLS_KEY_PATH=/certs/privkey.pem"
    echo "[Deploy] TLS: ${DOMAIN}"
  fi
fi

# ── Run ──────────────────────────────────────────────────────
echo "[Deploy] Starting container..."
docker run -d \
  --network host \
  ${TLS_ARGS} \
  -e SIGNAL_PORT="$SIGNAL_PORT" \
  -e STUN_PORT="$STUN_PORT" \
  -e EXTERNAL_IP="$EXTERNAL_IP" \
  -e REALM="$REALM" \
  -e API_SECRET="${API_SECRET:-}" \
  -e TURN_SECRET="${TURN_SECRET:-}" \
  -e TIDECLOAK_CONFIG_B64="${TIDECLOAK_CONFIG_B64:-}" \
  ${TLS_ENV} \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  "$IMAGE_NAME"

echo "[Deploy] Waiting for health check..."
sleep 2

# ── Verify ───────────────────────────────────────────────────
if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "[Deploy] Container running. Logs:"
  docker logs "$CONTAINER_NAME" --tail 15
  echo ""
  echo "[Deploy] Done!"
  echo "[Deploy] API_SECRET=${API_SECRET:+set (use same value in WAF)}"
  echo "[Deploy] TURN_SECRET=${TURN_SECRET:+set}"
  echo "[Deploy] Admin auth: ${TIDECLOAK_CONFIG_B64:+enabled}${TIDECLOAK_CONFIG_B64:-disabled (set TIDECLOAK_CONFIG_B64 in .env)}"
else
  echo "[Deploy] ERROR: Container failed to start"
  docker logs "$CONTAINER_NAME" --tail 20
  exit 1
fi
