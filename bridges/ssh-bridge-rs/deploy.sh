#!/usr/bin/env bash
# Deploy the SSH bridge as a Docker container.
# Run on the target VM: ./deploy.sh
#
# First run auto-detects tidecloak.json and saves config to .env.
# Subsequent runs reuse existing config.
#
# Requires: docker, base64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
CONTAINER_NAME="ssh-bridge"
IMAGE_NAME="keylessh-ssh-bridge"
BRIDGE_PORT="${PORT:-8088}"

# ── Load or generate config ─────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  echo "[Deploy] Loading config from .env"
  source "$ENV_FILE"
else
  echo "[Deploy] First run — generating config..."

  # Auto-detect tidecloak.json
  TIDECLOAK_CONFIG_B64=""
  for tc_candidate in \
    "${REPO_DIR}/data/tidecloak.json" \
    "${SCRIPT_DIR}/data/tidecloak.json" \
    "${REPO_DIR}/bridges/punchd-bridge/gateway/data/tidecloak.json"; do
    if [ -f "$tc_candidate" ]; then
      TIDECLOAK_CONFIG_B64=$(base64 -w0 < "$tc_candidate")
      echo "[Deploy] Auto-detected tidecloak.json: ${tc_candidate}"
      break
    fi
  done

  cat > "$ENV_FILE" <<EOF
PORT=${BRIDGE_PORT}
TIDECLOAK_CONFIG_B64=${TIDECLOAK_CONFIG_B64}
EOF
  chmod 600 "$ENV_FILE"
  echo "[Deploy] Config saved to .env (chmod 600)"
  echo ""

  if [ -z "$TIDECLOAK_CONFIG_B64" ]; then
    echo "[Deploy] WARNING: No tidecloak.json found."
    echo "  Place it in ${REPO_DIR}/data/ and re-run, or set TIDECLOAK_CONFIG_B64 in ${ENV_FILE}"
    echo ""
  fi

  source "$ENV_FILE"
fi

# ── Validate ─────────────────────────────────────────────────
BRIDGE_PORT="${PORT:-8088}"

if [ -z "${TIDECLOAK_CONFIG_B64:-}" ]; then
  echo "[Deploy] ERROR: TIDECLOAK_CONFIG_B64 not set. The SSH bridge requires TideCloak config for JWT verification."
  echo "  Place tidecloak.json in ${REPO_DIR}/data/ and run:"
  echo "    echo \"TIDECLOAK_CONFIG_B64=\$(base64 -w0 < ${REPO_DIR}/data/tidecloak.json)\" >> ${ENV_FILE}"
  exit 1
fi

# ── Build image ──────────────────────────────────────────────
echo "[Deploy] Building SSH bridge image..."
docker build --network host -t "$IMAGE_NAME" "$SCRIPT_DIR"

# ── Stop old container ───────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "[Deploy] Stopping old container: ${CONTAINER_NAME}"
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
fi

# ── Start container ──────────────────────────────────────────
echo "[Deploy] Starting SSH bridge on port ${BRIDGE_PORT}..."
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${BRIDGE_PORT}:8080" \
  -e TIDECLOAK_CONFIG_B64="${TIDECLOAK_CONFIG_B64}" \
  "$IMAGE_NAME"

echo "[Deploy] Waiting for container to start..."
sleep 2

# ── Verify ───────────────────────────────────────────────────
if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "[Deploy] ssh-bridge: running"
else
  echo "[Deploy] ERROR: ssh-bridge failed to start"
  docker logs "$CONTAINER_NAME" --tail 20 2>/dev/null || true
  exit 1
fi

# Health check
HEALTH=$(curl -s --max-time 3 "http://127.0.0.1:${BRIDGE_PORT}/health" 2>/dev/null || echo "")
if [ -n "$HEALTH" ]; then
  echo "[Deploy] Health: ${HEALTH}"
else
  echo "[Deploy] WARNING: Health check did not respond (may still be starting)"
fi

# ── Summary ──────────────────────────────────────────────────
EXTERNAL_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "============================================"
echo " KeyleSSH SSH Bridge deployed"
echo "============================================"
echo ""
echo "  Bridge:  http://${EXTERNAL_IP}:${BRIDGE_PORT}"
echo "  Health:  http://${EXTERNAL_IP}:${BRIDGE_PORT}/health"
echo "  Logs:    http://${EXTERNAL_IP}:${BRIDGE_PORT}/logs"
echo ""
echo "Add this to your main server environment:"
echo "  BRIDGE_URL=wss://${EXTERNAL_IP}:${BRIDGE_PORT}"
echo ""
echo "Firewall: open port ${BRIDGE_PORT}/tcp"
