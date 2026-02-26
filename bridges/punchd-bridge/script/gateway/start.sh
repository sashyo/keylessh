#!/usr/bin/env bash
# Start the gateway for local development.
# Prompts for secrets on first run and saves them for next time.
#
# The STUN server operator generates API_SECRET and TURN_SECRET.
# Get them from whoever runs the STUN server you're connecting to.
#
# Usage:
#   ./start.sh                                    # prompts for secrets on first run
#   API_SECRET=xxx TURN_SECRET=yyy ./start.sh     # pass secrets directly
#   STUN_SERVER_URL=wss://stun:9090 ./start.sh    # custom STUN server

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
TC_PORT="${TC_PORT:-8080}"

# ── Load or prompt for secrets ─────────────────────────────────
load_secrets() {
  # 1. Already set via environment
  if [ -n "${API_SECRET:-}" ] && [ -n "${TURN_SECRET:-}" ]; then
    echo "[Gateway] Using secrets from environment"
    return
  fi

  # 2. Saved from previous run
  if [ -f "$ENV_FILE" ]; then
    echo "[Gateway] Loading secrets from ${ENV_FILE}"
    source "$ENV_FILE"
    if [ -n "${API_SECRET:-}" ] && [ -n "${TURN_SECRET:-}" ]; then
      return
    fi
  fi

  # 3. Prompt — get these from whoever runs the STUN server
  echo ""
  echo "[Gateway] Secrets not found."
  echo "  Get API_SECRET and TURN_SECRET from the STUN server operator."
  echo ""
  read -rp "  API_SECRET: " API_SECRET
  read -rp "  TURN_SECRET: " TURN_SECRET
  echo ""
  save_secrets
}

save_secrets() {
  cat > "$ENV_FILE" <<EOF
API_SECRET=${API_SECRET}
TURN_SECRET=${TURN_SECRET}
EOF
  chmod 600 "$ENV_FILE"
  echo "[Gateway] Secrets saved to ${ENV_FILE}"
}

load_secrets
export API_SECRET="${API_SECRET:-}"
export TURN_SECRET="${TURN_SECRET:-}"

# ── Adapter config ──────────────────────────────────────────────
# Check gateway/data first, then root data/
ADAPTER_CONFIG="${REPO_ROOT}/gateway/data/tidecloak.json"
if [ ! -f "$ADAPTER_CONFIG" ]; then
  ADAPTER_CONFIG="${REPO_ROOT}/data/tidecloak.json"
fi
if [ -f "$ADAPTER_CONFIG" ]; then
  echo "[Gateway] Adapter config: ${ADAPTER_CONFIG}"
  export TIDECLOAK_CONFIG_PATH="$ADAPTER_CONFIG"
else
  echo "[Gateway] WARN: No adapter config found"
  echo "  Run script/tidecloak/start.sh first to initialize TideCloak."
fi

# ── Gateway configuration ──────────────────────────────────────
export STUN_SERVER_URL="${STUN_SERVER_URL:-wss://tidestun.codesyo.com:9090}"
export ICE_SERVERS="${ICE_SERVERS:-stun:20.211.145.216:3478}"
export BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
export BACKENDS="${BACKENDS:-}"
export LISTEN_PORT="${LISTEN_PORT:-7891}"
export HEALTH_PORT="${HEALTH_PORT:-7892}"
export TURN_SERVER="${TURN_SERVER:-turn:20.211.145.216:3478}"

echo "[Gateway] Starting with:"
echo "  STUN_SERVER_URL=$STUN_SERVER_URL"
echo "  BACKEND_URL=$BACKEND_URL"
echo "  BACKENDS=${BACKENDS:-<from BACKEND_URL>}"
echo "  LISTEN_PORT=$LISTEN_PORT"
echo "  API_SECRET=${API_SECRET:+set}"
echo "  TURN_SECRET=${TURN_SECRET:+set}"

# ── Install, build and start ──────────────────────────────────────
cd "${REPO_ROOT}/gateway"
npm install
npm run build
exec npm start
