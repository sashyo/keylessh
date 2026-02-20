#!/usr/bin/env bash
# Start the WAF for local development.
# Auto-detects TideCloak adapter config and prompts for secrets on first run.
#
# Usage:
#   ./start.sh                          # defaults (TideCloak on port 8080)
#   TC_PORT=8180 ./start.sh             # custom TideCloak port
#   API_SECRET=xxx TURN_SECRET=yyy ./start.sh  # override secrets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
TC_PORT="${TC_PORT:-8080}"

# ── Load or prompt for secrets ─────────────────────────────────
load_secrets() {
  # 1. Already set via environment
  if [ -n "${API_SECRET:-}" ] && [ -n "${TURN_SECRET:-}" ]; then
    echo "[WAF] Using secrets from environment"
    return
  fi

  # 2. Saved from previous run
  if [ -f "$ENV_FILE" ]; then
    echo "[WAF] Loading secrets from ${ENV_FILE}"
    source "$ENV_FILE"
    if [ -n "${API_SECRET:-}" ] && [ -n "${TURN_SECRET:-}" ]; then
      return
    fi
  fi

  # 3. From stun-server deploy
  local STUN_ENV="${REPO_ROOT}/stun-server/.env"
  if [ -f "$STUN_ENV" ]; then
    echo "[WAF] Loading secrets from stun-server/.env"
    eval "$(grep -E '^(API_SECRET|TURN_SECRET)=' "$STUN_ENV")"
    if [ -n "${API_SECRET:-}" ] && [ -n "${TURN_SECRET:-}" ]; then
      save_secrets
      return
    fi
  fi

  # 4. Prompt user
  echo ""
  echo "[WAF] Secrets not found. Paste them from your STUN server deploy output."
  echo "  (Run 'cat stun-server/.env' on your VM to find them)"
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
  echo "[WAF] Secrets saved to ${ENV_FILE}"
}

load_secrets
export API_SECRET="${API_SECRET:-}"
export TURN_SECRET="${TURN_SECRET:-}"

# ── Adapter config ──────────────────────────────────────────────
ADAPTER_CONFIG="${REPO_ROOT}/data/tidecloak.json"
if [ -f "$ADAPTER_CONFIG" ]; then
  echo "[WAF] Adapter config: ${ADAPTER_CONFIG}"
  export TIDECLOAK_CONFIG_PATH="$ADAPTER_CONFIG"
else
  echo "[WAF] WARN: No adapter config at ${ADAPTER_CONFIG}"
  echo "  Run script/tidecloak/start.sh first to initialize TideCloak."
fi

# ── WAF configuration ──────────────────────────────────────────
export STUN_SERVER_URL="${STUN_SERVER_URL:-wss://tidestun.codesyo.com:9090}"
export ICE_SERVERS="${ICE_SERVERS:-stun:20.211.145.216:3478}"
export BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
export BACKENDS="${BACKENDS:-}"
export LISTEN_PORT="${LISTEN_PORT:-7891}"
export HEALTH_PORT="${HEALTH_PORT:-7892}"
export TURN_SERVER="${TURN_SERVER:-turn:20.211.145.216:3478}"

echo "[WAF] Starting with:"
echo "  STUN_SERVER_URL=$STUN_SERVER_URL"
echo "  BACKEND_URL=$BACKEND_URL"
echo "  BACKENDS=${BACKENDS:-<from BACKEND_URL>}"
echo "  LISTEN_PORT=$LISTEN_PORT"
echo "  API_SECRET=${API_SECRET:+set}"
echo "  TURN_SECRET=${TURN_SECRET:+set}"

# ── Build and start ─────────────────────────────────────────────
cd "${REPO_ROOT}/waf"
npm run build
exec npm start
