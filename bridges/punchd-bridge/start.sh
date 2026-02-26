#!/usr/bin/env bash
# Start Punc'd for local development.
#
# On first run:
#   1. Starts TideCloak (Docker) and initializes a realm (localhost)
#   2. Restarts TideCloak with public hostname so Tide SDK works remotely
#   3. Re-signs IdP settings + re-fetches adapter config
#   4. Prompts for STUN server secrets (API_SECRET + TURN_SECRET)
#   5. Installs deps, builds, and starts the gateway
#
# On subsequent runs, TideCloak and secrets are reused automatically.
#
# Usage:
#   ./start.sh                                    # full setup
#   ./start.sh --skip-tc                          # skip TideCloak, gateway only
#   API_SECRET=xxx TURN_SECRET=yyy ./start.sh     # pass secrets directly
#   STUN_SERVER_URL=wss://stun:9090 ./start.sh    # custom STUN server

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${REPO_ROOT}/script/gateway/.env"
TC_PORT="${TC_PORT:-8080}"
TC_CONTAINER="${TC_CONTAINER:-mytidecloak}"
SKIP_TC="${1:-}"
REALM_NAME="${NEW_REALM_NAME:-keylessh}"
CLIENT_NAME="${CLIENT_NAME:-myclient}"

# Resolve STUN server URL early
STUN_SERVER_URL="${STUN_SERVER_URL:-wss://tidestun.codesyo.com:9090}"

# Derive public URL from STUN server URL:
# wss://tidestun.codesyo.com:9090 → https://tidestun.codesyo.com
TC_PUBLIC_URL="${TC_PUBLIC_URL:-$(echo "$STUN_SERVER_URL" | sed 's|^wss://|https://|;s|^ws://|http://|;s|:[0-9]*$||')}"

# ── Adapter config paths ────────────────────────────────────────
ADAPTER_CONFIG="${REPO_ROOT}/gateway/data/tidecloak.json"
if [ ! -f "$ADAPTER_CONFIG" ]; then
  ADAPTER_CONFIG="${REPO_ROOT}/data/tidecloak.json"
fi

# ── TideCloak ───────────────────────────────────────────────────
start_tidecloak() {
  if [ "$SKIP_TC" = "--skip-tc" ]; then
    echo "[TideCloak] Skipped (--skip-tc)"
    return
  fi

  # Already have adapter config — just make sure container is running
  if [ -f "$ADAPTER_CONFIG" ]; then
    if docker ps --format '{{.Names}}' | grep -q "^${TC_CONTAINER}$"; then
      echo "[TideCloak] Already running on port ${TC_PORT}"
      patch_admin_console_redirects
      return
    fi
    echo "[TideCloak] Adapter config exists — starting container with public URL"
    start_tc_container "$TC_PUBLIC_URL"
    wait_for_tc
    patch_admin_console_redirects
    return
  fi

  # First run — two-phase startup
  echo "[TideCloak] No adapter config found — running full setup"

  # Phase 1: Init with localhost (so invite link works in local browser)
  start_tc_container "http://localhost:${TC_PORT}"
  init_tc_realm

  # Phase 2: Restart with public URL so Tide SDK/enclave uses reachable URLs
  echo ""
  echo "[TideCloak] Restarting with public hostname: ${TC_PUBLIC_URL}"
  start_tc_container "$TC_PUBLIC_URL"
  wait_for_tc

  # Re-sign IdP settings so ork registration gets the public URL
  resign_idp_settings

  # Re-fetch adapter config (now has public URL as auth-server-url)
  refetch_adapter_config

  # Patch admin console so gateway-proxied login works
  patch_admin_console_redirects
}

start_tc_container() {
  local kc_hostname="${1:-http://localhost:${TC_PORT}}"

  # Stop existing container if present
  if docker ps -a --format '{{.Names}}' | grep -q "^${TC_CONTAINER}$"; then
    echo "[TideCloak] Stopping existing container..."
    docker rm -f "$TC_CONTAINER" > /dev/null 2>&1 || true
  fi

  # Check port is free
  if ss -tlnp 2>/dev/null | grep -q ":${TC_PORT} "; then
    echo "[TideCloak] ERROR: Port ${TC_PORT} is already in use"
    echo "  Use a different port: TC_PORT=8180 ./start.sh"
    exit 1
  fi

  echo "[TideCloak] Starting on port ${TC_PORT} (KC_HOSTNAME=${kc_hostname})..."
  docker run \
    --name "$TC_CONTAINER" \
    -d \
    -v "${REPO_ROOT}/script/tidecloak":/opt/keycloak/data/h2 \
    -p "${TC_PORT}:8080" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=password \
    -e "KC_HOSTNAME=${kc_hostname}" \
    -e "KC_HOSTNAME_ADMIN=http://localhost:${TC_PORT}" \
    -e SYSTEM_HOME_ORK=https://sork1.tideprotocol.com \
    -e USER_HOME_ORK=https://sork1.tideprotocol.com \
    -e THRESHOLD_T=3 \
    -e THRESHOLD_N=5 \
    -e PAYER_PUBLIC=20000011d6a0e8212d682657147d864b82d10e92776c15ead43dcfdc100ebf4dcfe6a8 \
    tideorg/tidecloak-stg-dev:latest

  echo "[TideCloak] Container '${TC_CONTAINER}' started on port ${TC_PORT}"
}

wait_for_tc() {
  echo -n "[TideCloak] Waiting for TideCloak to be ready..."
  for i in $(seq 1 30); do
    if curl -s -f --connect-timeout 3 "http://localhost:${TC_PORT}" > /dev/null 2>&1; then
      echo " ready"
      return
    fi
    echo -n "."
    sleep 3
  done
  echo " timeout!"
  echo "[TideCloak] ERROR: TideCloak did not start in time"
  exit 1
}

get_admin_token() {
  curl -s -f -X POST "http://localhost:${TC_PORT}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin" -d "password=password" \
    -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token'
}

resign_idp_settings() {
  echo "[TideCloak] Re-signing IdP settings with public URL..."
  local token
  token="$(get_admin_token)"

  curl -s -f -X POST "http://localhost:${TC_PORT}/admin/realms/${REALM_NAME}/vendorResources/sign-idp-settings" \
    -H "Authorization: Bearer $token" > /dev/null 2>&1

  echo "[TideCloak] IdP settings re-signed"
}

refetch_adapter_config() {
  echo "[TideCloak] Re-fetching adapter config with public URL..."
  local token
  token="$(get_admin_token)"

  local client_uuid
  client_uuid=$(curl -s -f -X GET "http://localhost:${TC_PORT}/admin/realms/${REALM_NAME}/clients?clientId=${CLIENT_NAME}" \
    -H "Authorization: Bearer $token" | jq -r '.[0].id')

  mkdir -p "$(dirname "$ADAPTER_CONFIG")"
  curl -s -f -X GET "http://localhost:${TC_PORT}/admin/realms/${REALM_NAME}/vendorResources/get-installations-provider?clientId=${client_uuid}&providerId=keycloak-oidc-keycloak-json" \
    -H "Authorization: Bearer $token" > "$ADAPTER_CONFIG"

  echo "[TideCloak] Adapter config updated: $ADAPTER_CONFIG"
}

patch_admin_console_redirects() {
  echo "[TideCloak] Patching admin console redirect URIs..."
  local token
  token="$(get_admin_token)" || return

  local client_uuid
  client_uuid=$(curl -s -f "http://localhost:${TC_PORT}/admin/realms/master/clients?clientId=security-admin-console" \
    -H "Authorization: Bearer $token" | jq -r '.[0].id')
  [ -z "$client_uuid" ] || [ "$client_uuid" = "null" ] && return

  local gw_port="${LISTEN_PORT:-7891}"
  local existing
  existing=$(curl -s -f "http://localhost:${TC_PORT}/admin/realms/master/clients/$client_uuid" \
    -H "Authorization: Bearer $token")

  local updated
  updated=$(echo "$existing" | jq \
    --arg gw_uri "https://localhost:${gw_port}/*" \
    --arg gw_origin "https://localhost:${gw_port}" \
    --arg pub_uri "${TC_PUBLIC_URL}/*" \
    --arg pub_origin "${TC_PUBLIC_URL}" \
    '.redirectUris += [$gw_uri, $pub_uri] | .webOrigins += [$gw_origin, $pub_origin] | .redirectUris |= unique | .webOrigins |= unique')

  curl -s -f -X PUT "http://localhost:${TC_PORT}/admin/realms/master/clients/$client_uuid" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "$updated" > /dev/null 2>&1

  echo "[TideCloak] Admin console redirect URIs patched (Gateway :${gw_port})"
}

init_tc_realm() {
  export TIDECLOAK_LOCAL_URL="http://localhost:${TC_PORT}"
  mkdir -p "${REPO_ROOT}/data"
  cd "${REPO_ROOT}/script/tidecloak"
  bash ./init-tidecloak.sh
  cd "$REPO_ROOT"
  # Re-resolve adapter config path after init creates it
  ADAPTER_CONFIG="${REPO_ROOT}/data/tidecloak.json"
}

start_tidecloak

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
  mkdir -p "$(dirname "$ENV_FILE")"
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
if [ -f "$ADAPTER_CONFIG" ]; then
  echo "[Gateway] Adapter config: ${ADAPTER_CONFIG}"
  export TIDECLOAK_CONFIG_PATH="$ADAPTER_CONFIG"
else
  echo "[Gateway] WARN: No adapter config found"
  echo "  Run again without --skip-tc to initialize TideCloak."
fi

# ── Gateway configuration ──────────────────────────────────────
export STUN_SERVER_URL="${STUN_SERVER_URL:-wss://tidestun.codesyo.com:9090}"
export ICE_SERVERS="${ICE_SERVERS:-stun:20.211.145.216:3478}"
export BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
export BACKENDS="${BACKENDS:-}"
export LISTEN_PORT="${LISTEN_PORT:-7891}"
export HEALTH_PORT="${HEALTH_PORT:-7892}"
export TURN_SERVER="${TURN_SERVER:-turn:20.211.145.216:3478}"
# Internal TideCloak URL for proxying (KC_HOSTNAME is now public)
export TC_INTERNAL_URL="${TC_INTERNAL_URL:-http://localhost:${TC_PORT}}"

echo ""
echo "[Gateway] Starting with:"
echo "  STUN_SERVER_URL=$STUN_SERVER_URL"
echo "  TC_PUBLIC_URL=$TC_PUBLIC_URL"
echo "  TC_INTERNAL_URL=$TC_INTERNAL_URL"
echo "  BACKEND_URL=$BACKEND_URL"
echo "  BACKENDS=${BACKENDS:-<from BACKEND_URL>}"
echo "  LISTEN_PORT=$LISTEN_PORT"
echo "  API_SECRET=${API_SECRET:+set}"
echo "  TURN_SECRET=${TURN_SECRET:+set}"

# ── Install, build and start gateway ────────────────────────────
cd "${REPO_ROOT}/gateway"
npm install
npm run build
exec npm start
