#!/usr/bin/env bash
# TideCloak admin helper — interactive admin session.
#
# Temporarily restarts TideCloak with KC_HOSTNAME=localhost so the admin
# console works natively (no proxy issues). When you're done, it restarts
# with the public KC_HOSTNAME and re-signs IdP settings.
#
# Usage:
#   ./admin.sh            # interactive admin session (localhost → public)
#   ./admin.sh --resign   # just re-sign IdP settings (no admin session)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
TC_PORT="${TC_PORT:-8080}"
TC_CONTAINER="${TC_CONTAINER:-mytidecloak}"
REALM_NAME="${NEW_REALM_NAME:-keylessh}"
CLIENT_NAME="${CLIENT_NAME:-myclient}"
STUN_SERVER_URL="${STUN_SERVER_URL:-wss://tidestun.codesyo.com:9090}"
TC_PUBLIC_URL="${TC_PUBLIC_URL:-$(echo "$STUN_SERVER_URL" | sed 's|^wss://|https://|;s|^ws://|http://|;s|:[0-9]*$||')}"

wait_for_tc() {
  echo -n "  Waiting for TideCloak..."
  for i in $(seq 1 30); do
    if curl -s -f --connect-timeout 3 "http://localhost:${TC_PORT}" > /dev/null 2>&1; then
      echo " ready"
      return
    fi
    echo -n "."
    sleep 3
  done
  echo " timeout!"
  exit 1
}

get_admin_token() {
  curl -s -f -X POST "http://localhost:${TC_PORT}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin" -d "password=password" \
    -d "grant_type=password" -d "client_id=admin-cli" | jq -r '.access_token'
}

restart_tc() {
  local kc_hostname="$1"
  docker rm -f "$TC_CONTAINER" > /dev/null 2>&1 || true
  docker run \
    --name "$TC_CONTAINER" \
    -d \
    -v "${REPO_ROOT}/script/tidecloak":/opt/keycloak/data/h2 \
    -p "${TC_PORT}:8080" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=password \
    -e "KC_HOSTNAME=${kc_hostname}" \
    -e SYSTEM_HOME_ORK=https://sork1.tideprotocol.com \
    -e USER_HOME_ORK=https://sork1.tideprotocol.com \
    -e THRESHOLD_T=3 \
    -e THRESHOLD_N=5 \
    -e PAYER_PUBLIC=20000011d6a0e8212d682657147d864b82d10e92776c15ead43dcfdc100ebf4dcfe6a8 \
    tideorg/tidecloak-stg-dev:latest
  wait_for_tc
}

resign_idp_settings() {
  echo "  Signing IdP settings..."
  local token
  token="$(get_admin_token)"
  curl -s -f -X POST "http://localhost:${TC_PORT}/admin/realms/${REALM_NAME}/vendorResources/sign-idp-settings" \
    -H "Authorization: Bearer $token" > /dev/null 2>&1
  echo "  IdP settings signed with current KC_HOSTNAME"
}

# ── --resign: just re-sign without interactive session ──────────
if [ "${1:-}" = "--resign" ]; then
  echo "[Admin] Re-signing IdP settings with public URL: ${TC_PUBLIC_URL}"
  echo ""

  echo "  Step 1/2: Restarting TideCloak with KC_HOSTNAME=${TC_PUBLIC_URL}"
  restart_tc "$TC_PUBLIC_URL"

  echo "  Step 2/2: Signing IdP settings..."
  resign_idp_settings

  echo ""
  echo "Done! IdP settings signed with ${TC_PUBLIC_URL}."
  echo "Restart the gateway to pick up the new KC_HOSTNAME."
  exit 0
fi

# ── Interactive admin session ───────────────────────────────────
echo ""
echo "=== TideCloak Admin Session ==="
echo ""
echo "This will:"
echo "  1. Restart TideCloak with KC_HOSTNAME=localhost (admin console works)"
echo "  2. Wait for you to do admin work"
echo "  3. Restart with KC_HOSTNAME=${TC_PUBLIC_URL} (for Tide SDK)"
echo "  4. Re-sign IdP settings"
echo ""
read -rp "Press Enter to start (Ctrl+C to cancel)..."

# Step 1: Restart with localhost
echo ""
echo "[Step 1/4] Restarting TideCloak with KC_HOSTNAME=http://localhost:${TC_PORT}"
restart_tc "http://localhost:${TC_PORT}"

echo ""
echo "============================================"
echo "  Admin Console Ready!"
echo ""
echo "  URL:   http://localhost:${TC_PORT}/admin/master/console/"
echo "  Login: admin / password"
echo "  Realm: ${REALM_NAME}"
echo ""
echo "  Do your admin work now (create token drafts, etc.)"
echo "============================================"
echo ""
read -rp "Press Enter when done with admin work..."

# Step 2: Restart with public URL
echo ""
echo "[Step 2/4] Restarting TideCloak with KC_HOSTNAME=${TC_PUBLIC_URL}"
restart_tc "$TC_PUBLIC_URL"

# Step 3: Re-sign IdP settings
echo "[Step 3/4] Re-signing IdP settings with public URL"
resign_idp_settings

# Step 4: Done
echo ""
echo "[Step 4/4] Done!"
echo ""
echo "  KC_HOSTNAME is now: ${TC_PUBLIC_URL}"
echo "  IdP settings signed with public URL."
echo "  Restart the gateway to resume normal operation."
echo ""
