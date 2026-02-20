#!/usr/bin/env bash
# Start TideCloak and initialize a realm.
# Configurable port to avoid conflicts (default: 8080).
#
# Usage:
#   ./start.sh                     # port 8080
#   TC_PORT=8180 ./start.sh        # port 8180
#   ./start.sh --skip-init         # start only, no realm init

set -euo pipefail

TC_PORT="${TC_PORT:-8080}"
TC_CONTAINER="${TC_CONTAINER:-mytidecloak}"
SKIP_INIT="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Stop existing container if running ────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q "^${TC_CONTAINER}$"; then
  echo "[TideCloak] Stopping existing container..."
  docker rm -f "$TC_CONTAINER" > /dev/null 2>&1 || true
fi

# ── Check port is free ────────────────────────────────────────
if ss -tlnp 2>/dev/null | grep -q ":${TC_PORT} "; then
  echo "[TideCloak] ERROR: Port ${TC_PORT} is already in use"
  echo "  Use a different port: TC_PORT=8180 ./start.sh"
  exit 1
fi

# ── Start TideCloak ──────────────────────────────────────────
echo "[TideCloak] Starting on port ${TC_PORT}..."
docker run \
  --name "$TC_CONTAINER" \
  -d \
  -v "${SCRIPT_DIR}":/opt/keycloak/data/h2 \
  -p "${TC_PORT}:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=password \
  -e "KC_HOSTNAME=http://localhost:${TC_PORT}" \
  -e SYSTEM_HOME_ORK=https://sork1.tideprotocol.com \
  -e USER_HOME_ORK=https://sork1.tideprotocol.com \
  -e THRESHOLD_T=3 \
  -e THRESHOLD_N=5 \
  -e PAYER_PUBLIC=20000011d6a0e8212d682657147d864b82d10e92776c15ead43dcfdc100ebf4dcfe6a8 \
  tideorg/tidecloak-stg-dev:latest

echo "[TideCloak] Container '${TC_CONTAINER}' started on port ${TC_PORT}"

# ── Initialize realm ─────────────────────────────────────────
if [ "$SKIP_INIT" = "--skip-init" ]; then
  echo "[TideCloak] Skipping initialization (--skip-init)"
else
  export TIDECLOAK_LOCAL_URL="http://localhost:${TC_PORT}"
  mkdir -p "${SCRIPT_DIR}/../../data"
  cd "$SCRIPT_DIR"
  bash ./init-tidecloak.sh
fi

echo ""
echo "[TideCloak] Ready at http://localhost:${TC_PORT}"
echo "[TideCloak] Admin console: http://localhost:${TC_PORT}/admin"
