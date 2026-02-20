#!/usr/bin/env bash
# Start the WAF with sensible defaults.
# Override any variable by setting it before running, e.g.:
#   STUN_SERVER_URL=wss://example.com:9090 ./start.sh
#   TC_PORT=8180 ./start.sh

set -euo pipefail

TC_PORT="${TC_PORT:-8080}"

export STUN_SERVER_URL="${STUN_SERVER_URL:-wss://tidestun.codesyo.com:9090}"
export ICE_SERVERS="${ICE_SERVERS:-stun:20.211.145.216:3478}"
export BACKEND_URL="${BACKEND_URL:-http://localhost:3000}"
export LOCAL_AUTH_URL="${LOCAL_AUTH_URL:-http://localhost:${TC_PORT}}"
export LISTEN_PORT="${LISTEN_PORT:-7891}"
export HEALTH_PORT="${HEALTH_PORT:-7892}"

cd "$(dirname "$0")"

echo "[WAF] Building..."
npm run build

echo "[WAF] Starting with:"
echo "  STUN_SERVER_URL=$STUN_SERVER_URL"
echo "  ICE_SERVERS=$ICE_SERVERS"
echo "  BACKEND_URL=$BACKEND_URL"
echo "  LOCAL_AUTH_URL=$LOCAL_AUTH_URL"
echo "  LISTEN_PORT=$LISTEN_PORT"
echo "  HEALTH_PORT=$HEALTH_PORT"

npm start
