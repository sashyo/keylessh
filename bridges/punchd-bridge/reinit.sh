#!/usr/bin/env bash
# Wipe TideCloak and re-initialize from scratch.
# Uses localhost hostname for init (so invite link works),
# then restarts with the public hostname before starting the gateway.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Stop gateway if running
pkill -f "node.*dist/index.js" 2>/dev/null || true

# Remove TideCloak container
docker rm -f mytidecloak 2>/dev/null || true

# Remove old adapter configs
rm -f "${REPO_ROOT}/data/tidecloak.json" "${REPO_ROOT}/gateway/data/tidecloak.json"

# Run start.sh (handles two-phase TC startup + gateway)
exec bash "${REPO_ROOT}/start.sh"
