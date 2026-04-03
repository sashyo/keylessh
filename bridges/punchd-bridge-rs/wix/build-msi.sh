#!/bin/bash
set -e

# Build Punchd VPN MSI installer using Docker (Windows container)
#
# Prerequisites:
#   - Docker Desktop with Windows containers enabled
#   - Build the builder image first: docker build -m 4GB -t punchd-vpn-builder wix/
#
# Usage:
#   ./wix/build-msi.sh [path-to-exe]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXE_PATH="${1:-$SCRIPT_DIR/../target/x86_64-pc-windows-gnu/release/punchd-vpn.exe}"

if [ ! -f "$EXE_PATH" ]; then
    echo "Error: punchd-vpn.exe not found at $EXE_PATH"
    echo "Build it first:"
    echo "  cargo build --release --target x86_64-pc-windows-gnu --bin punchd-vpn"
    exit 1
fi

# Copy exe next to the wxs and CA source
cp "$EXE_PATH" "$SCRIPT_DIR/punchd-vpn.exe"

echo "Building Punchd VPN MSI..."
echo "  Exe: $EXE_PATH"

# Check if builder image exists
if ! docker image inspect punchd-vpn-builder &>/dev/null; then
    echo "  Builder image not found. Building it first (this takes 5-50 min)..."
    docker build -m 4GB -t punchd-vpn-builder "$SCRIPT_DIR"
fi

# Run the builder
docker run --rm -v "${SCRIPT_DIR}:C:\src" punchd-vpn-builder

# Cleanup
rm -f "$SCRIPT_DIR/punchd-vpn.exe"

if [ -f "$SCRIPT_DIR/punchd-vpn.msi" ]; then
    SIZE=$(du -h "$SCRIPT_DIR/punchd-vpn.msi" | cut -f1)
    echo ""
    echo "MSI built: $SCRIPT_DIR/punchd-vpn.msi ($SIZE)"
    echo ""
    echo "Install (GUI):    msiexec /i punchd-vpn.msi"
    echo "Install (silent): msiexec /i punchd-vpn.msi /qn VPN_CONFIG_FILE=C:\\path\\to\\vpn-config.toml"
else
    echo "Error: MSI was not produced"
    exit 1
fi
