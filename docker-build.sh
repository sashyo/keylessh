#!/bin/bash
set -e

# =============================================================================
# KeyleSSH Docker Build Script
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
IMAGE_NAME="${IMAGE_NAME:-keylessh}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-}"  # e.g., ghcr.io/tide-foundation or your-acr.azurecr.io

# Full image name
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
else
    FULL_IMAGE="$IMAGE_NAME:$IMAGE_TAG"
fi

print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Docker Build"
echo "Image: $FULL_IMAGE"
echo ""

# Build the image
print_header "Building Docker Image"
docker build \
    --platform linux/amd64 \
    -t "$FULL_IMAGE" \
    -f Dockerfile \
    .

print_header "Build Complete!"
echo ""
echo "Image built: $FULL_IMAGE"
echo ""
echo "To run locally:"
echo "  docker run -d \\"
echo "    --name keylessh \\"
echo "    -p 3000:3000 \\"
echo "    -v \$(pwd)/data:/app/data \\"
echo "    -e BRIDGE_URL=wss://your-bridge-url \\"
echo "    $FULL_IMAGE"
echo ""
echo "To push to registry:"
echo "  docker push $FULL_IMAGE"
echo ""

# Optional: push to registry
if [ "$PUSH" = "true" ] && [ -n "$REGISTRY" ]; then
    print_header "Pushing to Registry"
    docker push "$FULL_IMAGE"
    echo "Pushed: $FULL_IMAGE"
fi
