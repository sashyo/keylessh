#!/bin/bash
set -e

# Load .env file if it exists
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# =============================================================================
# KeyleSSH Web App Deployment Script
# Builds and deploys the application to Azure Web App
# =============================================================================

# Configuration (from .env or defaults)
ENV_NAME="${ENV_NAME:-myenv}"
RESOURCE_GROUP="${RESOURCE_GROUP:-keylessh-${ENV_NAME}}"
WEBAPP_NAME="${WEBAPP_NAME:-keylessh-${ENV_NAME}}"
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-$SCRIPT_DIR/tidecloak.json}"

# =============================================================================
print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Web App Deployment"
echo "Environment:    $ENV_NAME"
echo "Resource Group: $RESOURCE_GROUP"
echo "Web App:        $WEBAPP_NAME"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Error: Please login to Azure first: az login"
    exit 1
fi

# Navigate to project root
cd "$SCRIPT_DIR/.."

# =============================================================================
print_header "Copying TideCloak Config"
if [ -f "$TIDECLOAK_CONFIG" ]; then
    # Copy to client adapter (used during build for browser auth)
    cp "$TIDECLOAK_CONFIG" client/src/tidecloakAdapter.json
    echo "Copied $TIDECLOAK_CONFIG to client/src/tidecloakAdapter.json"
else
    echo "Warning: tidecloak.json not found at $TIDECLOAK_CONFIG"
    echo "Build will use default client/src/tidecloakAdapter.json"
fi

# =============================================================================
print_header "Installing Dependencies"
npm ci

# =============================================================================
print_header "Building Application"
npm run build

# =============================================================================
print_header "Creating Deployment Package"
rm -rf deploy deploy.zip
mkdir -p deploy

# Copy build output
cp -r dist deploy/

# Copy package files
cp package.json deploy/
cp package-lock.json deploy/

# Copy tidecloak.json if it exists
if [ -f "$TIDECLOAK_CONFIG" ]; then
    mkdir -p deploy/data
    cp "$TIDECLOAK_CONFIG" deploy/data/tidecloak.json
    echo "Included tidecloak.json from $TIDECLOAK_CONFIG"
else
    echo "Warning: tidecloak.json not found at $TIDECLOAK_CONFIG"
fi

# Install production dependencies only
cd deploy
npm ci --omit=dev
cd ..

# Create zip
cd deploy
zip -r ../deploy.zip .
cd ..

# =============================================================================
print_header "Deploying to Azure Web App"
az webapp deploy \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --src-path deploy.zip \
    --type zip

# =============================================================================
print_header "Cleaning Up"
rm -rf deploy deploy.zip

# =============================================================================
print_header "Deployment Complete!"

WEBAPP_URL=$(az webapp show \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "defaultHostName" -o tsv)

echo ""
echo "Web App URL: https://$WEBAPP_URL"
echo ""
echo "View logs with:"
echo "  az webapp log tail --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP"
echo ""
