#!/bin/bash
set -e

# Load .env file if it exists
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# =============================================================================
# KeyleSSH Web App Deployment Script
# Builds and deploys the application to Azure Web App
# =============================================================================

# Configuration (from .env or defaults)
RESOURCE_GROUP="${RESOURCE_GROUP:-KeyleSSH}"
WEBAPP_NAME="${WEBAPP_NAME:-keylessh-multi}"

# Get project root (parent of azure folder)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-$PROJECT_ROOT/data/tidecloak.json}"

# Resolve to absolute path
if [ -f "$TIDECLOAK_CONFIG" ]; then
    TIDECLOAK_CONFIG="$(cd "$(dirname "$TIDECLOAK_CONFIG")" && pwd)/$(basename "$TIDECLOAK_CONFIG")"
fi

# =============================================================================
print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Web App Deployment"
echo "Resource Group:    $RESOURCE_GROUP"
echo "Web App:           $WEBAPP_NAME"
echo "Project Root:      $PROJECT_ROOT"
echo "TideCloak Config:  $TIDECLOAK_CONFIG"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Error: Please login to Azure first: az login"
    exit 1
fi

# Navigate to project root
cd "$PROJECT_ROOT"

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

# NOTE: We don't install node_modules locally because better-sqlite3
# needs to be compiled for Azure's Node version (20.x).
# Azure will run npm install automatically during deployment.

# Create zip (use PowerShell on Windows if zip not available)
print_header "Creating ZIP Archive"
cd deploy
if command -v zip &> /dev/null; then
    zip -r ../deploy.zip .
elif command -v powershell &> /dev/null; then
    powershell -Command "Compress-Archive -Path * -DestinationPath ../deploy.zip -Force"
else
    echo "Error: Neither 'zip' nor 'powershell' available for creating archive"
    exit 1
fi
cd ..

# =============================================================================
print_header "Configuring Azure Build"
# Disable Oryx build - we deploy pre-built artifacts via GitHub Actions
# Native modules (better-sqlite3) are compiled for Node 20 on Linux in the workflow
az webapp config appsettings set \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --settings \
        SCM_DO_BUILD_DURING_DEPLOYMENT=false \
        ENABLE_ORYX_BUILD=false \
    --output none

# =============================================================================
print_header "Deploying to Azure Web App (with Oryx build)"

# Get publish credentials
CREDS=$(az webapp deployment list-publishing-credentials \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "{username:publishingUserName, password:publishingPassword}" -o json)

DEPLOY_USER=$(echo $CREDS | jq -r '.username')
DEPLOY_PASS=$(echo $CREDS | jq -r '.password')

# Deploy using Kudu zipdeploy API (triggers Oryx build)
curl -X POST \
    --user "$DEPLOY_USER:$DEPLOY_PASS" \
    --data-binary @deploy.zip \
    -H "Content-Type: application/zip" \
    "https://$WEBAPP_NAME.scm.azurewebsites.net/api/zipdeploy?isAsync=false"

echo ""

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
