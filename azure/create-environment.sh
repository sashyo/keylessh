#!/bin/bash
set -e

# Load .env file if it exists
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# =============================================================================
# KeyleSSH Environment Setup Script
# Creates: Web App (uses existing Resource Group, Storage Account, and Bridge)
# =============================================================================

# Configuration - Uses existing resources
RESOURCE_GROUP="${RESOURCE_GROUP:-KeyleSSH}"
LOCATION="${LOCATION:-australiaeast}"

# Resource names
WEBAPP_NAME="${WEBAPP_NAME:-keylessh-multi}"
APP_SERVICE_PLAN="${APP_SERVICE_PLAN:-keylessh-plan}"

# Existing resources
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-keylesshstorage}"
BRIDGE_URL="${BRIDGE_URL:-wss://keylessh-bridge-devops.icybay-5c9a159d.australiaeast.azurecontainerapps.io}"

# =============================================================================
print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Environment Setup"
echo "Resource Group:   $RESOURCE_GROUP"
echo "Location:         $LOCATION"
echo "Web App:          $WEBAPP_NAME"
echo "Storage Account:  $STORAGE_ACCOUNT (existing)"
echo "Bridge URL:       $BRIDGE_URL (existing)"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Error: Please login to Azure first: az login"
    exit 1
fi

# =============================================================================
print_header "Checking Resource Group"
az group show --name $RESOURCE_GROUP --output none 2>/dev/null || {
    echo "Error: Resource group $RESOURCE_GROUP does not exist!"
    exit 1
}
echo "Using existing resource group: $RESOURCE_GROUP"

# =============================================================================
print_header "Getting Storage Account Key"
STORAGE_KEY=$(az storage account keys list \
    --account-name $STORAGE_ACCOUNT \
    --resource-group $RESOURCE_GROUP \
    --query "[0].value" -o tsv)

if [ -z "$STORAGE_KEY" ]; then
    echo "Error: Could not get storage account key for $STORAGE_ACCOUNT"
    exit 1
fi
echo "Got storage key for: $STORAGE_ACCOUNT"

# Ensure file share exists
az storage share create \
    --name keylessh-multi \
    --account-name $STORAGE_ACCOUNT \
    --account-key "$STORAGE_KEY" \
    --quota 5 \
    --output none 2>/dev/null || echo "File share already exists"

# =============================================================================
print_header "Creating App Service Plan"
az appservice plan create \
    --name $APP_SERVICE_PLAN \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --sku B1 \
    --is-linux \
    --output none 2>/dev/null || echo "App Service Plan already exists"

# =============================================================================
print_header "Creating Web App"
az webapp create \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --plan $APP_SERVICE_PLAN \
    --runtime "NODE:20-lts" \
    --output none 2>/dev/null || echo "Web App already exists"

# Enable WebSockets on Web App
echo "Enabling WebSockets..."
az webapp config set \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --web-sockets-enabled true \
    --output none

# Set startup command
az webapp config set \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --startup-file "node dist/index.cjs" \
    --output none

# Mount Azure Files for persistent storage
echo "Mounting Azure Files..."
az webapp config storage-account add \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --custom-id keylessh-multi \
    --storage-type AzureFiles \
    --share-name keylessh-multi \
    --account-name $STORAGE_ACCOUNT \
    --access-key "$STORAGE_KEY" \
    --mount-path /home/site/data \
    --output none 2>/dev/null || echo "Storage mount already exists"

# Enable Always On (prevents cold starts)
az webapp config set \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --always-on true \
    --output none

# =============================================================================
print_header "Configuring Web App Environment Variables"

# Get Web App URL
WEBAPP_URL=$(az webapp show \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "defaultHostName" -o tsv)

# Set environment variables on Web App
az webapp config appsettings set \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --settings \
        NODE_ENV=production \
        DATABASE_URL=/home/site/data/keylessh.db \
        BRIDGE_URL=$BRIDGE_URL \
        ENABLE_MULTI_TENANT=true \
    --output none

# =============================================================================
print_header "Setup Complete!"

echo ""
echo "Resources:"
echo "  Resource Group:   $RESOURCE_GROUP"
echo "  Web App:          https://$WEBAPP_URL"
echo "  Storage Account:  $STORAGE_ACCOUNT"
echo "  Bridge URL:       $BRIDGE_URL"
echo ""
echo "Web App Settings Applied:"
echo "  NODE_ENV=production"
echo "  DATABASE_URL=/home/site/data/keylessh.db"
echo "  BRIDGE_URL=$BRIDGE_URL"
echo "  ENABLE_MULTI_TENANT=true"
echo ""
echo "Next Steps:"
echo ""
echo "  1. Set TideCloak admin credentials (for multi-tenancy user provisioning):"
echo "     az webapp config appsettings set --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --settings \\"
echo "       KC_USER=admin \\"
echo "       KC_PASSWORD=your-tidecloak-admin-password"
echo ""
echo "  2. Upload tidecloak.json to Azure Files:"
echo "     az storage file upload \\"
echo "       --account-name $STORAGE_ACCOUNT \\"
echo "       --share-name keylessh-multi \\"
echo "       --source ./data/tidecloak.json \\"
echo "       --path tidecloak.json"
echo ""
echo "  3. Configure GitHub Actions secret AZURE_WEBAPP_PUBLISH_PROFILE:"
echo "     az webapp deployment list-publishing-profiles --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --xml"
echo ""
echo "  4. Deploy the app via GitHub Actions (push to main) or manually:"
echo "     ./azure/deploy-webapp.sh"
echo ""
