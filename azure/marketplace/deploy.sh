#!/bin/bash
set -e

# =============================================================================
# KeyleSSH Azure Marketplace Deployment Script
# Deploys KeyleSSH + TCP Bridge as Azure Container Apps with persistent storage
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Configuration
RESOURCE_GROUP="${RESOURCE_GROUP:-keylessh-rg}"
LOCATION="${LOCATION:-eastus}"
NAME_PREFIX="${NAME_PREFIX:-keylessh}"
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-$SCRIPT_DIR/../../data/tidecloak.json}"

print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Azure Deployment"
echo "Resource Group: $RESOURCE_GROUP"
echo "Location:       $LOCATION"
echo "Name Prefix:    $NAME_PREFIX"
echo ""

# Check Azure CLI login
if ! az account show &> /dev/null; then
    echo "Error: Please login to Azure first: az login"
    exit 1
fi

# Validate tidecloak.json exists
if [ ! -f "$TIDECLOAK_CONFIG" ]; then
    echo "Error: TideCloak config not found at $TIDECLOAK_CONFIG"
    echo "Please provide the path via TIDECLOAK_CONFIG environment variable"
    exit 1
fi

# Base64 encode tidecloak.json
TIDECLOAK_B64=$(base64 -w0 "$TIDECLOAK_CONFIG" 2>/dev/null || base64 "$TIDECLOAK_CONFIG")
echo "TideCloak config loaded from: $TIDECLOAK_CONFIG"

# Create resource group if it doesn't exist
print_header "Creating Resource Group"
az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none 2>/dev/null || echo "Resource group already exists"

# Deploy Bicep template
print_header "Deploying KeyleSSH Infrastructure"
DEPLOYMENT_OUTPUT=$(az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$SCRIPT_DIR/main.bicep" \
    --parameters namePrefix="$NAME_PREFIX" \
    --parameters tidecloakConfigB64="$TIDECLOAK_B64" \
    --parameters location="$LOCATION" \
    --query "properties.outputs" \
    --output json)

# Extract outputs
KEYLESSH_URL=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.keylesshUrl.value')
BRIDGE_URL=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.bridgeUrl.value')
STORAGE_ACCOUNT=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.storageAccountName.value')
FILE_SHARE=$(echo "$DEPLOYMENT_OUTPUT" | jq -r '.fileShareName.value')

print_header "Deployment Complete!"
echo ""
echo "Resources Deployed:"
echo "  KeyleSSH URL:     $KEYLESSH_URL"
echo "  Bridge URL:       $BRIDGE_URL"
echo "  Storage Account:  $STORAGE_ACCOUNT"
echo "  File Share:       $FILE_SHARE"
echo ""
echo "Next Steps:"
echo ""
echo "1. Upload tidecloak.json to the file share:"
echo "   az storage file upload \\"
echo "     --account-name $STORAGE_ACCOUNT \\"
echo "     --share-name $FILE_SHARE \\"
echo "     --source $TIDECLOAK_CONFIG \\"
echo "     --path tidecloak.json"
echo ""
echo "2. Access KeyleSSH at: $KEYLESSH_URL"
echo ""
echo "3. Configure TideCloak with the following redirect URI:"
echo "   $KEYLESSH_URL/*"
echo ""
echo "4. (Optional) Configure Stripe for billing:"
echo "   az containerapp update \\"
echo "     --name ${NAME_PREFIX}-app \\"
echo "     --resource-group $RESOURCE_GROUP \\"
echo "     --set-env-vars STRIPE_SECRET_KEY=sk_... STRIPE_WEBHOOK_SECRET=whsec_..."
echo ""
