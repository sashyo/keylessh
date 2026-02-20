#!/bin/bash
set -e

# Load .env file if it exists
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# =============================================================================
# KeyleSSH Environment Setup Script
# Creates: Resource Group, Web App (frontend), Container App (TCP Bridge), ACR
# =============================================================================

# Configuration - CHANGE THESE for each new realm/environment
ENV_NAME="${ENV_NAME:-myenv}"                    # Environment name (e.g., prod, staging, dev)
LOCATION="${LOCATION:-australiaeast}"            # Azure region
RESOURCE_GROUP="${RESOURCE_GROUP:-keylessh-${ENV_NAME}}"

# Derived names (can override via env vars)
WEBAPP_NAME="${WEBAPP_NAME:-keylessh-${ENV_NAME}}"
BRIDGE_APP_NAME="${BRIDGE_APP_NAME:-keylessh-bridge-${ENV_NAME}}"
ACR_NAME="${ACR_NAME:-keylesshacr${ENV_NAME}}"   # Must be globally unique, alphanumeric only
CONTAINER_ENV_NAME="${CONTAINER_ENV_NAME:-keylessh-env-${ENV_NAME}}"
APP_SERVICE_PLAN="${APP_SERVICE_PLAN:-keylessh-plan-${ENV_NAME}}"

# TideCloak config (required for TCP bridge JWT verification)
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-../data/tidecloak.json}"

# =============================================================================
print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Environment Setup"
echo "Environment:      $ENV_NAME"
echo "Resource Group:   $RESOURCE_GROUP"
echo "Location:         $LOCATION"
echo "Web App:          $WEBAPP_NAME"
echo "TCP Bridge:       $BRIDGE_APP_NAME"
echo "Container Registry: $ACR_NAME"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Error: Please login to Azure first: az login"
    exit 1
fi

# Check if tidecloak.json exists
if [ ! -f "$TIDECLOAK_CONFIG" ]; then
    echo "Warning: TideCloak config not found at $TIDECLOAK_CONFIG"
    echo "TCP Bridge will be created but JWT verification won't work without it."
    echo "You can update the secret later with:"
    echo "  az containerapp secret set --name $BRIDGE_APP_NAME --resource-group $RESOURCE_GROUP --secrets tidecloak-config=\$(base64 -w0 path/to/tidecloak.json)"
    TIDECLOAK_CONFIG_B64=""
else
    TIDECLOAK_CONFIG_B64=$(base64 -w0 "$TIDECLOAK_CONFIG")
fi

# =============================================================================
print_header "Creating Resource Group"
az group create \
    --name $RESOURCE_GROUP \
    --location $LOCATION \
    --output none 2>/dev/null || echo "Resource group already exists"

# =============================================================================
print_header "Creating Azure Container Registry"
az acr create \
    --resource-group $RESOURCE_GROUP \
    --name $ACR_NAME \
    --sku Basic \
    --admin-enabled true \
    --output none 2>/dev/null || echo "Container registry already exists"

# =============================================================================
print_header "Creating App Service Plan (for Web App)"
az appservice plan create \
    --name $APP_SERVICE_PLAN \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --sku B1 \
    --is-linux \
    --output none 2>/dev/null || echo "App Service Plan already exists"

# =============================================================================
print_header "Creating Web App (Frontend)"
az webapp create \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --plan $APP_SERVICE_PLAN \
    --runtime "NODE:22-lts" \
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

# =============================================================================
print_header "Building and Pushing TCP Bridge Image"
cd "$(dirname "$0")/../tcp-bridge"

az acr build \
    --registry $ACR_NAME \
    --image $BRIDGE_APP_NAME:latest \
    --file Dockerfile \
    .

cd - > /dev/null

# =============================================================================
print_header "Creating Container Apps Environment"
az containerapp env create \
    --name $CONTAINER_ENV_NAME \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --output none 2>/dev/null || echo "Container Apps environment already exists"

# =============================================================================
print_header "Deploying TCP Bridge Container App"

# Get ACR credentials
ACR_SERVER=$(az acr show --name $ACR_NAME --query loginServer -o tsv)
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

# Build the create command
CREATE_CMD="az containerapp create \
    --name $BRIDGE_APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --environment $CONTAINER_ENV_NAME \
    --image $ACR_SERVER/$BRIDGE_APP_NAME:latest \
    --registry-server $ACR_SERVER \
    --registry-username $ACR_USERNAME \
    --registry-password $ACR_PASSWORD \
    --target-port 8080 \
    --ingress external \
    --min-replicas 0 \
    --max-replicas 100 \
    --cpu 0.25 \
    --memory 0.5Gi \
    --scale-rule-name http-connections \
    --scale-rule-type http \
    --scale-rule-http-concurrency 10"

# Add secrets if tidecloak config exists
if [ -n "$TIDECLOAK_CONFIG_B64" ]; then
    CREATE_CMD="$CREATE_CMD \
        --secrets tidecloak-config=$TIDECLOAK_CONFIG_B64 \
        --env-vars TIDECLOAK_CONFIG_B64=secretref:tidecloak-config"
fi

eval $CREATE_CMD

# =============================================================================
print_header "Configuring Web App Environment Variables"

# Get the bridge URL
BRIDGE_FQDN=$(az containerapp show \
    --name $BRIDGE_APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "properties.configuration.ingress.fqdn" -o tsv)

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
        BRIDGE_URL=wss://$BRIDGE_FQDN \
    --output none

# =============================================================================
print_header "Deployment Complete!"

echo ""
echo "Resources Created:"
echo "  Resource Group:     $RESOURCE_GROUP"
echo "  Web App:            https://$WEBAPP_URL"
echo "  TCP Bridge:         wss://$BRIDGE_FQDN"
echo "  Container Registry: $ACR_SERVER"
echo ""
echo "Web App Settings Applied:"
echo "  BRIDGE_URL=wss://$BRIDGE_FQDN"
echo "  NODE_ENV=production"
echo ""
echo "Next Steps:"
echo "  1. Configure GitHub Actions secret AZURE_WEBAPP_PUBLISH_PROFILE_${ENV_NAME^^}"
echo "     Get it with: az webapp deployment list-publishing-profiles --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --xml"
echo ""
echo "  2. Add remaining environment variables to Web App:"
echo "     az webapp config appsettings set --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --settings \\"
echo "       DATABASE_URL=./data/keylessh.db \\"
echo "       COMPILER_IMAGE=ghcr.io/tide-foundation/forseti-compiler:latest"
echo ""
echo "  3. Mount persistent storage for data/ volume (SQLite + tidecloak.json)"
echo ""
echo "  4. Deploy the app code via GitHub Actions or:"
echo "     az webapp deployment source config-zip --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --src deploy.zip"
echo ""
