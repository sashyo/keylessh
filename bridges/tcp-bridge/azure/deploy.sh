#!/bin/bash
set -e

# Configuration - update these values
RESOURCE_GROUP="KeyleSSH"
LOCATION="australiaeast"
ENVIRONMENT_NAME="keylessh-env"
ACR_NAME="keylesshacr"
APP_NAME="keylessh-tcp-bridge"

# Path to tidecloak.json config (required for JWT verification)
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-../../data/tidecloak.json}"

echo "=== KeyleSSH TCP Bridge Deployment ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo "Container App: $APP_NAME"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Please login to Azure first: az login"
    exit 1
fi

# Check if tidecloak.json exists
if [ ! -f "$TIDECLOAK_CONFIG" ]; then
    echo "Error: TideCloak config not found at $TIDECLOAK_CONFIG"
    echo "Please ensure tidecloak.json exists with JWKS configuration"
    exit 1
fi

# Read and base64 encode the config for storage as a secret
TIDECLOAK_CONFIG_B64=$(base64 -w0 "$TIDECLOAK_CONFIG")

# Create resource group if not exists
echo "Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none 2>/dev/null || true

# Create Azure Container Registry if not exists
echo "Creating container registry..."
az acr create \
    --resource-group $RESOURCE_GROUP \
    --name $ACR_NAME \
    --sku Basic \
    --admin-enabled true \
    --output none 2>/dev/null || true

# Build and push image
echo "Building and pushing Docker image..."
az acr build \
    --registry $ACR_NAME \
    --image $APP_NAME:latest \
    --file Dockerfile \
    .

# Create Container Apps environment if not exists
echo "Creating Container Apps environment..."
az containerapp env create \
    --name $ENVIRONMENT_NAME \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --output none 2>/dev/null || true

# Get ACR credentials
ACR_SERVER=$(az acr show --name $ACR_NAME --query loginServer -o tsv)
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

# Deploy Container App
echo "Deploying Container App..."
az containerapp create \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --environment $ENVIRONMENT_NAME \
    --image "$ACR_SERVER/$APP_NAME:latest" \
    --registry-server $ACR_SERVER \
    --registry-username $ACR_USERNAME \
    --registry-password $ACR_PASSWORD \
    --target-port 8080 \
    --ingress external \
    --min-replicas 0 \
    --max-replicas 100 \
    --cpu 0.25 \
    --memory 0.5Gi \
    --secrets "tidecloak-config=$TIDECLOAK_CONFIG_B64" \
    --env-vars "TIDECLOAK_CONFIG_B64=secretref:tidecloak-config" \
    --scale-rule-name http-connections \
    --scale-rule-type http \
    --scale-rule-http-concurrency 10

# Get the URL
BRIDGE_URL=$(az containerapp show \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "properties.configuration.ingress.fqdn" -o tsv)

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "TCP Bridge URL: https://$BRIDGE_URL"
echo ""
echo "Add this to your main server environment:"
echo "  BRIDGE_URL=wss://$BRIDGE_URL"
echo ""
echo "The bridge will scale from 0 to 100 instances based on SSH connections."
