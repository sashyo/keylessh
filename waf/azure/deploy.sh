#!/bin/bash
set -e

# Configuration - update these values
RESOURCE_GROUP="keylessh-rg"
LOCATION="eastus"
ENVIRONMENT_NAME="keylessh-env"
ACR_NAME="keylesshacr"
APP_NAME="keylessh-waf"

# Auto-load STUN deployment config if available
STUN_ENV="$(dirname "$0")/../../.stun-deploy.env"
if [ -f "$STUN_ENV" ]; then
    echo "Loading STUN config from $STUN_ENV"
    set -a; source "$STUN_ENV"; set +a
fi

# Required
BACKEND_URL="${BACKEND_URL:-}"
STUN_SERVER_URL="${STUN_SERVER_URL:-}"

# Optional
ICE_SERVERS="${ICE_SERVERS:-}"
TURN_SERVER="${TURN_SERVER:-}"
TURN_SECRET="${TURN_SECRET:-}"
WAF_ID="${WAF_ID:-}"
WAF_DISPLAY_NAME="${WAF_DISPLAY_NAME:-}"
WAF_DESCRIPTION="${WAF_DESCRIPTION:-}"
AUTH_SERVER_PUBLIC_URL="${AUTH_SERVER_PUBLIC_URL:-}"
STRIP_AUTH_HEADER="${STRIP_AUTH_HEADER:-false}"

# Path to tidecloak.json config (required for JWT verification)
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-../../data/tidecloak.json}"

echo "=== KeyleSSH WAF Gateway Deployment ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo "Container App: $APP_NAME"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Please login to Azure first: az login"
    exit 1
fi

if [ -z "$BACKEND_URL" ]; then
    echo "Error: BACKEND_URL is required"
    echo "Usage: BACKEND_URL=http://app:3000 STUN_SERVER_URL=ws://stun:9090 ./deploy.sh"
    exit 1
fi

if [ -z "$STUN_SERVER_URL" ]; then
    echo "Error: STUN_SERVER_URL is required"
    echo "Usage: BACKEND_URL=http://app:3000 STUN_SERVER_URL=ws://stun:9090 ./deploy.sh"
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

# Build env vars string — always include required vars
ENV_VARS="TIDECLOAK_CONFIG_B64=secretref:tidecloak-config"
ENV_VARS="$ENV_VARS BACKEND_URL=$BACKEND_URL"
ENV_VARS="$ENV_VARS STUN_SERVER_URL=$STUN_SERVER_URL"
ENV_VARS="$ENV_VARS STRIP_AUTH_HEADER=$STRIP_AUTH_HEADER"

# Append optional vars only if set
[ -n "$ICE_SERVERS" ]           && ENV_VARS="$ENV_VARS ICE_SERVERS=$ICE_SERVERS"
[ -n "$TURN_SERVER" ]           && ENV_VARS="$ENV_VARS TURN_SERVER=$TURN_SERVER"
[ -n "$TURN_SECRET" ]           && ENV_VARS="$ENV_VARS TURN_SECRET=$TURN_SECRET"
[ -n "$WAF_ID" ]                && ENV_VARS="$ENV_VARS WAF_ID=$WAF_ID"
[ -n "$WAF_DISPLAY_NAME" ]      && ENV_VARS="$ENV_VARS WAF_DISPLAY_NAME=$WAF_DISPLAY_NAME"
[ -n "$WAF_DESCRIPTION" ]       && ENV_VARS="$ENV_VARS WAF_DESCRIPTION=$WAF_DESCRIPTION"
[ -n "$AUTH_SERVER_PUBLIC_URL" ] && ENV_VARS="$ENV_VARS AUTH_SERVER_PUBLIC_URL=$AUTH_SERVER_PUBLIC_URL"

# Deploy Container App (internal ingress — not publicly accessible)
echo "Deploying Container App (internal)..."
az containerapp create \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --environment $ENVIRONMENT_NAME \
    --image "$ACR_SERVER/$APP_NAME:latest" \
    --registry-server $ACR_SERVER \
    --registry-username $ACR_USERNAME \
    --registry-password $ACR_PASSWORD \
    --target-port 7891 \
    --ingress internal \
    --min-replicas 0 \
    --max-replicas 100 \
    --cpu 0.25 \
    --memory 0.5Gi \
    --secrets "tidecloak-config=$TIDECLOAK_CONFIG_B64" \
    --env-vars $ENV_VARS \
    --scale-rule-name http-connections \
    --scale-rule-type http \
    --scale-rule-http-concurrency 10

# Get the internal URL
WAF_URL=$(az containerapp show \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "properties.configuration.ingress.fqdn" -o tsv)

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "WAF Internal URL: http://$WAF_URL (not publicly accessible)"
echo "Health Check: http://$WAF_URL:7892/health"
echo "STUN Server:  $STUN_SERVER_URL"
echo ""
echo "Clients reach this WAF through the STUN/TURN server."
echo "The WAF will scale from 0 to 100 instances based on HTTP connections."
