#!/bin/bash
# Azure CLI script to create App Service with Azure Files for KeyleSSH
# Run this script after logging in with: az login

set -e

# ============================================
# CONFIGURATION - Modify these values
# ============================================
RESOURCE_GROUP="KeyleSSH"
LOCATION="australiaeast"              # Change to your preferred region
APP_NAME="KeyleSSH"                   # Must be globally unique
STORAGE_ACCOUNT="keylesshstorage"     # Must be globally unique, lowercase, no dashes
APP_SERVICE_PLAN="keylessh-plan"
SKU="B1"                              # B1 = Basic tier (supports WebSockets)

# ============================================
# Create Resource Group
# ============================================
echo "Creating resource group: $RESOURCE_GROUP..."
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION

# ============================================
# Create Storage Account
# ============================================
echo "Creating storage account: $STORAGE_ACCOUNT..."
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS \
  --kind StorageV2

# Get storage account key
STORAGE_KEY=$(az storage account keys list \
  --account-name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --query "[0].value" -o tsv)

# ============================================
# Create Azure File Share
# ============================================
echo "Creating file share: keylessh-data..."
az storage share create \
  --name keylessh-data \
  --account-name $STORAGE_ACCOUNT \
  --account-key "$STORAGE_KEY" \
  --quota 5

# ============================================
# Create App Service Plan
# ============================================
echo "Creating App Service Plan: $APP_SERVICE_PLAN..."
az appservice plan create \
  --name $APP_SERVICE_PLAN \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku $SKU \
  --is-linux

# ============================================
# Create Web App
# ============================================
echo "Creating Web App: $APP_NAME..."
az webapp create \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_SERVICE_PLAN \
  --runtime "NODE:20-lts"

# ============================================
# Configure Web App Settings
# ============================================
echo "Configuring Web App settings..."

# Enable WebSockets (critical for SSH connections)
az webapp config set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --web-sockets-enabled true

# Set startup command
az webapp config set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --startup-file "node dist/index.cjs"

# Set environment variables
az webapp config appsettings set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    NODE_ENV=production \
    DATABASE_URL=/home/site/data/keylessh.db \
    WEBSITE_NODE_DEFAULT_VERSION=~20

# ============================================
# Mount Azure Files to /home/site/data
# ============================================
echo "Mounting Azure Files share..."
az webapp config storage-account add \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --custom-id keylessh-data \
  --storage-type AzureFiles \
  --share-name keylessh-data \
  --account-name $STORAGE_ACCOUNT \
  --access-key "$STORAGE_KEY" \
  --mount-path /home/site/data

# ============================================
# Configure Always On (prevents cold starts)
# ============================================
echo "Enabling Always On..."
az webapp config set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --always-on true

# ============================================
# Get Publish Profile for GitHub Actions
# ============================================
echo ""
echo "============================================"
echo "SETUP COMPLETE!"
echo "============================================"
echo ""
echo "Web App URL: https://$APP_NAME.azurewebsites.net"
echo ""
echo "NEXT STEPS:"
echo ""
echo "1. Get the publish profile for GitHub Actions:"
echo "   az webapp deployment list-publishing-profiles \\"
echo "     --name $APP_NAME \\"
echo "     --resource-group $RESOURCE_GROUP \\"
echo "     --xml"
echo ""
echo "2. Add it as a GitHub secret named AZURE_WEBAPP_PUBLISH_PROFILE"
echo ""
echo "3. Upload your tidecloak.json to the Azure File Share:"
echo "   az storage file upload \\"
echo "     --account-name $STORAGE_ACCOUNT \\"
echo "     --share-name keylessh-data \\"
echo "     --source ./data/tidecloak.json \\"
echo "     --path tidecloak.json"
echo ""
echo "4. Push to main branch to trigger deployment"
echo ""
