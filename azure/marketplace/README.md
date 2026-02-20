# KeyleSSH Azure Marketplace Deployment

This directory contains the Azure Resource Manager (Bicep) templates for deploying KeyleSSH to Azure.

## Architecture

The deployment creates:

1. **Container Apps Environment** - Managed Kubernetes environment
2. **KeyleSSH Container App** - Main application (web UI + API)
3. **TCP Bridge Container App** - WebSocket to TCP bridge for SSH tunneling
4. **Storage Account** - Azure Files for persistent data
5. **Log Analytics Workspace** - Centralized logging

```
┌─────────────────────────────────────────────────────────────┐
│                    Azure Container Apps                      │
│  ┌─────────────────────┐    ┌─────────────────────────────┐ │
│  │   KeyleSSH App      │    │      TCP Bridge             │ │
│  │   (Web + API)       │───▶│   (WebSocket → TCP)         │ │
│  │   Port 3000         │    │   Port 8080                 │ │
│  └──────────┬──────────┘    └─────────────────────────────┘ │
│             │                                                │
│  ┌──────────▼──────────┐                                    │
│  │   Azure Files       │                                    │
│  │   - keylessh.db     │                                    │
│  │   - tidecloak.json  │                                    │
│  └─────────────────────┘                                    │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. Azure CLI installed and logged in
2. TideCloak realm configured with KeyleSSH client
3. `tidecloak.json` configuration file

## Quick Deploy

```bash
# Set your configuration
export RESOURCE_GROUP="keylessh-prod"
export LOCATION="eastus"
export TIDECLOAK_CONFIG="./tidecloak.json"

# Deploy
./deploy.sh
```

## Manual Deployment

### 1. Create Resource Group

```bash
az group create --name keylessh-rg --location eastus
```

### 2. Base64 Encode TideCloak Config

```bash
TIDECLOAK_B64=$(base64 -w0 tidecloak.json)
```

### 3. Deploy Bicep Template

```bash
az deployment group create \
  --resource-group keylessh-rg \
  --template-file main.bicep \
  --parameters namePrefix=keylessh \
  --parameters tidecloakConfigB64="$TIDECLOAK_B64"
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `namePrefix` | Yes | `keylessh` | Prefix for all resource names |
| `location` | No | Resource group location | Azure region |
| `tidecloakConfigB64` | Yes | - | Base64-encoded tidecloak.json |
| `keylesshImage` | No | `tideorg/keylessh:latest` | KeyleSSH container image |
| `bridgeImage` | No | `tideorg/keylessh-bridge:latest` | TCP Bridge container image |
| `stripeSecretKey` | No | - | Stripe API key (for SaaS billing) |
| `stripeWebhookSecret` | No | - | Stripe webhook secret |
| `keylesshCpu` | No | `0.5` | CPU for KeyleSSH (cores) |
| `keylesshMemory` | No | `1Gi` | Memory for KeyleSSH |
| `bridgeCpu` | No | `0.25` | CPU for TCP Bridge (cores) |
| `bridgeMemory` | No | `0.5Gi` | Memory for TCP Bridge |
| `bridgeMinReplicas` | No | `0` | Min bridge replicas (0 = scale to zero) |
| `bridgeMaxReplicas` | No | `100` | Max bridge replicas |

## Post-Deployment

### 1. Upload TideCloak Config to Storage

```bash
az storage file upload \
  --account-name <storage-account-name> \
  --share-name keylessh-data \
  --source tidecloak.json \
  --path tidecloak.json
```

### 2. Configure TideCloak Redirect URI

Add the KeyleSSH URL to your TideCloak client's valid redirect URIs:
```
https://<keylessh-app>.azurecontainerapps.io/*
```

### 3. Access KeyleSSH

Open the URL shown in the deployment output.

## Azure Marketplace Submission

For Azure Marketplace listing, this deployment includes:

- `main.bicep` - Main deployment template
- `createUiDefinition.json` - Azure portal UI definition
- `parameters.json` - Parameter defaults

### Marketplace Requirements

1. Push images to a public registry or Azure Marketplace ACR
2. Create Partner Center account
3. Submit as "Azure Application - Solution Template" offer
4. Include documentation and support info

## Troubleshooting

### View Logs

```bash
# KeyleSSH logs
az containerapp logs show \
  --name keylessh-app \
  --resource-group keylessh-rg \
  --follow

# TCP Bridge logs
az containerapp logs show \
  --name keylessh-bridge \
  --resource-group keylessh-rg \
  --follow
```

### Check Container Status

```bash
az containerapp show \
  --name keylessh-app \
  --resource-group keylessh-rg \
  --query "properties.runningStatus"
```

### Restart Containers

```bash
az containerapp revision restart \
  --name keylessh-app \
  --resource-group keylessh-rg \
  --revision <revision-name>
```
