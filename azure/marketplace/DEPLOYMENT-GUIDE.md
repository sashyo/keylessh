# KeyleSSH Deployment Guide

Deploy KeyleSSH from Azure Marketplace in minutes.

---

## Prerequisites

Before deploying KeyleSSH, you need:

### 1. TideCloak Configuration

KeyleSSH uses TideCloak for decentralized identity. You'll need a `tidecloak.json` configuration file from your TideCloak realm.

**If you don't have TideCloak yet:**
- Contact [Tide Protocol](https://tideprotocol.com) to set up a realm
- Or deploy TideCloak yourself from [TideCloak documentation](https://docs.tidecloak.com)

**Your tidecloak.json should look like:**
```json
{
  "realm": "your-realm",
  "auth-server-url": "https://your-tidecloak-server/",
  "resource": "keylessh",
  "credentials": {
    "secret": "your-client-secret"
  }
}
```

### 2. Azure Subscription

An active Azure subscription with permissions to create:
- Resource groups
- Container Apps
- Storage accounts

---

## Step-by-Step Deployment

### Step 1: Find KeyleSSH in Marketplace

1. Go to [Azure Portal](https://portal.azure.com)
2. Click **Create a resource**
3. Search for **"KeyleSSH"**
4. Select **KeyleSSH - Decentralized SSH PAM**
5. Click **Create**

### Step 2: Configure Basics

| Field | Description |
|-------|-------------|
| **Subscription** | Select your Azure subscription |
| **Resource Group** | Create new or select existing |
| **Region** | Choose a region close to your users |
| **Name Prefix** | Prefix for all resources (e.g., `mycompany-keylessh`) |

### Step 3: Upload TideCloak Configuration

1. Open your `tidecloak.json` file
2. Copy the entire contents
3. Paste into the **TideCloak Configuration** field

> **Note:** The configuration is stored securely as an Azure secret and base64-encoded during deployment.

### Step 4: Configure Resources (Optional)

Default settings work for most deployments. Adjust if needed:

| Setting | Default | Description |
|---------|---------|-------------|
| KeyleSSH CPU | 0.5 cores | Increase for high user counts |
| KeyleSSH Memory | 1 GB | Increase for large session recordings |
| Bridge Min Replicas | 0 | Set to 1+ for always-on SSH connections |
| Bridge Max Replicas | 100 | Maximum concurrent SSH connections |

### Step 5: Review and Create

1. Review all settings
2. Click **Create**
3. Wait for deployment (typically 3-5 minutes)

---

## Post-Deployment Setup

### 1. Get Your KeyleSSH URL

After deployment completes:

1. Go to your **Resource Group**
2. Find the Container App named `<prefix>-app`
3. Click on it and copy the **Application URL**

Your URL will look like: `https://mycompany-keylessh-app.azurecontainerapps.io`

### 2. Configure TideCloak Redirect URI

Add KeyleSSH to your TideCloak client's allowed redirects:

1. Log into your TideCloak admin console
2. Go to **Clients** → **keylessh**
3. Add to **Valid Redirect URIs**:
   ```
   https://<your-keylessh-url>/*
   ```
4. Add to **Web Origins**:
   ```
   https://<your-keylessh-url>
   ```
5. Save changes

### 3. First Login

1. Open your KeyleSSH URL in a browser
2. Click **Sign In**
3. Authenticate with TideCloak
4. You're in! Start adding servers.

---

## Adding Your First Server

### 1. Prepare Your SSH Server

KeyleSSH connects to your servers via SSH. Ensure:

- SSH is enabled on the target server
- Port 22 (or your SSH port) is accessible from Azure
- You have credentials (password or will use KeyleSSH-managed keys)

### 2. Add Server in KeyleSSH

1. Go to **Servers** → **Add Server**
2. Enter:
   - **Name**: Friendly name (e.g., "Production Web Server")
   - **Hostname**: IP or DNS name
   - **Port**: SSH port (default 22)
   - **Username**: SSH user
3. Click **Save**

### 3. Connect

1. Select your server from the list
2. Click **Connect**
3. A web-based SSH terminal opens
4. You're connected!

---

## Architecture Overview

KeyleSSH deploys these Azure resources:

```
┌─────────────────────────────────────────────────────────────────┐
│                   Your Azure Subscription                        │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Container Apps Environment                     │ │
│  │                                                             │ │
│  │   ┌─────────────────┐         ┌──────────────────────┐    │ │
│  │   │  KeyleSSH App   │         │    TCP Bridge        │    │ │
│  │   │  (Web + API)    │────────▶│  (SSH Tunneling)     │    │ │
│  │   │                 │         │  Auto-scales 0-100   │    │ │
│  │   └────────┬────────┘         └──────────────────────┘    │ │
│  │            │                                               │ │
│  └────────────│───────────────────────────────────────────────┘ │
│               │                                                  │
│   ┌───────────▼───────────┐    ┌─────────────────────────────┐  │
│   │   Azure Files         │    │   Log Analytics             │  │
│   │   - Database          │    │   - Application logs        │  │
│   │   - Session recordings│    │   - Security events         │  │
│   └───────────────────────┘    └─────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Tide ORK       │
                    │  Network        │
                    │  (Decentralized │
                    │   Key Mgmt)     │
                    └─────────────────┘
```

### What Each Component Does

| Component | Purpose |
|-----------|---------|
| **KeyleSSH App** | Web UI, API, user management, session recording |
| **TCP Bridge** | Converts WebSocket connections to SSH (scalable) |
| **Azure Files** | Persistent storage for database and recordings |
| **Log Analytics** | Centralized logging for troubleshooting |
| **Tide ORK Network** | Decentralized key management (external) |

---

## Estimated Costs

KeyleSSH uses consumption-based pricing. Typical costs:

| Usage Level | Monthly Estimate |
|-------------|------------------|
| **Small** (1-10 users, occasional use) | $20-30 |
| **Medium** (10-50 users, regular use) | $40-80 |
| **Large** (50+ users, heavy use) | $100-200+ |

**Cost breakdown:**
- Container Apps: ~$20-50/month (scales with usage)
- Storage: ~$1-5/month
- Log Analytics: ~$1-5/month

> **Tip:** Set `Bridge Min Replicas = 0` to enable scale-to-zero when not in use.

---

## Troubleshooting

### KeyleSSH Won't Start

**Check container logs:**
1. Go to your Resource Group
2. Find `<prefix>-app` Container App
3. Click **Log stream** in the left menu
4. Look for error messages

**Common issues:**
- Invalid TideCloak configuration → Check tidecloak.json format
- TideCloak unreachable → Verify auth-server-url is accessible

### Can't Connect to SSH Servers

**Check:**
1. Is the server reachable from Azure? (firewall rules)
2. Is SSH enabled on the target server?
3. Are credentials correct?

**View bridge logs:**
1. Find `<prefix>-bridge` Container App
2. Click **Log stream**
3. Look for connection errors

### Authentication Fails

**Check TideCloak:**
1. Verify redirect URIs are configured correctly
2. Ensure the KeyleSSH client is enabled
3. Check user has appropriate roles assigned

---

## Scaling

### Increase SSH Connection Capacity

Edit the TCP Bridge Container App:
1. Go to **Scale** settings
2. Increase **Max replicas** (up to 100+)

### Increase Application Resources

Edit the KeyleSSH Container App:
1. Go to **Containers** settings
2. Increase CPU/Memory allocation

---

## Security Best Practices

1. **Enable Azure Private Endpoints** - Restrict network access
2. **Use Managed Identity** - For Azure resource access
3. **Enable Azure AD Conditional Access** - Additional authentication controls
4. **Review Session Recordings** - Regularly audit access
5. **Set Up Quorum Policies** - Require multi-party approval for sensitive servers

---

## Support

- **Documentation**: https://docs.keylessh.com
- **Email**: support@tideprotocol.com
- **Issues**: https://github.com/tide-foundation/keylessh-m2/issues

---

## Uninstalling

To remove KeyleSSH:

1. Go to your Resource Group
2. Delete all resources with your prefix, or
3. Delete the entire Resource Group

> **Warning:** Deleting the Storage Account removes all session recordings and configuration permanently.
