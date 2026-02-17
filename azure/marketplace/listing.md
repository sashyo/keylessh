# KeyleSSH Azure Marketplace Listing Content

Use this content when creating the marketplace listing in Partner Center.

---

## Offer Details

### Offer Name
KeyleSSH - Passwordless SSH Access Management

### Short Description (100 chars max)
Secure SSH access without passwords. Cryptographic authentication powered by Tide Protocol.

### Long Description

**KeyleSSH** transforms SSH access management by eliminating passwords entirely. Using Tide Protocol's decentralized cryptography, KeyleSSH provides:

**Key Features:**
- **Passwordless Authentication** - No SSH keys to manage, no passwords to remember
- **Decentralized Security** - Private keys are never stored in one place
- **Fine-grained Access Control** - Define who can access which servers
- **Session Recording** - Full audit trail of all SSH sessions
- **Web-based Terminal** - Access servers from any browser
- **Policy Engine** - Cryptographic access policies with Forseti contracts

**How It Works:**
1. Users authenticate via TideCloak (OIDC)
2. Access policies are evaluated cryptographically
3. Temporary SSH credentials are issued per-session
4. All sessions are recorded for compliance

**Architecture:**
- **KeyleSSH App** - Web UI and API server
- **TCP Bridge** - Scalable WebSocket-to-SSH tunneling
- **Azure Files** - Persistent storage for configuration and audit logs

**Perfect For:**
- DevOps teams managing cloud infrastructure
- Organizations with compliance requirements (SOC2, HIPAA)
- MSPs managing multiple client environments
- Any team wanting to eliminate SSH key sprawl

### Search Keywords
SSH, passwordless, access management, security, DevOps, compliance, audit, Tide Protocol, decentralized, cryptography

---

## Categories

- **Primary**: Security
- **Secondary**: Developer Tools, IT & Management Tools

---

## Pricing

### Bring Your Own License (BYOL)
Users deploy their own infrastructure. Pricing is based on Azure consumption (Container Apps, Storage).

**Estimated Monthly Cost:**
- Container Apps: ~$20-50/month (depending on usage)
- Storage Account: ~$1-5/month
- Total: ~$25-55/month for small deployments

---

## Support Information

### Support Contact
- Email: support@tideprotocol.com
- Documentation: https://docs.keylessh.com

### Privacy Policy URL
https://tideprotocol.com/privacy

### Terms of Use URL
https://tideprotocol.com/terms

---

## Technical Requirements

### Prerequisites
- Azure subscription
- TideCloak realm configured with KeyleSSH client
- tidecloak.json configuration file

### Resources Deployed
- Azure Container Apps Environment
- 2 Container Apps (KeyleSSH + TCP Bridge)
- Azure Storage Account with File Share
- Log Analytics Workspace

### Regions
Available in all Azure regions that support Container Apps.

---

## Screenshots Needed

1. **Login Page** - TideCloak authentication screen
2. **Dashboard** - Server list and status
3. **Terminal** - Web-based SSH session
4. **User Management** - Admin panel for users
5. **Session Recording** - Audit playback feature
6. **Architecture Diagram** - Visual overview

---

## Logos Needed

1. **Small Logo**: 48x48 PNG, transparent background
2. **Large Logo**: 216x216 PNG, transparent background
3. **Wide Logo**: 255x115 PNG (optional)

---

## Videos (Optional)

- **Demo Video**: 2-3 minute walkthrough
- **Architecture Overview**: Technical deep-dive
