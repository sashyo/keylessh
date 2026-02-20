# KeyleSSH Azure Marketplace Listing Content

Use this content when creating the marketplace listing in Partner Center.

---

## Offer Details

### Offer Name
KeyleSSH - Decentralized SSH Privileged Access Management

### Short Description (100 chars max)
Revolutionary SSH PAM with decentralized keys. No single point of failure. Access anywhere, securely.

### Long Description

**KeyleSSH** revolutionizes SSH Privileged Access Management (PAM) by eliminating the fundamental security flaws of traditional approaches. Powered by Tide Protocol's decentralized cryptography, KeyleSSH delivers what no other PAM solution can: **true zero-trust with no god-mode access**.

---

## Why KeyleSSH Changes Everything

### 🔐 Decentralized Key Management by Tide Protocol

Traditional PAM solutions store master keys in a central vault—creating a honey pot for attackers and a single point of compromise. **KeyleSSH is different.**

- **No Central Key Storage** - Private keys are cryptographically split across Tide's decentralized network of ORKs (Orchestrated Recluders of Keys)
- **Keys Never Exist in One Place** - Not on your servers, not in a vault, not anywhere
- **Mathematically Impossible to Steal** - Even if attackers breach your infrastructure, there's no key to steal
- **No Insider Threat** - System administrators cannot extract or misuse credentials

### 🌍 Access Your Servers Anywhere, Anytime—Securely

Work from anywhere without compromising security:

- **Browser-Based SSH Terminal** - Connect to any server from any device with just a web browser
- **No VPN Required** - Secure WebSocket tunneling through the TCP Bridge
- **Zero Client Installation** - Nothing to install, configure, or maintain on end-user devices
- **Session Continuity** - Reconnect seamlessly if your connection drops
- **Full Session Recording** - Every keystroke captured for compliance and audit

### 👥 Quorum-Based Access Control—No God-Mode

**The end of all-powerful admin accounts.** KeyleSSH enforces cryptographic policies that require multiple parties to approve sensitive access:

- **Multi-Party Authorization** - Critical access requires approval from multiple administrators
- **No Single Point of God-Like Access** - No individual can grant themselves unlimited privileges
- **Cryptographic Policy Enforcement** - Access rules enforced by Forseti smart contracts, not just software checks
- **Immutable Audit Trail** - Every access decision is cryptographically signed and recorded
- **Separation of Duties** - Built-in enforcement of security best practices

---

## Key Features

| Feature | Traditional PAM | KeyleSSH |
|---------|----------------|----------|
| Key Storage | Centralized vault | Decentralized (no vault) |
| Admin Override | Yes (god mode) | No (quorum required) |
| Key Theft Risk | High | Mathematically impossible |
| Access From | VPN/Corporate network | Anywhere (browser) |
| Client Software | Required | None |
| Insider Threat | Vulnerable | Protected |

---

## How It Works

1. **Authenticate** - Users login via TideCloak using decentralized identity
2. **Request Access** - Select target server and role
3. **Quorum Approval** - If required, designated approvers authorize the session
4. **Cryptographic Signing** - Tide ORKs collaboratively sign the session credential
5. **Connect** - Secure WebSocket tunnel established to SSH server
6. **Audit** - Full session recorded for compliance review

---

## Architecture

- **KeyleSSH App** - Web UI for server management, user access, and session playback
- **TCP Bridge** - Horizontally scalable WebSocket-to-SSH bridge (auto-scales to 100+ instances)
- **Tide ORK Network** - Decentralized key management (no infrastructure to manage)
- **Azure Files** - Persistent storage for configuration and session recordings

---

## Perfect For

- **Enterprises** eliminating privileged access risks
- **Financial Services** requiring multi-party authorization
- **Healthcare** with HIPAA compliance requirements
- **Government** with zero-trust mandates
- **MSPs** managing multiple client environments securely
- **Any organization** wanting to eliminate the "keys to the kingdom" problem

---

## Security Certifications & Compliance

KeyleSSH helps you meet:
- SOC 2 Type II
- HIPAA
- PCI-DSS
- NIST 800-53
- Zero Trust Architecture requirements

---

### Search Keywords
SSH, PAM, privileged access management, decentralized, zero trust, passwordless, quorum, multi-party authorization, Tide Protocol, key management, compliance, audit, session recording, browser SSH

---

## Categories

- **Primary**: Security → Identity & Access Management
- **Secondary**: IT & Management Tools → Management & Monitoring

---

## Pricing

### Bring Your Own License (BYOL)
Deploy on your Azure infrastructure. Pay only for Azure consumption.

**Estimated Monthly Cost:**
- Container Apps: ~$20-50/month (depending on usage)
- Storage Account: ~$1-5/month
- Total: ~$25-55/month for small deployments

Enterprise licensing available for advanced features and support.

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
2. **Dashboard** - Server list and connection status
3. **Terminal** - Web-based SSH session in action
4. **Access Request** - Quorum approval workflow
5. **User Management** - Admin panel for users and roles
6. **Session Recording** - Audit playback feature
7. **Architecture Diagram** - Decentralized security overview

---

## Logos

1. **Small Logo**: 48x48 PNG ✅ `logo-48x48.png`
2. **Large Logo**: 216x216 PNG ✅ `logo-216x216.png`
3. **Wide Logo**: 255x115 PNG (optional)

---

## Videos (Optional)

- **Demo Video**: 2-3 minute walkthrough showing browser SSH access
- **Security Deep-Dive**: How decentralized keys eliminate the vault problem
- **Quorum Demo**: Multi-party authorization in action
