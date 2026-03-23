# TideSSP — Ed25519 Security Support Provider for Windows

A Windows Security Support Provider (SSP) that enables Ed25519-based authentication for RDP sessions, replacing traditional NTLM password-based auth.

## How it works

1. Gateway sends the JWT access token to TideSSP via CredSSP/NLA
2. TideSSP verifies the Ed25519 signature against the public key from the TideCloak config
3. TideSSP extracts the username from the JWT and creates a Windows logon session
4. The RDP desktop session starts without requiring a password

## Configuration

TideSSP reads the TideCloak configuration (`tidecloak.json`) from the Windows registry at:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\TideSSP\Config (REG_SZ)
```

The Ed25519 public key is extracted from `jwk.keys[0].x` in the JSON at startup. If the realm's signing key is rotated, update the registry value and reboot.

## Build

Requires Windows with MSVC (Visual Studio Build Tools).

```powershell
cmake -B build
cmake --build build --config Release
```

## Install

### Option A: MSI Installer

Build the MSI (requires [WiX Toolset v4+](https://wixtoolset.org/) and a Developer Command Prompt):

```powershell
installer\build.bat
```

Install with the path to your `tidecloak.json`:

```powershell
msiexec /i installer\out\TideSSP.msi TIDE_CONFIG_FILE="C:\path\to\tidecloak.json"
```

Or pass the JSON content directly:

```powershell
msiexec /i installer\out\TideSSP.msi TIDE_CONFIG="{\"realm\":\"myrealm\",...}"
```

To uninstall, use **Add/Remove Programs** or `msiexec /x TideSSP.msi`.

### Option B: Manual (PowerShell)

Run as Administrator:

```powershell
.\install.ps1 -ConfigFile C:\path\to\tidecloak.json
```

The script auto-discovers `tidecloak.json` in common locations if `-ConfigFile` is not specified.

Then reboot.

To uninstall manually:

```powershell
.\install.ps1 -Uninstall
```

Then reboot.

## Updating the Public Key

If the TideCloak realm signing key is rotated:

1. Export a new `tidecloak.json` from TideCloak admin console
2. Update the registry:
   ```powershell
   $json = Get-Content tidecloak.json -Raw
   Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\TideSSP" -Name "Config" -Value $json
   ```
3. Reboot (the SSP reads the key once at LSA startup)

## Wire Protocol

```
TOKEN_JWT (client → server):
  [0x04][JWT bytes (ASCII)]
```

TideSSP verifies the JWT's Ed25519 signature, checks expiry, extracts `preferred_username`, and creates a logon session via S4U.

## Security

- Ed25519 verification uses TweetNaCl (public domain, no external dependencies)
- Private key never exists in full — TideCloak threshold cryptography splits it across ORK nodes
- SSP runs in LSA context within standard Windows security boundaries
- Public key is configurable at install time — no recompilation needed for key rotation
