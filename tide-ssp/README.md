# TideSSP — KeyleSSH JWT Security Support Provider for Windows

A Windows Security Support Provider (SSP) that enables KeyleSSH Ed25519-based JWT authentication for RDP sessions, replacing traditional NTLM password-based auth.

This Windows driver will disable your Windows machine's RDP password authentication and will replace it with an exclusive KeyleSSH webRDP access. Unlike any other solution, this provides a firewall/NAT traversal method to RDP to your machine, using a web interface and a zero-knowledge authentication mechanism. 

## How it works

### Distributed (proxiing through a Punchd Gateway)

```
Browser -(RDP-over-WebRTC)-> Punchd Gateway -(RDP-over-TCP)-> Windows Machine
```


1. User initiate a request to RDP from KeyleSSH to an internal RDP endpoint (desktop)
2. User's browser (KeyleSSH client) establishes a WebRTP connection with that desktop's gateway
3. Gateway verifies KeyleSSH JWT access token and sends it to the desktop (via CredSSP/NLA)
4. The TideSSP driver on that desktops verifies the JWT's Ed25519 signature against the public key from the TideCloak config
5. TideSSP extracts the username from the JWT and creates a Windows logon session
6. The RDP desktop session starts without requiring a password

### Direct (Punchd workstation)

```
Browser -(RDP-over-WebRTC)-> Windows Machine
```

1. User initiate a request to RDP from KeyleSSH to an internal RDP endpoint (desktop)
2. User's browser (KeyleSSH client) establishes a WebRTP connection with that desktop
3. Desktop verifies KeyleSSH JWT access token and verifies its Ed25519 signature against the public key from the TideCloak config
4. TideSSP extracts the username from the JWT and creates a Windows logon session
5. The RDP desktop session starts without requiring a password


# Distributed deployment

## Configuration

TideSSP reads the TideCloak configuration (`tidecloak.json`) from the Windows System32 folder (at `%SystemRoot%\System32`).

The permanent Ed25519 public key is extracted from `jwk.keys[0].x` in the JSON at startup. If the realm's signing key is ever changed, update the file and reboot.

## Build (using specialized builder docker image)

This describes the process of building the TideSSP windows driver from source by first creating a specialized docker image with all the prerequisites, and then using that docker image to build the driver.

### Prerequisites

- Windows machine (Windows 10 or above, Windows server 2022 or above)
- Docker Desktop
- Windows-native docker build set on a Windows Container Engine (a setting on Docker Desktop)
- Git

### Get source code

Download this repo and set yourself in the tide-ssp folder:

```bash
git clone https://github.com/sashyo/keylessh.git
cd keylessh\tide-ssp
```

### Builder image preparation

```bash
docker build -m 4GB -t tidessp-builder .
```

This can take a very long time (5~50 minutes) so be patient. Once you have created the tidessp-builder image, you can run the next step (building the driver) as many times as you'd like.

### Build the driver in the docker

While still in the `keylessh\tide-ssp` directory, run the following:

```bash
docker run --rm -v "${PWD}:C:\src" tidessp-builder
```

You now have the driver in `./out/TideSSP.msi`

## Installation / Deployment

To use this driver on any win10+/Server2022+ machine, you need to copy 2 files:
1. The `TideSSP.msi` driver
2. The `tidecloak.json` adapter

For this example, we'll assume you copied those to `c:\tide`. After copying those 2 files you have 2 options on how to install it: GUI-assisted or CLI. Choose the most appropriate one for you.

### Option 1: Guided installation

Double click (or run `start c:\tide\TideSSP.msi`) the driver installer and follow prompt.

### Option 2: CLI installation

For quick, no-UI installation (especially on servers without UI), follow these steps using elevated `PowerShell` console:

> [!CAUTION]
> This is a quiet installation that will immediately restart your machine upon successful installation.

```powershell
cd c:\tide
msiexec /i "C:\tide\TideSSP.msi" /qn TIDE_CONFIG_FILE="C:\tide\tidecloak.json" /L*V "C:\tide\tidessp.log"
```

A saucerful installation will copy `TideSSP.dll` and `tidecloak.json` (+few others) to your `System32` folder.

### Changing the TideCloak adapter

If you need to change the adaptor settings, simple update the `%SystemRoot%\System32\tidecloak.json` file and restart your Windows machine.

### Uninstalling TideSSP

To uninstall the driver from the Windows machine, you can use the standard add/remove option in your desktop, or use this direct CLI method:

```powershell
$app=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -eq "TideSSP" } | Select-Object -First 1; if(-not $app){throw "TideSSP is not installed."}; $productCode=if($app.PSChildName -match '^\{[0-9A-Fa-f-]+\}$'){$app.PSChildName}else{([regex]::Match($app.UninstallString,'\{[0-9A-Fa-f-]+\}')).Value}; if(-not $productCode){throw "Could not determine TideSSP product code."}; $p=Start-Process msiexec.exe -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru; if($p.ExitCode -eq 3010){Write-Host "TideSSP was uninstalled. A reboot is required."}elseif($p.ExitCode -eq 0){Write-Host "TideSSP was uninstalled successfully."}else{throw "Uninstall failed with exit code $($p.ExitCode)."}
```

# Direct deployment

## Configuration

The TideCloak configuration (`tidecloak.json`) and the KeyleSSH configuration (`gateway.toml`) reside in the Windows service folder (at `"%ProgramFiles%\PunchdGateway"`).

The permanent Ed25519 public key is extracted from `jwk.keys[0].x` in the JSON at startup. If the realm's signing key is ever changed, update the file and reboot.

## Build (using specialized builder docker image)

This describes the process of building the PunchdEndpoint windows service installer from source by first creating a specialized docker image with all the prerequisites, and then using that docker image to build the driver.

Follow the exact same instructions to build the **specialized builder docker** image for the _Distributed deployement_ above.

> [!INFORMATION]
> If you already built the **specialized builder docker** image for the _Distributed deployement_ earlier, you can use the exact same image. You don't need to build it again.

### Build the PunchdEndpoint installer in the docker

While still in the `keylessh\tide-ssp` directory, run the following:

```bash
docker run --rm -v "${PWD}\..\:C:\src" --entrypoint cmd tidessp-builder /S /C C:\workstationbuild.cmd
```

You now have the driver in `./out/PunchdEndpoint.msi`

## Installation / Deployment

To use this driver on any win10+/Server2022+ machine, you need to copy 3 files:
1. The `PunchdEndpoint.msi` driver
2. The `tidecloak.json` adapter
3. A `gateway.toml` config file

For this example, we'll assume you copied those to `c:\tide`. After copying those 3 files, you have 2 options on how to install it: GUI-assisted or CLI. Choose the most appropriate one for you.

### Option 1: Guided installation

Double click (or run `start c:\tide\PunchdEndpoint.msi`) the driver installer and follow prompt.

### Option 2: CLI installation

For quick, no-UI installation (especially on servers without UI), follow these steps using elevated `PowerShell` console:

> [!CAUTION]
> This is a quiet installation that will immediately restart your machine upon successful installation.

```powershell
cd c:\tide
msiexec /i "PunchdEndpoint.msi" /qn TIDE_CONFIG_FILE="C:\tide\tidecloak.json" GATEWAY_CONFIG_FILE="C:\tide\gateway.toml" /L*V "tideEP.log"
```

A successful installation will copy `TideSSP.dll` and `tidecloak.json` (+few others) to your `System32` folder, and will create a new folder `"%ProgramFiles%\PunchdGateway"`, populate it with binaries and register a windows service named `PunchdGateway` to run automatically when the machine loads.

### Changing the TideCloak adapter

If you need to change the adaptor settings, simple update the `%SystemRoot%\System32\tidecloak.json` file, the `"%ProgramFiles%\PunchdGateway\gateway.toml"`, the `"%ProgramFiles%\PunchdGateway\tidecloak.json"` and restart your Windows machine.



### Uninstalling the Punchd Endpoint service

To uninstall the driver from the Windows machine, you can use the standard add/remove option in your desktop, or use this direct CLI method:

```powershell
$app=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -eq "PunchdEndpoint" } | Select-Object -First 1; if(-not $app){throw "PunchdEndpoint is not installed."}; $productCode=if($app.PSChildName -match '^\{[0-9A-Fa-f-]+\}$'){$app.PSChildName}else{([regex]::Match($app.UninstallString,'\{[0-9A-Fa-f-]+\}')).Value}; if(-not $productCode){throw "Could not determine PunchdEndpoint product code."}; $p=Start-Process msiexec.exe -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru; if($p.ExitCode -eq 3010){Write-Host "PunchdEndpoint was uninstalled. A reboot is required."}elseif($p.ExitCode -eq 0){Write-Host "PunchdEndpoint was uninstalled successfully."}else{throw "Uninstall failed with exit code $($p.ExitCode)."}
```


---

# Misc

## Build from source locally

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
