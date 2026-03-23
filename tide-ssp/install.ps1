#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install TideSSP + TideSubAuth for passwordless RDP.

.DESCRIPTION
    Copies TideSSP.dll and TideSubAuth.dll to System32, registers TideSSP
    as an LSA Security Package and TideSubAuth as an MSV1_0 subauthentication
    package, and writes the TideCloak config to the registry.
    A reboot is required after installation.

.PARAMETER Uninstall
    Remove TideSSP and TideSubAuth and clean up registry entries.

.PARAMETER DllPath
    Path to TideSSP.dll. If not specified, searches build/ subdirectories.

.PARAMETER ConfigFile
    Path to tidecloak.json. Required on install. The JSON is stored in the
    registry and TideSSP reads the Ed25519 public key from it at startup.

#>

param(
    [switch]$Uninstall,
    [string]$DllPath,
    [string]$ConfigFile
)

$dllName = "TideSSP.dll"
$subAuthDllName = "TideSubAuth.dll"
$packageName = "TideSSP"
$system32 = "$env:SystemRoot\System32"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$msv1_0Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$tideSspRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\TideSSP"

if ($Uninstall) {
    Write-Host "Uninstalling TideSSP + TideSubAuth..." -ForegroundColor Yellow

    # Remove from Security Packages
    [string[]]$packages = (Get-ItemProperty $regPath).SecurityPackages
    [string[]]$filtered = $packages | Where-Object { $_ -ne $packageName }
    Set-ItemProperty $regPath -Name SecurityPackages -Value $filtered

    # Remove SubAuth registration
    if (Test-Path $msv1_0Path) {
        Remove-ItemProperty $msv1_0Path -Name "Auth0" -ErrorAction SilentlyContinue
    }

    # Remove TideSSP config from registry
    if (Test-Path $tideSspRegPath) {
        Remove-Item $tideSspRegPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed TideSSP registry config"
    }

    # Clear UF_MNS_LOGON_ACCOUNT from all local users (in case it was left set)
    $UF_MNS = 0x20000
    Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
        try {
            $u = [ADSI]"WinNT://./$($_.Name),user"
            if ($u.UserFlags.Value -band $UF_MNS) {
                $u.UserFlags.Value = $u.UserFlags.Value -band (-bnot $UF_MNS)
                $u.SetInfo()
                Write-Host "Cleared UF_MNS_LOGON_ACCOUNT on '$($_.Name)'"
            }
        } catch {}
    }

    # Delete DLLs
    foreach ($dll in @($dllName, $subAuthDllName)) {
        $dest = Join-Path $system32 $dll
        if (Test-Path $dest) {
            Remove-Item $dest -Force
            Write-Host "Removed $dest"
        }
    }

    Write-Host "TideSSP uninstalled. Reboot to complete." -ForegroundColor Green
    return
}

# --- Install ---

# Validate ConfigFile
if (-not $ConfigFile) {
    # Try default locations
    $scriptDir0 = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    foreach ($candidate in @(
        (Join-Path $scriptDir0 "tidecloak.json"),
        (Join-Path $scriptDir0 "..\data\tidecloak.json"),
        (Join-Path $scriptDir0 "data\tidecloak.json")
    )) {
        if (Test-Path $candidate) {
            $ConfigFile = $candidate
            break
        }
    }
}

if (-not $ConfigFile -or -not (Test-Path $ConfigFile)) {
    Write-Error "tidecloak.json is required. Use -ConfigFile <path> to specify the TideCloak configuration file."
    return
}

$configJson = Get-Content $ConfigFile -Raw
Write-Host "Using TideCloak config: $ConfigFile"

# Write config to registry
if (-not (Test-Path $tideSspRegPath)) {
    New-Item -Path $tideSspRegPath -Force | Out-Null
}
Set-ItemProperty $tideSspRegPath -Name "Config" -Value $configJson -Type String
Write-Host "Wrote TideCloak config to registry ($($configJson.Length) chars)"

# Determine script directory
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

# Find and copy both DLLs
foreach ($dll in @($dllName, $subAuthDllName)) {
    $sourceDll = $null
    if ($DllPath -and $dll -eq $dllName) {
        $sourceDll = $DllPath
    } else {
        foreach ($sub in @("build\Release", "build\Debug", "build", ".")) {
            $candidate = Join-Path $scriptDir (Join-Path $sub $dll)
            if (Test-Path $candidate) {
                $sourceDll = $candidate
                break
            }
        }
    }

    if (-not $sourceDll -or -not (Test-Path $sourceDll)) {
        Write-Error "Cannot find $dll. Build first: cmake -B build && cmake --build build --config Release"
        return
    }

    $destDll = Join-Path $system32 $dll
    Write-Host "Copying $sourceDll -> $destDll"
    Copy-Item $sourceDll $destDll -Force
}

# Register TideSSP as Security Package
[string[]]$packages = (Get-ItemProperty $regPath).SecurityPackages
if ($packages -contains $packageName) {
    Write-Host "TideSSP already registered in Security Packages"
} else {
    [string[]]$packages += $packageName
    Set-ItemProperty $regPath -Name SecurityPackages -Value $packages
    Write-Host "Added TideSSP to Security Packages"
}

# Register TideSubAuth as MSV1_0 SubAuth package 0
if (-not (Test-Path $msv1_0Path)) {
    New-Item -Path $msv1_0Path -Force | Out-Null
}
Set-ItemProperty $msv1_0Path -Name "Auth0" -Value "TideSubAuth" -Type String
Write-Host "Registered TideSubAuth as MSV1_0\Auth0"

Write-Host ""
Write-Host "TideSSP + TideSubAuth installed. Reboot to activate." -ForegroundColor Green
Write-Host "UF_MNS_LOGON_ACCOUNT is toggled dynamically by TideSSP/SubAuth - no manual setup needed."
Write-Host "After reboot, RDP logons via the gateway will be passwordless."
