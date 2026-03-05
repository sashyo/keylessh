#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install TideSSP + TideSubAuth for passwordless RDP.

.DESCRIPTION
    Copies TideSSP.dll and TideSubAuth.dll to System32, registers TideSSP
    as an LSA Security Package and TideSubAuth as an MSV1_0 subauthentication
    package.  A reboot is required after installation.

.PARAMETER Uninstall
    Remove TideSSP and TideSubAuth and clean up registry entries.

.PARAMETER DllPath
    Path to TideSSP.dll. If not specified, searches build/ subdirectories.

.PARAMETER Username
    Local username to enable SubAuth for (sets UF_MNS_LOGON_ACCOUNT).
    If not specified, uses the current user.
#>

param(
    [switch]$Uninstall,
    [string]$DllPath,
    [string]$Username = $env:USERNAME
)

$dllName = "TideSSP.dll"
$subAuthDllName = "TideSubAuth.dll"
$packageName = "TideSSP"
$system32 = "$env:SystemRoot\System32"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$msv1_0Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

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

# Set UF_MNS_LOGON_ACCOUNT on the target user so MSV1_0 calls SubAuth
# for interactive logons (including RDP)
try {
    $user = [ADSI]"WinNT://./$Username,user"
    $flags = $user.UserFlags.Value
    $UF_MNS = 0x20000
    if (($flags -band $UF_MNS) -eq 0) {
        $user.UserFlags.Value = $flags -bor $UF_MNS
        $user.SetInfo()
        Write-Host "Set UF_MNS_LOGON_ACCOUNT on user '$Username'"
    } else {
        Write-Host "UF_MNS_LOGON_ACCOUNT already set on '$Username'"
    }
} catch {
    Write-Warning "Could not set UF_MNS_LOGON_ACCOUNT on '$Username': $_"
    Write-Warning "SubAuth may not be called for interactive logons."
}

Write-Host ""
Write-Host "TideSSP + TideSubAuth installed. Reboot to activate." -ForegroundColor Green
Write-Host "After reboot, RDP logons via the gateway will be passwordless."
