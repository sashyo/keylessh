#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install TideSSP as a Windows Security Package.

.DESCRIPTION
    Copies TideSSP.dll to System32 and registers it as an LSA Security Package.
    A reboot (or restart of the RDP service) is required after installation.

.PARAMETER Uninstall
    Remove TideSSP from Security Packages and delete the DLL.

.PARAMETER DllPath
    Path to TideSSP.dll. If not specified, searches build/ subdirectories.
#>

param(
    [switch]$Uninstall,
    [string]$DllPath
)

$dllName = "TideSSP.dll"
$packageName = "TideSSP"
$system32 = "$env:SystemRoot\System32"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

if ($Uninstall) {
    Write-Host "Uninstalling TideSSP..." -ForegroundColor Yellow

    # Remove from Security Packages
    [string[]]$packages = (Get-ItemProperty $regPath).SecurityPackages
    [string[]]$filtered = $packages | Where-Object { $_ -ne $packageName }
    Set-ItemProperty $regPath -Name SecurityPackages -Value $filtered

    # Delete DLL
    $destDll = Join-Path $system32 $dllName
    if (Test-Path $destDll) {
        Remove-Item $destDll -Force
        Write-Host "Removed $destDll"
    }

    Write-Host "TideSSP uninstalled. Reboot to complete." -ForegroundColor Green
    return
}

# --- Install ---

# Find the built DLL
$sourceDll = $null

if ($DllPath) {
    $sourceDll = $DllPath
} else {
    # Determine script directory (works both as .ps1 file and pasted in terminal)
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

    foreach ($sub in @("build\Release", "build\Debug", "build", ".")) {
        $candidate = Join-Path $scriptDir (Join-Path $sub $dllName)
        if (Test-Path $candidate) {
            $sourceDll = $candidate
            break
        }
    }
}

if (-not $sourceDll -or -not (Test-Path $sourceDll)) {
    Write-Error "Cannot find $dllName. Either:"
    Write-Error "  1. Build first:  cmake -B build && cmake --build build --config Release"
    Write-Error "  2. Specify path: .\install.ps1 -DllPath C:\path\to\TideSSP.dll"
    return
}

# Copy to System32
$destDll = Join-Path $system32 $dllName
Write-Host "Copying $sourceDll -> $destDll"
Copy-Item $sourceDll $destDll -Force

# Register as Security Package (must be String[] for registry)
[string[]]$packages = (Get-ItemProperty $regPath).SecurityPackages
if ($packages -contains $packageName) {
    Write-Host "TideSSP already registered in Security Packages"
} else {
    [string[]]$packages += $packageName
    Set-ItemProperty $regPath -Name SecurityPackages -Value $packages
    Write-Host "Added TideSSP to Security Packages"
}

Write-Host ""
Write-Host "TideSSP installed. Reboot to activate." -ForegroundColor Green
Write-Host "After reboot, TideSSP will be available as a security package for RDP/CredSSP."
