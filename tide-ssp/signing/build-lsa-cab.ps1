<#
.SYNOPSIS
    Package the TideSSP LSA binaries into a signed CAB for Microsoft's file
    signing service.

.DESCRIPTION
    LSA Protection (RunAsPPL) only loads modules carrying a Microsoft signature.
    An EV code-signing certificate cannot produce one: it authenticates your
    Partner Center account and signs the submission, and Microsoft signs the
    binaries. See:
      https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-manage

    Submissions must be a single signed CAB containing every file to be signed,
    so this packages TideSSP.dll and TideSubAuth.dll — the two DLLs that load
    into LSASS. TideCA.dll is deliberately excluded: it is an MSI custom action
    that runs in msiexec, never in LSA, so your EV signature is sufficient for it.

    The DLLs go in unsigned. Microsoft signs them and returns them; rebuild the
    MSI around the returned files and do not re-sign them, or their signature
    breaks and LSA rejects them again.

.PARAMETER BinDir
    Directory holding the built DLLs. Defaults to the CMake Release output.

.PARAMETER OutDir
    Where to write the CAB.

.PARAMETER Thumbprint
    SHA1 thumbprint of the EV certificate to sign the CAB with. If omitted,
    signtool picks a certificate automatically (/a).

.PARAMETER TimestampUrl
    RFC 3161 timestamp server.

.PARAMETER SkipSign
    Build the CAB but do not sign it — useful for inspecting the contents first.

.EXAMPLE
    .\build-lsa-cab.ps1
    .\build-lsa-cab.ps1 -Thumbprint A1B2C3... -OutDir C:\submissions
#>

[CmdletBinding()]
param(
    [string]$BinDir = (Join-Path $PSScriptRoot "..\build\Release"),
    [string]$OutDir = (Join-Path $PSScriptRoot "..\out\signing"),
    [string]$Thumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SkipSign
)

$ErrorActionPreference = "Stop"

# Only files that load into LSASS belong here.
$LsaBinaries = @("TideSSP.dll", "TideSubAuth.dll")
$CabName = "TideSSP-LSA.cab"

function Resolve-Tool([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # signtool lives in the Windows SDK rather than on PATH by default.
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    ) | Where-Object { Test-Path $_ }

    foreach ($root in $roots) {
        $found = Get-ChildItem -Path $root -Filter $name -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -match "\\x64\\" } |
                 Sort-Object FullName -Descending |
                 Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "$name not found. Install the Windows SDK, or run from a Developer Command Prompt."
}

$BinDir = (Resolve-Path $BinDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# ── Check the inputs before building anything ──────────────────────

$missing = $LsaBinaries | Where-Object { -not (Test-Path (Join-Path $BinDir $_)) }
if ($missing) {
    throw "Missing from ${BinDir}: $($missing -join ', '). Build first: cmake --build build --config Release"
}

Write-Host "Packaging for Microsoft LSA signing" -ForegroundColor Cyan
foreach ($dll in $LsaBinaries) {
    $path = Join-Path $BinDir $dll
    $item = Get-Item $path

    # A file already carrying your Authenticode signature is a sign the wrong
    # build is being submitted — Microsoft's signature is what LSA checks.
    $sig = Get-AuthenticodeSignature $path
    $sigNote = if ($sig.Status -eq "NotSigned") { "unsigned" } else { "ALREADY SIGNED ($($sig.Status))" }

    Write-Host ("  {0,-20} {1,10:N0} bytes  {2}" -f $dll, $item.Length, $sigNote)
    if ($sig.Status -ne "NotSigned") {
        Write-Warning "$dll is already signed. Submit unsigned binaries — Microsoft's signature is the one LSA requires."
    }
}

# ── Build the CAB ──────────────────────────────────────────────────

# makecab is driven by a directive file. Generated here so paths are absolute
# and correct regardless of where this is run from.
$ddfPath = Join-Path $OutDir "TideSSP-LSA.ddf"
$ddf = @"
.OPTION EXPLICIT
.Set CabinetNameTemplate=$CabName
.Set DiskDirectory1=$OutDir
.Set CompressionType=MSZIP
.Set Cabinet=on
.Set Compress=on
; A submission must be one cabinet, so disable every size and count limit
; that would otherwise cause makecab to split the output.
.Set MaxDiskSize=0
.Set MaxCabinetSize=0
.Set MaxDiskFileCount=0
.Set CabinetFileCountThreshold=0
.Set FolderFileCountThreshold=0
.Set FolderSizeThreshold=0
.Set DestinationDir=TideSSP
"@
foreach ($dll in $LsaBinaries) {
    $ddf += "`n`"$(Join-Path $BinDir $dll)`""
}
Set-Content -Path $ddfPath -Value $ddf -Encoding ASCII

$cabPath = Join-Path $OutDir $CabName
Remove-Item $cabPath -ErrorAction SilentlyContinue

Write-Host "`nBuilding $CabName..." -ForegroundColor Cyan
$makecab = Resolve-Tool "makecab.exe"
& $makecab /F $ddfPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makecab failed with exit code $LASTEXITCODE" }
if (-not (Test-Path $cabPath)) { throw "makecab reported success but $cabPath does not exist" }

# makecab leaves these behind next to the working directory.
Remove-Item (Join-Path $OutDir "setup.inf"), (Join-Path $OutDir "setup.rpt") -ErrorAction SilentlyContinue

Write-Host "  $cabPath ($((Get-Item $cabPath).Length) bytes)" -ForegroundColor Green

# ── Sign it ────────────────────────────────────────────────────────

if ($SkipSign) {
    Write-Host "`nSkipping signing (-SkipSign). Sign before submitting:" -ForegroundColor Yellow
    Write-Host "  signtool sign /fd sha256 /a /tr $TimestampUrl /td sha256 `"$cabPath`""
    return
}

$signtool = Resolve-Tool "signtool.exe"
$signArgs = @("sign", "/fd", "sha256", "/tr", $TimestampUrl, "/td", "sha256", "/v")
if ($Thumbprint) { $signArgs += @("/sha1", $Thumbprint) } else { $signArgs += "/a" }
$signArgs += $cabPath

Write-Host "`nSigning with your EV certificate..." -ForegroundColor Cyan
& $signtool @signArgs
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE" }

& $signtool verify /pa /v $cabPath
if ($LASTEXITCODE -ne 0) { throw "Signature verification failed" }

Write-Host "`nReady to submit:" -ForegroundColor Green
Write-Host "  $cabPath"
Write-Host @"

Next steps:
  1. Partner Center -> Hardware -> Submit new hardware, and upload this CAB.
  2. Microsoft returns the signed DLLs.
  3. Rebuild the MSI against the returned files. Do not re-sign them — that
     replaces Microsoft's signature and LSA will reject them again.
"@
