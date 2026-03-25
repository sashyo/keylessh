# escape=`

FROM mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2022

SHELL ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

ARG VS_BUILDTOOLS_URI=https://aka.ms/vs/17/release/vs_BuildTools.exe
ARG WIX_VERSION=4.0.5

ENV VSINSTALLDIR="C:\\BuildTools" `
    PATH="C:\\BuildTools\\MSBuild\\Current\\Bin;C:\\BuildTools\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin;C:\\BuildTools\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\Ninja;C:\\Users\\ContainerAdministrator\\.dotnet\\tools;C:\\Program Files\\dotnet;C:\\Windows\\System32;C:\\Windows"

WORKDIR C:\\temp

# Install only the native build toolchain you need
RUN $ErrorActionPreference = 'Stop'; `
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
    Invoke-WebRequest -Uri $env:VS_BUILDTOOLS_URI -OutFile vs_BuildTools.exe; `
    Start-Process -FilePath .\vs_BuildTools.exe -ArgumentList `
      '--quiet', '--wait', '--norestart', '--nocache', `
      '--installPath', 'C:\BuildTools', `
      '--add', 'Microsoft.VisualStudio.Workload.VCTools', `
      '--add', 'Microsoft.VisualStudio.Component.VC.CMake.Project', `
      '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.22621' `
      -NoNewWindow -Wait; `
    if ($LASTEXITCODE -ne 0) { throw \"VS Build Tools install failed with exit code $LASTEXITCODE\" }; `
    Remove-Item .\vs_BuildTools.exe -Force

# Install WiX v4 as a dotnet global tool
RUN $ErrorActionPreference = 'Stop'; `
    dotnet tool install --global wix --version $env:WIX_VERSION; `
    wix extension add WixToolset.UI.wixext; `
    wix extension add WixToolset.Util.wixext

WORKDIR C:\\src
COPY . .

# Build project and installer
RUN $ErrorActionPreference = 'Stop'; `
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release; `
    cmake --build build --config Release; `
    if (!(Test-Path 'installer\build.bat')) { throw 'installer\build.bat not found'; }; `
    cmd /S /C installer\build.bat

# Gather outputs
RUN $ErrorActionPreference = 'Stop'; `
    New-Item -ItemType Directory -Force -Path C:\out | Out-Null; `
    if (Test-Path 'installer\out') { Copy-Item 'installer\out\*' 'C:\out\' -Recurse -Force; }; `
    if (Test-Path 'build\Release') { Copy-Item 'build\Release\*' 'C:\out\' -Recurse -Force; }

WORKDIR C:\\out
CMD ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", "Get-ChildItem -Recurse C:\\out"]