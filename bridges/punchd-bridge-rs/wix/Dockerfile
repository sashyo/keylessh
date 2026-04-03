# escape=`

FROM mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2022

SHELL ["cmd", "/S", "/C"]

ARG VS_BUILDTOOLS_URI=https://aka.ms/vs/17/release/vs_buildtools.exe
ARG WIX_VERSION=6.0.2

ENV PATH="C:\Users\ContainerAdministrator\.dotnet\tools;C:\Program Files\dotnet;C:\Windows\System32;C:\Windows"

WORKDIR C:/TEMP

USER ContainerAdministrator
RUN setx /M TEMP "C:\TEMP" && setx /M TMP "C:\TEMP"

RUN echo Install Visual Studio Build Tools
RUN curl -SL --output C:\TEMP\vs_buildtools.exe %VS_BUILDTOOLS_URI% `
 && start /w C:\TEMP\vs_buildtools.exe --quiet --wait --norestart --nocache `
      --installPath "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools" `
      --add Microsoft.VisualStudio.Workload.VCTools `
      --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
      --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
 && if "%ERRORLEVEL%"=="3010" exit /b 0 `
 && if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL% `
 && del /q C:\TEMP\vs_buildtools.exe

RUN echo Install WiX
RUN dotnet tool install --global wix --version %WIX_VERSION% `
 && wix extension add --global WixToolset.UI.wixext/%WIX_VERSION%

RUN echo Prove the MSVC toolchain exists
RUN call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && where cl `
 && cl

RUN echo Generate build script
RUN > C:\build.cmd echo @echo off `
 && >> C:\build.cmd echo setlocal `
 && >> C:\build.cmd echo call "%%ProgramFiles(x86)%%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo cd /d C:\src `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo echo === Step 1: Compile custom actions DLL === `
 && >> C:\build.cmd echo cl /LD /O2 ca\PunchdCA.c ca\PunchdCA.def /Fe:ca\PunchdCA.dll /link msi.lib advapi32.lib shell32.lib user32.lib ole32.lib `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo echo === Step 2: Build MSI === `
 && >> C:\build.cmd echo wix build punchd-vpn.wxs -arch x64 -o punchd-vpn.msi `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo echo === Success === `
 && >> C:\build.cmd echo echo MSI output: C:\src\punchd-vpn.msi `
 && >> C:\build.cmd echo endlocal

WORKDIR C:/work

ENTRYPOINT ["cmd", "/S", "/C", "C:\\build.cmd"]
