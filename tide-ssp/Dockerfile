# escape=`

FROM mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2022

SHELL ["cmd", "/S", "/C"]

ARG VS_BUILDTOOLS_URI=https://aka.ms/vs/17/release/vs_buildtools.exe
ARG WIX_VERSION=6.0.2
ARG CMAKE_VERSION=4.3.0
ARG NINJA_VERSION=1.13.0

ENV PATH="C:\Users\ContainerAdministrator\.cargo\bin;C:\tools\cmake\bin;C:\tools\ninja;C:\Users\ContainerAdministrator\.dotnet\tools;C:\Program Files\dotnet;C:\Windows\System32;C:\Windows"

WORKDIR C:/TEMP

RUN echo shell-ok && where cmd && dotnet --info

USER ContainerAdministrator
RUN setx /M TEMP "C:\TEMP" && setx /M TMP "C:\TEMP"

RUN echo Install Visual Studio Build Tools - this is the command shape that worked
RUN curl -SL --output C:\TEMP\vs_buildtools.exe %VS_BUILDTOOLS_URI% `
 && start /w C:\TEMP\vs_buildtools.exe --quiet --wait --norestart --nocache `
      --installPath "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools" `
      --add Microsoft.VisualStudio.Workload.VCTools `
      --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
      --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
 && if "%ERRORLEVEL%"=="3010" exit /b 0 `
 && if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL% `
 && del /q C:\TEMP\vs_buildtools.exe

RUN echo Install CMake
RUN if not exist C:\tools mkdir C:\tools `
 && curl -SL --output C:\TEMP\cmake.zip https://github.com/Kitware/CMake/releases/download/v%CMAKE_VERSION%/cmake-%CMAKE_VERSION%-windows-x86_64.zip `
 && tar -xf C:\TEMP\cmake.zip -C C:\tools `
 && ren C:\tools\cmake-%CMAKE_VERSION%-windows-x86_64 cmake `
 && del /q C:\TEMP\cmake.zip

RUN echo Install Ninja
RUN if not exist C:\tools\ninja mkdir C:\tools\ninja `
 && curl -SL --output C:\TEMP\ninja.zip https://github.com/ninja-build/ninja/releases/download/v%NINJA_VERSION%/ninja-win.zip `
 && tar -xf C:\TEMP\ninja.zip -C C:\tools\ninja `
 && del /q C:\TEMP\ninja.zip

RUN where cmake && cmake --version && where ninja && ninja --version

RUN echo Install WiX
RUN dotnet tool install --global wix --version %WIX_VERSION% `
 && wix extension add --global WixToolset.UI.wixext/%WIX_VERSION% `
 && wix extension add --global WixToolset.Util.wixext/%WIX_VERSION%

RUN echo Install Rust toolchain
RUN curl -SL --output C:\TEMP\rustup-init.exe https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe `
 && C:\TEMP\rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-msvc `
 && del /q C:\TEMP\rustup-init.exe
RUN rustc --version && cargo --version

RUN echo Download WinSW (service wrapper)
ARG WINSW_VERSION=v2.12.0
RUN if not exist C:\tools\winsw mkdir C:\tools\winsw `
 && curl -SL -o C:\tools\winsw\WinSW-x64.exe https://github.com/winsw/winsw/releases/download/%WINSW_VERSION%/WinSW-x64.exe

RUN echo Prove the MSVC toolchain exists
RUN dir "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools" `
 && dir "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" `
 && call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && where cl `
 && cl

RUN echo Generate runtime build scripts inside the image

RUN echo --- build.cmd: TideSSP only (mount tide-ssp at C:\src) ---
RUN > C:\build.cmd echo @echo off `
 && >> C:\build.cmd echo setlocal `
 && >> C:\build.cmd echo call "%%ProgramFiles(x86)%%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo cd /d C:\src `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo if exist build rmdir /s /q build `
 && >> C:\build.cmd echo call installer\build.bat `
 && >> C:\build.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\build.cmd echo endlocal

RUN echo --- workstationbuild.cmd: TideSSP + PunchdEndpoint (mount repo root at C:\src) ---
RUN > C:\workstationbuild.cmd echo @echo off `
 && >> C:\workstationbuild.cmd echo setlocal `
 && >> C:\workstationbuild.cmd echo call "%%ProgramFiles(x86)%%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && >> C:\workstationbuild.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\workstationbuild.cmd echo cd /d C:\src\tide-ssp `
 && >> C:\workstationbuild.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\workstationbuild.cmd echo if exist build rmdir /s /q build `
 && >> C:\workstationbuild.cmd echo call installer\workstationbuild.bat `
 && >> C:\workstationbuild.cmd echo if errorlevel 1 exit /b %%errorlevel%% `
 && >> C:\workstationbuild.cmd echo endlocal

WORKDIR C:/work

ENTRYPOINT ["cmd", "/S", "/C", "C:\\build.cmd"]