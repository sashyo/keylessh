# escape=`

FROM mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2022

SHELL ["cmd", "/S", "/C"]

ARG VS_BUILDTOOLS_URI=https://aka.ms/vs/17/release/vs_buildtools.exe
ARG WIX_VERSION=6.0.2
ARG CMAKE_VERSION=4.3.0
ARG NINJA_VERSION=1.13.0

ENV PATH="C:\tools\cmake\bin;C:\tools\ninja;C:\Users\ContainerAdministrator\.dotnet\tools;C:\Program Files\dotnet;C:\Windows\System32;C:\Windows"

WORKDIR C:/TEMP

RUN echo shell-ok && where cmd && dotnet --info

RUN curl -SL --output C:\TEMP\vs_buildtools.exe %VS_BUILDTOOLS_URI% `
 && start /w C:\TEMP\vs_buildtools.exe --quiet --wait --norestart --nocache `
      --installPath "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools" `
      --add Microsoft.VisualStudio.Workload.VCTools `
      --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
      --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
 && if "%ERRORLEVEL%"=="3010" exit /b 0 `
 && if not "%ERRORLEVEL%"=="0" exit /b %ERRORLEVEL% `
 && del /q C:\TEMP\vs_buildtools.exe

RUN if not exist C:\tools mkdir C:\tools `
 && curl -SL --output C:\TEMP\cmake.zip https://github.com/Kitware/CMake/releases/download/v%CMAKE_VERSION%/cmake-%CMAKE_VERSION%-windows-x86_64.zip `
 && tar -xf C:\TEMP\cmake.zip -C C:\tools `
 && ren C:\tools\cmake-%CMAKE_VERSION%-windows-x86_64 cmake `
 && del /q C:\TEMP\cmake.zip

RUN if not exist C:\tools\ninja mkdir C:\tools\ninja `
 && curl -SL --output C:\TEMP\ninja.zip https://github.com/ninja-build/ninja/releases/download/v%NINJA_VERSION%/ninja-win.zip `
 && tar -xf C:\TEMP\ninja.zip -C C:\tools\ninja `
 && del /q C:\TEMP\ninja.zip

RUN where cmake && cmake --version && where ninja && ninja --version

RUN dotnet tool install --global wix --version %WIX_VERSION% `
 && wix extension add --global WixToolset.UI.wixext/%WIX_VERSION% `
 && wix extension add --global WixToolset.Util.wixext/%WIX_VERSION%

RUN dir "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools" `
 && dir "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" `
 && call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && where cl `
 && cl

WORKDIR C:/src
COPY . .

RUN if exist build rmdir /s /q build `
 && call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 `
 && call installer\build.bat

RUN if not exist C:\out mkdir C:\out `
 && if exist out xcopy /E /I /Y out C:\out `
 && if exist build\Release xcopy /E /I /Y build\Release C:\out

WORKDIR C:/out
CMD ["cmd", "/S", "/C", "dir C:\\out /s"]