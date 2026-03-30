@echo off
setlocal

REM ---------------------------------------------------------------
REM  Build TideWorkstation MSI (TideSSP + Punchd Gateway service)
REM
REM  Expects the repository root at C:\src:
REM    C:\src\tide-ssp\                   TideSSP driver
REM    C:\src\bridges\punchd-bridge-rs\   Punchd Gateway
REM
REM  Prerequisites (provided by the Docker image):
REM    - Visual Studio Build Tools (MSVC)
REM    - CMake, Ninja
REM    - WiX Toolset v6+
REM    - Rust toolchain (stable-x86_64-pc-windows-msvc)
REM    - NSSM at C:\tools\nssm\nssm.exe
REM ---------------------------------------------------------------

set "TIDESSP=%~dp0.."
set "PUNCHD=C:\src\bridges\punchd-bridge-rs"
set "BUILD=%TIDESSP%\build"
set "OUTDIR=%TIDESSP%\out"

echo === Step 1: Build TideSSP DLLs (TideSSP, TideSubAuth, TideCA) ===
cmake -B "%BUILD%" -S "%TIDESSP%" -A x64
if %errorlevel% neq 0 goto :fail
cmake --build "%BUILD%" --config Release
if %errorlevel% neq 0 goto :fail

echo.
echo === Step 2: Build punchd-bridge-rs ===
if not exist "%PUNCHD%\Cargo.toml" (
    echo ERROR: %PUNCHD%\Cargo.toml not found.
    echo Mount the repository root at C:\src.
    goto :fail
)
pushd "%PUNCHD%"
cargo build --release
if %errorlevel% neq 0 (popd & goto :fail)
popd

echo.
echo === Step 3: Build combined MSI ===
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

wix build "%TIDESSP%\installer\WorkstationProduct.wxs" ^
    -arch x64 ^
    -bindpath BinDir="%BUILD%\Release" ^
    -bindpath InstallerDir="%TIDESSP%\installer" ^
    -bindpath PunchdDir="%PUNCHD%\target\release" ^
    -bindpath NssmDir="C:\tools\nssm" ^
    -o "%OUTDIR%\TideWorkstation.msi"
if %errorlevel% neq 0 goto :fail
if not exist "%OUTDIR%\TideWorkstation.msi" (
    echo ERROR: MSI was not produced.
    goto :fail
)

echo.
echo === Success ===
echo MSI output: %OUTDIR%\TideWorkstation.msi
goto :eof

:fail
echo.
echo === BUILD FAILED ===
exit /b 1
