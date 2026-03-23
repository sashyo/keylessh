@echo off
setlocal

REM ---------------------------------------------------------------
REM  Build TideSSP MSI installer
REM
REM  Prerequisites:
REM    - Visual Studio Build Tools
REM    - CMake (included with VS "C++ CMake tools" component)
REM    - WiX Toolset v6+  (dotnet tool install --global wix)
REM ---------------------------------------------------------------

pushd "%~dp0.."
set "ROOT=%CD%"
popd

set "BUILD=%ROOT%\build"
set "OUTDIR=%ROOT%\out"

echo === Step 1: Build all DLLs (TideSSP, TideSubAuth, TideCA) ===
cmake -B "%BUILD%" -S "%ROOT%" -A x64
if %errorlevel% neq 0 goto :fail
cmake --build "%BUILD%" --config Release
if %errorlevel% neq 0 goto :fail

echo.
echo === Step 2: Build MSI ===
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

wix build "%ROOT%\installer\Product.wxs" ^
    -arch x64 ^
    -bindpath BinDir="%BUILD%\Release" ^
    -bindpath InstallerDir="%ROOT%\installer" ^
    -o "%OUTDIR%\TideSSP.msi"
if %errorlevel% neq 0 goto :fail
if not exist "%OUTDIR%\TideSSP.msi" (
    echo ERROR: MSI was not produced.
    goto :fail
)

echo.
echo === Success ===
echo MSI output: %OUTDIR%\TideSSP.msi
goto :eof

:fail
echo.
echo === BUILD FAILED ===
exit /b 1
