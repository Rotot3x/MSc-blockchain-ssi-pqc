@echo off
REM Build script for liboqs on Windows

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR:~0,-9%
set LIBOQS_VERSION=0.14.0
set BUILD_DIR=%PROJECT_DIR%\build
set LIB_DIR=%PROJECT_DIR%\pqcrypto_fm\lib
set INCLUDE_DIR=%PROJECT_DIR%\pqcrypto_fm\include
set TEMP_DIR=%TEMP%\liboqs_build_%RANDOM%

echo 🚀 Starting liboqs build process...
echo Project directory: %PROJECT_DIR%
echo Temporary directory: %TEMP_DIR%

REM Clean previous builds
echo 🧹 Cleaning previous builds...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%LIB_DIR%" rmdir /s /q "%LIB_DIR%"
if exist "%INCLUDE_DIR%" rmdir /s /q "%INCLUDE_DIR%"
mkdir "%LIB_DIR%"
mkdir "%INCLUDE_DIR%"

REM Create temporary directory
mkdir "%TEMP_DIR%"

REM Download liboqs
echo 📥 Downloading liboqs %LIBOQS_VERSION%...
cd "%TEMP_DIR%"

REM Use PowerShell to download
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/open-quantum-safe/liboqs/archive/refs/tags/%LIBOQS_VERSION%.zip' -OutFile 'liboqs-%LIBOQS_VERSION%.zip'"

REM Extract using PowerShell
echo 📂 Extracting liboqs source...
powershell -Command "Expand-Archive -Path 'liboqs-%LIBOQS_VERSION%.zip' -DestinationPath '.'"
cd "liboqs-%LIBOQS_VERSION%"

REM Configure build
echo ⚙️  Configuring build...
mkdir build
cd build

REM Check for Visual Studio
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Visual Studio C++ compiler not found!
    echo Please run this script from a Visual Studio Developer Command Prompt
    exit /b 1
)

REM Configure cmake for Windows
cmake -DCMAKE_BUILD_TYPE=Release ^
      -DBUILD_SHARED_LIBS=ON ^
      -DOQS_USE_OPENSSL=OFF ^
      -DOQS_BUILD_ONLY_LIB=ON ^
      -DCMAKE_INSTALL_PREFIX="%PROJECT_DIR%\pqcrypto_fm" ^
      ..

if %errorlevel% neq 0 (
    echo ❌ CMake configuration failed!
    exit /b 1
)

REM Build
echo 🔧 Building liboqs...
cmake --build . --config Release

if %errorlevel% neq 0 (
    echo ❌ Build failed!
    exit /b 1
)

REM Install
echo 📦 Installing liboqs...
cmake --install . --config Release

if %errorlevel% neq 0 (
    echo ❌ Installation failed!
    exit /b 1
)

REM Verify installation
echo ✅ Verifying installation...
if exist "%LIB_DIR%\liboqs.dll" (
    echo ✅ liboqs library found: %LIB_DIR%\liboqs.dll
    dir "%LIB_DIR%\liboqs*"
) else (
    echo ❌ liboqs library not found!
    exit /b 1
)

REM Cleanup
echo 🧹 Cleaning up...
rmdir /s /q "%TEMP_DIR%"

echo 🎉 liboqs build completed successfully!
echo Library installed in: %LIB_DIR%
echo Headers installed in: %INCLUDE_DIR%

endlocal