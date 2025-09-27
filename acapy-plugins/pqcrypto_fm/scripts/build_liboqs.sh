#!/bin/bash
# Build script for liboqs on Unix systems (Linux/macOS)

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIBOQS_VERSION="0.14.0"
BUILD_DIR="${PROJECT_DIR}/build"
LIB_DIR="${PROJECT_DIR}/pqcrypto_fm/lib"
INCLUDE_DIR="${PROJECT_DIR}/pqcrypto_fm/include"
TEMP_DIR=$(mktemp -d)

echo "🚀 Starting liboqs build process..."
echo "Project directory: $PROJECT_DIR"
echo "Temporary directory: $TEMP_DIR"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf "$BUILD_DIR" "$LIB_DIR" "$INCLUDE_DIR"
mkdir -p "$LIB_DIR" "$INCLUDE_DIR"

# Download liboqs
echo "📥 Downloading liboqs ${LIBOQS_VERSION}..."
cd "$TEMP_DIR"
curl -L "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" -o "liboqs-${LIBOQS_VERSION}.tar.gz"

echo "📂 Extracting liboqs source..."
tar -xzf "liboqs-${LIBOQS_VERSION}.tar.gz"
cd "liboqs-${LIBOQS_VERSION}"

# Configure build
echo "⚙️  Configuring build..."
mkdir build && cd build

# Detect available build systems
if command -v ninja >/dev/null 2>&1; then
    echo "Using Ninja build system"
    CMAKE_GENERATOR="-GNinja"
    BUILD_CMD="ninja"
    INSTALL_CMD="ninja install"
else
    echo "Using Make build system"
    CMAKE_GENERATOR=""
    BUILD_CMD="make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
    INSTALL_CMD="make install"
fi

# Configure cmake
cmake ${CMAKE_GENERATOR} \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/pqcrypto_fm" \
    ..

# Build
echo "🔧 Building liboqs..."
$BUILD_CMD

# Install
echo "📦 Installing liboqs..."
$INSTALL_CMD

# Verify installation
echo "✅ Verifying installation..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    LIB_FILE="$LIB_DIR/liboqs.dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    LIB_FILE="$LIB_DIR/liboqs.so"
else
    # Generic Unix
    LIB_FILE="$LIB_DIR/liboqs.so"
fi

if [[ -f "$LIB_FILE" ]]; then
    echo "✅ liboqs library found: $LIB_FILE"
    ls -la "$LIB_DIR"/liboqs*
else
    echo "❌ liboqs library not found!"
    exit 1
fi

# Cleanup
echo "🧹 Cleaning up..."
rm -rf "$TEMP_DIR"

echo "🎉 liboqs build completed successfully!"
echo "Library installed in: $LIB_DIR"
echo "Headers installed in: $INCLUDE_DIR"