#!/bin/bash

# Mesh-Chain Simulation Build Script

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"

echo "=========================================="
echo "  Building Mesh-Chain Simulation"
echo "=========================================="
echo ""

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure
echo "[1/3] Configuring CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Build
echo ""
echo "[2/3] Building..."
cmake --build . -j$(nproc)

# Install
echo ""
echo "[3/3] Installing..."
cmake --install . --prefix="${PROJECT_DIR}/install"

echo ""
echo "=========================================="
echo "  Build Complete!"
echo "=========================================="
echo ""
echo "Executable: ${PROJECT_DIR}/install/bin/meshchain_sim"
echo ""
echo "Run simulation:"
echo "  ./install/bin/meshchain_sim [num_vehicles] [num_rsus] [duration_s]"
echo ""
echo "Example:"
echo "  ./install/bin/meshchain_sim 20 3 60"
echo ""
