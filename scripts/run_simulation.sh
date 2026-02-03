#!/bin/bash

# Mesh-Chain Simulation Runner

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXECUTABLE="${PROJECT_DIR}/install/bin/meshchain_sim"

# Default parameters
NUM_VEHICLES=20
NUM_RSUS=3
DURATION=60

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --vehicles)
            NUM_VEHICLES="$2"
            shift 2
            ;;
        --rsus)
            NUM_RSUS="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --scenario)
            SCENARIO="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--vehicles N] [--rsus N] [--duration S] [--scenario NAME]"
            exit 1
            ;;
    esac
done

echo "=========================================="
echo "  Mesh-Chain V2X Simulation"
echo "=========================================="
echo ""
echo "Parameters:"
echo "  Vehicles: ${NUM_VEHICLES}"
echo "  RSUs: ${NUM_RSUS}"
echo "  Duration: ${DURATION}s"
if [ -n "${SCENARIO}" ]; then
    echo "  Scenario: ${SCENARIO}"
fi
echo ""
echo "=========================================="
echo ""

# Check if executable exists
if [ ! -f "${EXECUTABLE}" ]; then
    echo "Error: Executable not found: ${EXECUTABLE}"
    echo "Please run ./scripts/build.sh first"
    exit 1
fi

# Run simulation
"${EXECUTABLE}" ${NUM_VEHICLES} ${NUM_RSUS} ${DURATION}

echo ""
echo "=========================================="
echo "  Simulation Complete"
echo "=========================================="
