#!/bin/bash
#
# Integrated Mesh-Chain Simulation Runner
#
# Orchestrates SUMO, OMNET++, and Mesh-Chain C++ simulation
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SUMO_DIR="$PROJECT_DIR/sumo"
OMNET_DIR="$PROJECT_DIR/omnetpp"
BUILD_DIR="$PROJECT_DIR/build"

# Parameters
DURATION=${1:-60}  # Simulation duration in seconds
NUM_VEHICLES=${2:-30}
NUM_RSUS=${3:-3}
USE_SUMO=${4:-yes}
USE_OMNET=${5:-no}  # OMNET++ optional for now
USE_GUI=${6:-no}

echo "=========================================="
echo "  Mesh-Chain Integrated Simulation"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Duration: ${DURATION}s"
echo "  Vehicles: $NUM_VEHICLES"
echo "  RSUs: $NUM_RSUS"
echo "  SUMO: $USE_SUMO"
echo "  OMNET++: $USE_OMNET"
echo "  GUI: $USE_GUI"
echo ""

# Check dependencies
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo "Warning: $1 not found. $2"
        return 1
    fi
    return 0
}

# Step 1: Start SUMO if enabled
SUMO_PID=""
if [ "$USE_SUMO" == "yes" ]; then
    echo "[1/4] Starting SUMO TraCI bridge..."

    if check_dependency "python3" "SUMO integration disabled"; then
        if check_dependency "sumo" "SUMO not installed"; then
            # Start SUMO bridge in background
            GUI_FLAG=""
            if [ "$USE_GUI" == "yes" ]; then
                GUI_FLAG="--gui"
            fi

            cd "$PROJECT_DIR"
            python3 scripts/sumo_traci_bridge.py \
                --config sumo/urban_scenario.sumocfg \
                --duration $DURATION \
                --output sumo_output.json \
                $GUI_FLAG &
            SUMO_PID=$!

            echo "  SUMO TraCI bridge started (PID: $SUMO_PID)"
            sleep 2  # Give SUMO time to start
        else
            echo "  Skipping SUMO (not installed)"
        fi
    fi
else
    echo "[1/4] Skipping SUMO (disabled)"
fi

# Step 2: Start OMNET++ if enabled
OMNET_PID=""
if [ "$USE_OMNET" == "yes" ]; then
    echo "[2/4] Starting OMNET++ simulation..."

    if check_dependency "opp_run" "OMNET++ not installed"; then
        cd "$OMNET_DIR"
        opp_run -u Cmdenv -c General -n . MeshChainNetwork &
        OMNET_PID=$!

        echo "  OMNET++ simulation started (PID: $OMNET_PID)"
        sleep 2
    else
        echo "  Skipping OMNET++ (not installed)"
    fi
else
    echo "[2/4] Skipping OMNET++ (disabled)"
fi

# Step 3: Run Mesh-Chain C++ simulation
echo "[3/4] Running Mesh-Chain simulation..."

cd "$PROJECT_DIR"
if [ -f "build/meshchain_sim" ]; then
    ./build/meshchain_sim $NUM_VEHICLES $NUM_RSUS $DURATION
else
    echo "Error: meshchain_sim not found. Please build first:"
    echo "  ./scripts/build.sh"
    exit 1
fi

# Step 4: Cleanup
echo "[4/4] Cleaning up..."

if [ ! -z "$SUMO_PID" ]; then
    echo "  Stopping SUMO (PID: $SUMO_PID)..."
    kill $SUMO_PID 2>/dev/null || true
fi

if [ ! -z "$OMNET_PID" ]; then
    echo "  Stopping OMNET++ (PID: $OMNET_PID)..."
    kill $OMNET_PID 2>/dev/null || true
fi

echo ""
echo "=========================================="
echo "  Simulation Complete!"
echo "=========================================="
echo ""
echo "Output files:"
if [ "$USE_SUMO" == "yes" ]; then
    echo "  - sumo_output.json (SUMO vehicle data)"
    echo "  - sumo_output.csv (C++ readable format)"
fi
echo ""
