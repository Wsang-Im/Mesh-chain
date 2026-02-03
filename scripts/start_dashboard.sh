#!/bin/bash
#
# Mesh-Chain Real-Time Dashboard Launcher
#

echo "========================================="
echo "  Mesh-Chain Real-Time Dashboard"
echo "========================================="
echo ""

# Check if simulator is already running
if pgrep -f "meshchain_integrated" > /dev/null; then
    echo "⚠️  Simulator is already running"
else
    echo "ℹ️  Starting simulator in background..."
    cd build
    ./meshchain_integrated sumo/highway.sumo.cfg 60 --sim-mode > /tmp/meshchain_sim.log 2>&1 &
    SIM_PID=$!
    echo "✓ Simulator started (PID: $SIM_PID)"
    echo "  Log: /tmp/meshchain_sim.log"
    cd ..
fi

echo ""
echo "Starting web server..."
cd visualization
python3 -m http.server 8000 > /dev/null 2>&1 &
WEB_PID=$!
echo "✓ Web server started (PID: $WEB_PID)"

echo ""
echo "========================================="
echo "  Dashboard Ready!"
echo "========================================="
echo ""
echo "📊 Open in browser:"
echo "   http://localhost:8000/realtime_dashboard.html"
echo ""
echo "To stop:"
echo "  pkill -f meshchain_integrated"
echo "  pkill -f 'python3 -m http.server'"
echo ""
echo "Simulator log: /tmp/meshchain_sim.log"
echo "Data file: visualization/data/simulation_data.json"
echo ""
