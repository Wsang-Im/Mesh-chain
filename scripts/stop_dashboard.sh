#!/bin/bash
#
# Stop Mesh-Chain Dashboard
#

echo "Stopping Mesh-Chain simulator..."
pkill -f "meshchain_integrated"

echo "Stopping web server..."
pkill -f "python3 -m http.server 8000"

echo "✓ All processes stopped"
