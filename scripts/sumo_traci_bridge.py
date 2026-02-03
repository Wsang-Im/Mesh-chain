#!/usr/bin/env python3
"""
SUMO TraCI Bridge for Mesh-Chain Simulation

Connects SUMO traffic simulation to Mesh-Chain C++ simulation:
- Reads vehicle positions from SUMO
- Calculates inter-vehicle distances
- Outputs data for C++ consumption
"""

import os
import sys
import json
import time
import socket
import argparse
from typing import Dict, List, Tuple

# Check if TraCI is available
try:
    import traci
    from sumolib import checkBinary
except ImportError:
    print("Error: SUMO TraCI not found. Please install SUMO and set SUMO_HOME.")
    print("Visit: https://sumo.dlr.de/docs/Installing/index.html")
    sys.exit(1)


class SUMOBridge:
    """Bridge between SUMO and Mesh-Chain simulation"""

    def __init__(self, sumo_config: str, port: int = 8813):
        self.sumo_config = sumo_config
        self.port = port
        self.vehicles = {}

    def start_sumo(self, gui: bool = False):
        """Start SUMO simulation"""
        if gui:
            sumo_binary = checkBinary('sumo-gui')
        else:
            sumo_binary = checkBinary('sumo')

        traci.start([
            sumo_binary,
            "-c", self.sumo_config,
            "--step-length", "0.1",  # 100ms steps to match Mesh-Chain
            "--no-warnings",
            "--quit-on-end"
        ])

        print(f"[SUMO Bridge] Started SUMO with config: {self.sumo_config}")

    def get_vehicle_data(self) -> Dict:
        """Get current vehicle positions and data"""
        vehicle_ids = traci.vehicle.getIDList()

        data = {
            "timestamp": traci.simulation.getTime(),
            "vehicles": []
        }

        for vid in vehicle_ids:
            try:
                pos = traci.vehicle.getPosition(vid)
                speed = traci.vehicle.getSpeed(vid)
                angle = traci.vehicle.getAngle(vid)
                road_id = traci.vehicle.getRoadID(vid)

                vehicle_data = {
                    "id": vid,
                    "x": pos[0],
                    "y": pos[1],
                    "speed_ms": speed,
                    "angle_deg": angle,
                    "road_id": road_id
                }

                data["vehicles"].append(vehicle_data)

            except traci.exceptions.TraCIException as e:
                # Vehicle might have left simulation
                continue

        return data

    def calculate_distances(self, data: Dict) -> Dict:
        """Calculate pairwise distances between vehicles"""
        vehicles = data["vehicles"]

        for i, v1 in enumerate(vehicles):
            v1["neighbors"] = []

            for j, v2 in enumerate(vehicles):
                if i == j:
                    continue

                # Euclidean distance
                dx = v1["x"] - v2["x"]
                dy = v1["y"] - v2["y"]
                dist = (dx*dx + dy*dy) ** 0.5

                # Only consider neighbors within 1km (C-V2X range)
                if dist <= 1000.0:
                    v1["neighbors"].append({
                        "id": v2["id"],
                        "distance_m": dist
                    })

        return data

    def write_csv_output(self, data: Dict, csv_file: str):
        """Write vehicle data in CSV format for easy C++ parsing"""
        import csv

        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            # Header
            writer.writerow(['timestamp', 'vehicle_id', 'x', 'y', 'speed_ms',
                           'angle_deg', 'road_id', 'neighbor_id', 'distance_m'])

            # Data rows
            for vehicle in data['vehicles']:
                for neighbor in vehicle['neighbors']:
                    writer.writerow([
                        data['timestamp'],
                        vehicle['id'],
                        vehicle['x'],
                        vehicle['y'],
                        vehicle['speed_ms'],
                        vehicle['angle_deg'],
                        vehicle['road_id'],
                        neighbor['id'],
                        neighbor['distance_m']
                    ])

    def run_simulation(self, duration_s: float = 60.0, output_file: str = None):
        """Run SUMO simulation and output vehicle data"""

        step = 0
        max_steps = int(duration_s / 0.1)  # 100ms per step

        print(f"[SUMO Bridge] Running simulation for {duration_s}s ({max_steps} steps)")

        while step < max_steps and traci.simulation.getMinExpectedNumber() > 0:
            traci.simulationStep()

            # Get vehicle data every step (100ms)
            data = self.get_vehicle_data()
            data = self.calculate_distances(data)

            if output_file:
                # Write JSON for debugging
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)

                # Write CSV for C++ consumption
                csv_file = output_file.replace('.json', '.csv')
                self.write_csv_output(data, csv_file)

            # Print status every 10 steps (1 second)
            if step % 10 == 0:
                print(f"[SUMO Bridge] Step {step}/{max_steps}, "
                      f"Vehicles: {len(data['vehicles'])}, "
                      f"Time: {data['timestamp']:.1f}s")

            step += 1

            # Small delay to sync with C++ simulation
            time.sleep(0.1)

        print("[SUMO Bridge] Simulation complete")
        traci.close()


def main():
    parser = argparse.ArgumentParser(description='SUMO TraCI Bridge for Mesh-Chain')
    parser.add_argument('--config', type=str, required=True,
                        help='SUMO configuration file (.sumocfg)')
    parser.add_argument('--duration', type=float, default=60.0,
                        help='Simulation duration in seconds (default: 60)')
    parser.add_argument('--output', type=str, default='sumo_output.json',
                        help='Output file for vehicle data (default: sumo_output.json)')
    parser.add_argument('--gui', action='store_true',
                        help='Use SUMO GUI instead of command-line')

    args = parser.parse_args()

    # Check if SUMO config exists
    if not os.path.exists(args.config):
        print(f"Error: SUMO config file not found: {args.config}")
        sys.exit(1)

    # Create bridge and run
    bridge = SUMOBridge(args.config)
    bridge.start_sumo(gui=args.gui)
    bridge.run_simulation(duration_s=args.duration, output_file=args.output)


if __name__ == "__main__":
    main()
