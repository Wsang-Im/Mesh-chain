#ifndef MESHCHAIN_TRACI_CLIENT_H
#define MESHCHAIN_TRACI_CLIENT_H

#include "../common/types.h"
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <cmath>

// Forward declarations for TraCI socket
#ifdef USE_TRACI
#include <libsumo/libsumo.h>
#endif

namespace meshchain {
namespace integration {

/**
 * SUMO TraCI Client
 *
 * Connects to SUMO via TraCI (Traffic Control Interface) to:
 * - Get real-time vehicle positions and speeds
 * - Calculate accurate inter-vehicle distances for ToF
 * - Synchronize simulation time with SUMO
 */
class TraCIClient {
public:
    struct VehicleState {
        std::string id;
        double x;           // Position X (meters)
        double y;           // Position Y (meters)
        double z;           // Position Z (meters, usually 0)
        double speed_mps;   // Speed (m/s)
        double heading_deg; // Heading (degrees)
        std::string road_id;
        std::string lane_id;
        double lane_position;

        // Calculate 3D distance to another vehicle
        double distanceTo(const VehicleState& other) const {
            double dx = x - other.x;
            double dy = y - other.y;
            double dz = z - other.z;
            return std::sqrt(dx*dx + dy*dy + dz*dz);
        }
    };

    struct Config {
        std::string sumo_host;      // SUMO host (default: "localhost")
        int sumo_port;              // SUMO TraCI port (default: 8813)
        std::string sumo_config;    // Path to .sumo.cfg file
        bool auto_start_sumo;       // Auto-start SUMO process
        bool use_gui;               // Use sumo-gui instead of sumo (default: false)
        double step_length_s;       // Simulation step length (default: 0.1s)
        double max_duration_s;      // Maximum simulation duration (for sim-mode)
    };

private:
    Config config_;
    bool connected_;
    double current_time_s_;
    std::map<std::string, VehicleState> vehicle_states_;
    int sumo_gui_pid_;  // PID for external sumo-gui process

#ifdef USE_TRACI
    // libsumo is header-only, no need for socket handle
#else
    // Simulation mode - no actual connection
#endif

public:
    explicit TraCIClient(const Config& config)
        : config_(config), connected_(false), current_time_s_(0.0), sumo_gui_pid_(-1) {}

    ~TraCIClient() {
        disconnect();
    }

    /**
     * Connect to SUMO via TraCI
     */
    bool connect() {
#ifdef USE_TRACI
        try {
            // GUI mode: Run sumo-gui as separate process (avoiding libsumo GUI memory bug)
            if (config_.use_gui) {
                std::cout << "[TraCI] Starting SUMO GUI as separate process (avoiding libsumo GUI crash)...\n";

                // Construct sumo-gui command
                std::string gui_cmd = "/usr/local/bin/sumo-gui -c " + config_.sumo_config +
                                     " --step-length " + std::to_string(config_.step_length_s) +
                                     " --delay 50";

                // Find GUI settings file
                std::string gui_settings = "sumo/gui-settings.xml";
                std::ifstream test_file(gui_settings);
                if (test_file.good()) {
                    gui_cmd += " --gui-settings-file " + gui_settings;
                    test_file.close();
                }

                gui_cmd += " &";  // Run in background

                // Execute sumo-gui as separate process
                int ret = system(gui_cmd.c_str());
                if (ret == 0) {
                    std::cout << "[TraCI] ✓ SUMO GUI window launched successfully\n";
                    std::cout << "[TraCI] → GUI will show visualization\n";
                    std::cout << "[TraCI] → Simulation runs in headless libsumo for stability\n";
                    std::this_thread::sleep_for(std::chrono::seconds(2));  // Time for GUI to start
                } else {
                    std::cerr << "[TraCI] Warning: Failed to launch SUMO GUI, continuing headless\n";
                }
            }

            // libsumo always runs in headless mode (avoiding GUI crash)
            std::vector<std::string> sumo_args;
            sumo_args.push_back("/usr/local/bin/sumo");
            std::cout << "[TraCI] Starting SUMO (headless libsumo)...\n";

            // Add configuration arguments
            sumo_args.push_back("-c");
            sumo_args.push_back(config_.sumo_config);
            std::cout << "[TraCI] Using SUMO config: " << config_.sumo_config << "\n";
            sumo_args.push_back("--step-length");
            sumo_args.push_back(std::to_string(config_.step_length_s));

            // Start SUMO (headless libsumo)
            libsumo::Simulation::start(sumo_args);
            connected_ = true;
            current_time_s_ = 0.0;
            std::cout << "[TraCI] ✓ Connected to SUMO (headless)\n";

            // Debug: Print loaded edges and lanes
            auto edge_ids = libsumo::Edge::getIDList();
            std::cout << "[TraCI] Loaded " << edge_ids.size() << " edges:\n";
            for (const auto& edge_id : edge_ids) {
                auto lane_count = libsumo::Edge::getLaneNumber(edge_id);
                std::cout << "[TraCI]   - Edge '" << edge_id << "': " << lane_count << " lanes\n";
            }

            if (config_.use_gui) {
                std::cout << "[TraCI] ✓ Simulation ready (GUI shows visualization, libsumo handles logic)\n";
            } else {
                std::cout << "[TraCI] ✓ Simulation ready (headless mode)\n";
            }

            return true;
        } catch (const std::exception& e) {
            std::cerr << "[TraCI] Connection failed: " << e.what() << "\n";
            return false;
        }
#else
        // Simulation mode - always succeeds
        std::cout << "[TraCI] Simulation mode - no actual SUMO connection\n";
        connected_ = true;
        return true;
#endif
    }

    /**
     * Disconnect from SUMO
     */
    void disconnect() {
        if (!connected_) return;

#ifdef USE_TRACI
        try {
            libsumo::Simulation::close();
        } catch (...) {
            // Ignore errors during shutdown
        }
#endif
        connected_ = false;
    }

    /**
     * Advance SUMO simulation by one step
     * Returns false if simulation ended
     */
    bool step() {
        if (!connected_) return false;

#ifdef USE_TRACI
        try {
            libsumo::Simulation::step();
            current_time_s_ = libsumo::Simulation::getTime();

            // Update all vehicle states
            updateVehicleStates();

            // Debug: Print vehicle count every 10 seconds
            static int debug_counter = 0;
            if (config_.use_gui && debug_counter++ % 100 == 0) {
                std::cout << "[TraCI] t=" << current_time_s_ << "s, vehicles=" << vehicle_states_.size() << "\n";
            }

            // Check if simulation ended
            int min_expected_vehicles = libsumo::Simulation::getMinExpectedNumber();
            return min_expected_vehicles > 0;
        } catch (const std::exception& e) {
            std::cerr << "[TraCI] Step failed: " << e.what() << "\n";
            return false;
        }
#else
        // Simulation mode - advance time
        current_time_s_ += config_.step_length_s;
        updateMockVehicleStates();
        // Use configured duration instead of hardcoded 300s
        double max_time = config_.max_duration_s > 0 ? config_.max_duration_s : 300.0;
        return current_time_s_ < max_time;
#endif
    }

    /**
     * Get current simulation time
     */
    double getCurrentTime() const {
        return current_time_s_;
    }

    /**
     * Set maximum duration for simulation mode
     */
    void setMaxDuration(double duration_s) {
        config_.max_duration_s = duration_s;
    }

    /**
     * Get all active vehicle states
     */
    const std::map<std::string, VehicleState>& getVehicleStates() const {
        return vehicle_states_;
    }

    /**
     * Get state of specific vehicle
     */
    std::optional<VehicleState> getVehicleState(const std::string& vehicle_id) const {
        auto it = vehicle_states_.find(vehicle_id);
        if (it != vehicle_states_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Get distance between two vehicles
     */
    std::optional<double> getDistance(const std::string& vid1, const std::string& vid2) const {
        auto v1 = getVehicleState(vid1);
        auto v2 = getVehicleState(vid2);

        if (v1.has_value() && v2.has_value()) {
            return v1->distanceTo(*v2);
        }
        return std::nullopt;
    }

    /**
     * Get all vehicles within range of a vehicle
     */
    std::vector<std::string> getVehiclesInRange(const std::string& vehicle_id,
                                                 double range_m) const {
        std::vector<std::string> result;

        auto center = getVehicleState(vehicle_id);
        if (!center.has_value()) return result;

        for (const auto& [vid, state] : vehicle_states_) {
            if (vid == vehicle_id) continue;

            double distance = center->distanceTo(state);
            if (distance <= range_m) {
                result.push_back(vid);
            }
        }

        return result;
    }

private:
    /**
     * Update vehicle states from SUMO
     */
    void updateVehicleStates() {
#ifdef USE_TRACI
        vehicle_states_.clear();

        auto vehicle_ids = libsumo::Vehicle::getIDList();

        for (const auto& vid : vehicle_ids) {
            VehicleState state;
            state.id = vid;

            // Get position
            auto pos = libsumo::Vehicle::getPosition(vid);
            state.x = pos.x;
            state.y = pos.y;
            state.z = pos.z;

            // Get speed
            state.speed_mps = libsumo::Vehicle::getSpeed(vid);

            // Get heading
            state.heading_deg = libsumo::Vehicle::getAngle(vid);

            // Get road/lane info
            state.road_id = libsumo::Vehicle::getRoadID(vid);
            state.lane_id = libsumo::Vehicle::getLaneID(vid);
            state.lane_position = libsumo::Vehicle::getLanePosition(vid);

            vehicle_states_[vid] = state;
        }
#endif
    }

    /**
     * Mock vehicle states for simulation mode
     */
    void updateMockVehicleStates() {
        // Generate mock vehicles moving on a highway
        const int num_vehicles = 50;  // 20 → 50 (increased vehicle count to improve ToF verification success rate)
        const double highway_length = 1000.0; // 2km → 1km (more densely populated environment)
        const double lane_width = 3.5; // meters

        vehicle_states_.clear();

        for (int i = 0; i < num_vehicles; ++i) {
            VehicleState state;
            state.id = "V" + std::to_string(i);

            // Position: vehicles spread along highway
            // Move based on speed and time
            double base_speed = 20.0 + (i % 5) * 2.0; // 20-28 m/s (72-100 km/h)
            double initial_pos = (i * highway_length / num_vehicles);
            state.x = std::fmod(initial_pos + base_speed * current_time_s_, highway_length);

            // Lane: 2 lanes
            int lane = i % 2;
            state.y = lane * lane_width;
            state.z = 0.0;

            state.speed_mps = base_speed;
            state.heading_deg = 90.0; // East
            state.road_id = "highway_1";
            state.lane_id = "highway_1_" + std::to_string(lane);
            state.lane_position = state.x;

            vehicle_states_[state.id] = state;
        }
    }
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_TRACI_CLIENT_H
