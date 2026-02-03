#ifndef MESHCHAIN_TRACI_CLIENT_SOCKET_H
#define MESHCHAIN_TRACI_CLIENT_SOCKET_H

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

// Use libtraci for multi-instance TCP socket connection
#ifdef USE_TRACI
// IMPORTANT: LIBTRACI must be defined BEFORE including any SUMO headers
#ifndef LIBTRACI
#define LIBTRACI 1
#endif
// Include libsumo headers - they will use libtraci implementation when LIBTRACI is defined
#include <libsumo/Simulation.h>
#include <libsumo/Vehicle.h>
#include <libsumo/Edge.h>
#endif

namespace meshchain {
namespace integration {

/**
 * SUMO TraCI Client (TCP Socket Version)
 *
 * Supports multiple simultaneous SUMO instances via libtraci
 */
class TraCIClientSocket {
public:
    struct VehicleState {
        std::string id;
        double x, y, z;
        double speed_mps;
        double heading_deg;
        std::string road_id;
        std::string lane_id;
        double lane_position;

        double distanceTo(const VehicleState& other) const {
            double dx = x - other.x;
            double dy = y - other.y;
            double dz = z - other.z;
            return std::sqrt(dx*dx + dy*dy + dz*dz);
        }
    };

    struct Config {
        std::string sumo_host;
        int sumo_port;
        std::string sumo_config;
        bool auto_start_sumo;
        bool use_gui;
        double step_length_s;
        double max_duration_s;
        std::string label;  // Unique label for this simulation instance
    };

private:
    Config config_;
    bool connected_;
    double current_time_s_;
    std::map<std::string, VehicleState> vehicle_states_;
    std::string connection_label_;

public:
    explicit TraCIClientSocket(const Config& config)
        : config_(config), connected_(false), current_time_s_(0.0) {
        // Generate unique label if not provided
        if (config_.label.empty()) {
            connection_label_ = "sim_" + std::to_string(config_.sumo_port);
        } else {
            connection_label_ = config_.label;
        }
    }

    ~TraCIClientSocket() {
        disconnect();
    }

    bool connect() {
#ifdef USE_TRACI
        try {
            std::string sumo_binary = config_.use_gui ? "/usr/local/bin/sumo-gui" : "/usr/local/bin/sumo";

            std::cout << "[TraCI:" << connection_label_ << "] Starting SUMO as TraCI server...\n";

            // Build SUMO command with remote port
            std::string sumo_cmd = sumo_binary +
                                  " -c " + config_.sumo_config +
                                  " --remote-port " + std::to_string(config_.sumo_port) +
                                  " --step-length " + std::to_string(config_.step_length_s);

            if (config_.use_gui) {
                sumo_cmd += " --start --delay 50";
                std::string gui_settings = "sumo/gui-settings.xml";
                std::ifstream test(gui_settings);
                if (test.good()) {
                    sumo_cmd += " --gui-settings-file " + gui_settings;
                }
            }

            sumo_cmd += " &";

            std::cout << "[TraCI:" << connection_label_ << "] Launching: " << sumo_cmd << "\n";
            int ret = system(sumo_cmd.c_str());
            if (ret != 0) {
                std::cerr << "[TraCI:" << connection_label_ << "] Failed to launch SUMO\n";
                return false;
            }

            std::cout << "[TraCI:" << connection_label_ << "] Waiting for SUMO to start...\n";
            std::this_thread::sleep_for(std::chrono::seconds(3));

            // Connect via libtraci
            std::cout << "[TraCI:" << connection_label_ << "] Connecting to "
                      << config_.sumo_host << ":" << config_.sumo_port << "...\n";

            auto result = libtraci::Simulation::init(
                config_.sumo_port,
                10,  // retries
                config_.sumo_host,
                connection_label_
            );

            if (result.first != 0) {
                throw std::runtime_error("Failed to connect: " + result.second);
            }

            connected_ = true;
            current_time_s_ = 0.0;

            std::cout << "[TraCI:" << connection_label_ << "] ✓ Connected via TCP socket\n";

            auto edge_ids = libtraci::Edge::getIDList(connection_label_);
            std::cout << "[TraCI:" << connection_label_ << "] Loaded " << edge_ids.size() << " edges\n";

            return true;
        } catch (const std::exception& e) {
            std::cerr << "[TraCI:" << connection_label_ << "] Connection failed: " << e.what() << "\n";
            return false;
        }
#else
        std::cout << "[TraCI:" << connection_label_ << "] Simulation mode\n";
        connected_ = true;
        return true;
#endif
    }

    void disconnect() {
#ifdef USE_TRACI
        if (connected_) {
            try {
                libtraci::Simulation::close(connection_label_);
                std::cout << "[TraCI:" << connection_label_ << "] Disconnected\n";
            } catch (...) {}
            connected_ = false;
        }
#endif
    }

    bool step() {
#ifdef USE_TRACI
        if (!connected_) return false;
        try {
            libtraci::Simulation::step(0.0, connection_label_);
            current_time_s_ = libtraci::Simulation::getTime(connection_label_);
            updateVehicleStates();

            int min_expected = libtraci::Simulation::getMinExpectedNumber(connection_label_);
            if (min_expected <= 0) {
                std::cout << "[TraCI:" << connection_label_ << "] No more vehicles expected\n";
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[TraCI:" << connection_label_ << "] Step failed: " << e.what() << "\n";
            return false;
        }
#else
        current_time_s_ += config_.step_length_s;
        return current_time_s_ < config_.max_duration_s;
#endif
    }

    double getCurrentTime() const { return current_time_s_; }

    const std::map<std::string, VehicleState>& getVehicleStates() const {
        return vehicle_states_;
    }

    std::optional<VehicleState> getVehicleState(const std::string& vehicle_id) const {
        auto it = vehicle_states_.find(vehicle_id);
        if (it != vehicle_states_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

private:
    void updateVehicleStates() {
#ifdef USE_TRACI
        auto vehicle_ids = libtraci::Vehicle::getIDList(connection_label_);

        vehicle_states_.clear();

        for (const auto& vid : vehicle_ids) {
            VehicleState state;
            state.id = vid;

            auto pos = libtraci::Vehicle::getPosition(vid, connection_label_);
            state.x = pos.x;
            state.y = pos.y;
            state.z = pos.z;

            state.speed_mps = libtraci::Vehicle::getSpeed(vid, connection_label_);
            state.heading_deg = libtraci::Vehicle::getAngle(vid, connection_label_);
            state.road_id = libtraci::Vehicle::getRoadID(vid, connection_label_);
            state.lane_id = libtraci::Vehicle::getLaneID(vid, connection_label_);
            state.lane_position = libtraci::Vehicle::getLanePosition(vid, connection_label_);

            vehicle_states_[vid] = state;
        }
#endif
    }
};

} // namespace integration
} // namespace meshchain

#endif
