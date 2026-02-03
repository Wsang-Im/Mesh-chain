#ifndef MESHCHAIN_SUMO_VISUALIZER_H
#define MESHCHAIN_SUMO_VISUALIZER_H

#include "../common/types.h"
#include <string>
#include <map>
#include <memory>
#include <iostream>
#include <cmath>

#ifdef USE_TRACI
// LIBTRACI is defined in CMakeLists.txt for TCP socket mode
#include <libsumo/libsumo.h>
#include <libsumo/POI.h>
#include <libsumo/Polygon.h>
#include <libsumo/Vehicle.h>
#endif

namespace meshchain {
namespace integration {

/**
 * SUMO GUI Visualizer
 *
 * Adds visualization overlays to SUMO GUI:
 * - Block creation status (PoI markers)
 * - WAVE communication range (Polygons)
 * - TLS handshake progress (Vehicle colors)
 * - Witness connections (Lines between vehicles)
 */
class SUMOVisualizer {
public:
    enum class BlockStatus {
        IDLE,           // No block being created
        CREATING,       // Block creation in progress
        SUCCESS,        // Block created successfully
        FAILED          // Block creation failed
    };

    enum class TLSStatus {
        NONE,           // No TLS connection
        HANDSHAKE,      // TLS handshake in progress
        CONNECTED,      // TLS connected
        ENCRYPTING      // Encrypting/decrypting data
    };

private:
    bool visualization_enabled_;
    std::map<std::string, BlockStatus> vehicle_block_status_;
    std::map<std::string, TLSStatus> vehicle_tls_status_;

    // WAVE range visualization
    static constexpr double WAVE_RANGE_M = 300.0;

    // Color definitions (RGBA) - helper struct
    struct Color {
        uint8_t r, g, b, a;

#ifdef USE_TRACI
        libsumo::TraCIColor toLibsumoColor() const {
            return libsumo::TraCIColor(r, g, b, a);
        }
#endif
    };

    // Colors for different states
    static constexpr Color COLOR_IDLE = {128, 128, 128, 255};      // Gray
    static constexpr Color COLOR_CREATING = {255, 165, 0, 255};    // Orange
    static constexpr Color COLOR_SUCCESS = {0, 255, 0, 255};       // Green
    static constexpr Color COLOR_FAILED = {255, 0, 0, 255};        // Red

    static constexpr Color COLOR_TLS_NONE = {255, 255, 255, 255};  // White
    static constexpr Color COLOR_TLS_HANDSHAKE = {255, 255, 0, 255}; // Yellow
    static constexpr Color COLOR_TLS_CONNECTED = {0, 255, 255, 255}; // Cyan
    static constexpr Color COLOR_TLS_ENCRYPTING = {138, 43, 226, 255}; // BlueViolet

    static constexpr Color COLOR_WAVE_RANGE = {0, 0, 255, 50};     // Blue transparent

public:
    explicit SUMOVisualizer(bool enable = true)
        : visualization_enabled_(enable) {}

    /**
     * Update vehicle block creation status
     */
    void updateBlockStatus(const std::string& vehicle_id, BlockStatus status) {
        if (!visualization_enabled_) return;

        vehicle_block_status_[vehicle_id] = status;

#ifdef USE_TRACI
        try {
            // Add PoI (Point of Interest) marker above vehicle
            std::string poi_id = "block_" + vehicle_id;

            // Get vehicle position
            if (!libsumo::Vehicle::getIDList().empty()) {
                auto pos = libsumo::Vehicle::getPosition(vehicle_id);

                // Add marker 5 meters above vehicle
                libsumo::POI::add(poi_id, pos.x, pos.y + 5.0,
                    getBlockStatusColor(status).toLibsumoColor(),
                    "poi", 0, "", 0, 0, 3.0);  // 3.0 = marker size

                // Add text label
                std::string label = getBlockStatusLabel(status);
                libsumo::POI::setParameter(poi_id, "text", label);
            }
        } catch (const std::exception& e) {
            std::cerr << "[SUMOViz] Failed to update block status: " << e.what() << "\n";
        }
#else
        // Simulation mode - just log
        std::cout << "[SUMOViz] " << vehicle_id << " block status: "
                  << getBlockStatusLabel(status) << "\n";
#endif
    }

    /**
     * Update vehicle TLS status
     */
    void updateTLSStatus(const std::string& vehicle_id, TLSStatus status) {
        if (!visualization_enabled_) return;

        vehicle_tls_status_[vehicle_id] = status;

#ifdef USE_TRACI
        try {
            // Change vehicle color based on TLS status
            Color color = getTLSStatusColor(status);
            libsumo::Vehicle::setColor(vehicle_id, color.toLibsumoColor());
        } catch (const std::exception& e) {
            std::cerr << "[SUMOViz] Failed to update TLS status: " << e.what() << "\n";
        }
#else
        std::cout << "[SUMOViz] " << vehicle_id << " TLS status: "
                  << getTLSStatusLabel(status) << "\n";
#endif
    }

    /**
     * Show WAVE communication range around vehicle
     */
    void showWaveRange(const std::string& vehicle_id, bool show = true) {
        if (!visualization_enabled_) return;

#ifdef USE_TRACI
        try {
            std::string polygon_id = "wave_" + vehicle_id;

            if (show) {
                // Get vehicle position
                auto pos = libsumo::Vehicle::getPosition(vehicle_id);

                // Create circle polygon (approximate with 16 points)
                libsumo::TraCIPositionVector shape;
                const int num_points = 16;
                for (int i = 0; i < num_points; ++i) {
                    double angle = 2.0 * M_PI * i / num_points;
                    double x = pos.x + WAVE_RANGE_M * std::cos(angle);
                    double y = pos.y + WAVE_RANGE_M * std::sin(angle);
                    libsumo::TraCIPosition pt;
                    pt.x = x;
                    pt.y = y;
                    pt.z = 0.0;
                    shape.value.push_back(pt);
                }

                // Add polygon
                libsumo::Polygon::add(polygon_id, shape,
                    COLOR_WAVE_RANGE.toLibsumoColor(),
                    true,  // fill
                    "wave_range",
                    0);    // layer
            } else {
                // Remove polygon
                libsumo::Polygon::remove(polygon_id);
            }
        } catch (const std::exception& e) {
            std::cerr << "[SUMOViz] Failed to show WAVE range: " << e.what() << "\n";
        }
#else
        std::cout << "[SUMOViz] " << vehicle_id << " WAVE range: "
                  << (show ? "ON" : "OFF") << "\n";
#endif
    }

    /**
     * Draw witness connection line
     */
    void showWitnessConnection(const std::string& creator_id,
                               const std::string& witness_id,
                               bool show = true) {
        if (!visualization_enabled_) return;

#ifdef USE_TRACI
        try {
            std::string line_id = "witness_" + creator_id + "_" + witness_id;

            if (show) {
                // Get positions
                auto creator_pos = libsumo::Vehicle::getPosition(creator_id);
                auto witness_pos = libsumo::Vehicle::getPosition(witness_id);

                // Create line as polygon
                libsumo::TraCIPositionVector shape;
                shape.value.push_back(creator_pos);
                shape.value.push_back(witness_pos);

                // Green line for active witness
                Color line_color = {0, 255, 0, 200};

                libsumo::Polygon::add(line_id, shape,
                    line_color.toLibsumoColor(),
                    false,  // no fill (just line)
                    "witness_connection",
                    1);     // layer 1 (above WAVE range)
            } else {
                libsumo::Polygon::remove(line_id);
            }
        } catch (const std::exception& e) {
            std::cerr << "[SUMOViz] Failed to show witness connection: " << e.what() << "\n";
        }
#else
        std::cout << "[SUMOViz] Witness connection " << creator_id << " -> " << witness_id
                  << ": " << (show ? "ON" : "OFF") << "\n";
#endif
    }

    /**
     * Clear all visualizations for a vehicle
     */
    void clearVehicle(const std::string& vehicle_id) {
#ifdef USE_TRACI
        try {
            // Remove PoI
            libsumo::POI::remove("block_" + vehicle_id);

            // Remove WAVE range
            libsumo::Polygon::remove("wave_" + vehicle_id);

            // Reset vehicle color
            libsumo::Vehicle::setColor(vehicle_id, COLOR_TLS_NONE.toLibsumoColor());
        } catch (...) {
            // Ignore errors
        }
#endif

        vehicle_block_status_.erase(vehicle_id);
        vehicle_tls_status_.erase(vehicle_id);
    }

    /**
     * Enable/disable visualization
     */
    void setEnabled(bool enabled) {
        visualization_enabled_ = enabled;
    }

    bool isEnabled() const {
        return visualization_enabled_;
    }

private:
    Color getBlockStatusColor(BlockStatus status) const {
        switch (status) {
            case BlockStatus::CREATING: return COLOR_CREATING;
            case BlockStatus::SUCCESS:  return COLOR_SUCCESS;
            case BlockStatus::FAILED:   return COLOR_FAILED;
            default:                    return COLOR_IDLE;
        }
    }

    std::string getBlockStatusLabel(BlockStatus status) const {
        switch (status) {
            case BlockStatus::CREATING: return "Creating Block...";
            case BlockStatus::SUCCESS:  return "Block Created ✓";
            case BlockStatus::FAILED:   return "Block Failed ✗";
            default:                    return "";
        }
    }

    Color getTLSStatusColor(TLSStatus status) const {
        switch (status) {
            case TLSStatus::HANDSHAKE:  return COLOR_TLS_HANDSHAKE;
            case TLSStatus::CONNECTED:  return COLOR_TLS_CONNECTED;
            case TLSStatus::ENCRYPTING: return COLOR_TLS_ENCRYPTING;
            default:                    return COLOR_TLS_NONE;
        }
    }

    std::string getTLSStatusLabel(TLSStatus status) const {
        switch (status) {
            case TLSStatus::HANDSHAKE:  return "TLS Handshake";
            case TLSStatus::CONNECTED:  return "TLS Connected";
            case TLSStatus::ENCRYPTING: return "TLS Encrypting";
            default:                    return "No TLS";
        }
    }
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_SUMO_VISUALIZER_H
