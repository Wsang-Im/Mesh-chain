#ifndef MESHCHAIN_TOF_ADAPTER_H
#define MESHCHAIN_TOF_ADAPTER_H

#include "../crypto/tof_measurement.h"
#include "traci_client.h"
#include <memory>

namespace meshchain {
namespace integration {

/**
 * ToF Adapter for SUMO Integration
 *
 * Bridges ToF measurement system with SUMO's actual vehicle positions
 * - Uses real distances from SUMO TraCI
 * - Simulates UWB/PHY timestamps based on actual propagation time
 * - Provides authentic ToF transcripts for witness verification
 */
class ToFAdapter {
public:
    struct Config {
        std::string vehicle_id;
        double sigma_tof_ns;        // ToF estimator std deviation (default: 3.0 ns)
        bool use_uwb;               // Use UWB (true) or PHY-assisted C-V2X (false)
        double channel_noise_db;    // Channel noise level
    };

private:
    Config config_;
    std::shared_ptr<TraCIClient> traci_;
    std::shared_ptr<crypto::ToFMeasurement> tof_measurement_;

public:
    explicit ToFAdapter(const Config& config, std::shared_ptr<TraCIClient> traci)
        : config_(config), traci_(traci) {

        // Initialize ToF measurement engine
        crypto::ToFMeasurement::Config tof_config;
        tof_config.sigma_tof_ns = config.sigma_tof_ns;
        tof_config.max_distance_m = 300.0;  // DSRC range
        tof_config.use_uwb = config.use_uwb;
        tof_config.channel_noise_db = config.channel_noise_db;

        tof_measurement_ = std::make_shared<crypto::ToFMeasurement>(tof_config);
    }

    /**
     * Measure ToF to a target vehicle using SUMO's real distance
     *
     * @param target_vehicle_id ID of the target vehicle
     * @param is_relay_attack Simulate relay attack (for testing)
     * @param relay_delay_ns Additional delay from relay (if attack)
     * @return ToF transcript or nullopt if vehicles not in range
     */
    std::optional<ToFTranscript> measureToVehicle(
            const std::string& target_vehicle_id,
            bool is_relay_attack = false,
            double relay_delay_ns = 0.0) {

        // Get actual distance from SUMO
        auto distance_opt = traci_->getDistance(config_.vehicle_id, target_vehicle_id);
        if (!distance_opt.has_value()) {
            // Vehicles not in simulation or too far
            return std::nullopt;
        }

        double actual_distance_m = *distance_opt;

        // Perform ToF measurement using actual distance
        ToFTranscript transcript = tof_measurement_->measure(
            actual_distance_m,
            is_relay_attack,
            relay_delay_ns
        );

        return transcript;
    }

    /**
     * Verify ToF transcript
     *
     * @param transcript ToF measurement result
     * @param target_vehicle_id ID of target vehicle (to check actual distance)
     * @return true if measurement is valid and matches actual distance
     */
    bool verify(const ToFTranscript& transcript, const std::string& target_vehicle_id) {
        // Get actual distance from SUMO
        auto distance_opt = traci_->getDistance(config_.vehicle_id, target_vehicle_id);
        if (!distance_opt.has_value()) {
            return false;
        }

        double actual_distance_m = *distance_opt;

        // Verify ToF using actual distance
        return tof_measurement_->verify(transcript, actual_distance_m);
    }

    /**
     * Get all vehicles in ToF range with their measured distances
     *
     * @param max_range_m Maximum range to consider
     * @return Map of vehicle_id -> ToF transcript
     */
    std::map<std::string, ToFTranscript> measureAllInRange(double max_range_m = 300.0) {
        std::map<std::string, ToFTranscript> results;

        // Get all vehicles in range from SUMO
        auto vehicles_in_range = traci_->getVehiclesInRange(config_.vehicle_id, max_range_m);

        for (const auto& target_id : vehicles_in_range) {
            auto transcript_opt = measureToVehicle(target_id);
            if (transcript_opt.has_value()) {
                results[target_id] = *transcript_opt;
            }
        }

        return results;
    }

    /**
     * Get minimum spatial separation requirement
     */
    double getMinimumSpatialSeparation() const {
        return tof_measurement_->getMinimumSpatialSeparation();
    }

    /**
     * Detect relay/mafia fraud by comparing ToF with expected distance
     */
    bool detectRelayFraud(const ToFTranscript& transcript,
                         const std::string& target_vehicle_id) {
        auto distance_opt = traci_->getDistance(config_.vehicle_id, target_vehicle_id);
        if (!distance_opt.has_value()) {
            return true;  // Suspicious: vehicle not found
        }

        double expected_distance_m = *distance_opt;
        return tof_measurement_->detectRelayFraud(transcript, expected_distance_m);
    }

    /**
     * Get underlying ToFMeasurement instance
     */
    std::shared_ptr<crypto::ToFMeasurement> getToFMeasurement() const {
        return tof_measurement_;
    }
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_TOF_ADAPTER_H
