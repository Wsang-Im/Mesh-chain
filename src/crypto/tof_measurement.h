#ifndef MESHCHAIN_TOF_MEASUREMENT_H
#define MESHCHAIN_TOF_MEASUREMENT_H

#include "../common/types.h"
#include <random>
#include <cmath>
#include <thread>

namespace meshchain {
namespace crypto {

/**
 * ToF (Time of Flight) Distance Bounding
 *
 * Critical requirements from paper:
 * - Nanosecond-grade tolerance εtof ≤ 10 ns
 * - UWB or PHY-assisted C-V2X timestamps
 * - RSSI is NEVER used as a distance bound (only coarse prior)
 * - Resistance to relay/mafia fraud
 *
 * Physics: c = 299,792,458 m/s
 * 10ns tolerance → ~3m distance uncertainty
 */
class ToFMeasurement {
public:
    // Speed of light in m/ns
    static constexpr double SPEED_OF_LIGHT_M_PER_NS = 0.299792458;

    struct Config {
        double sigma_tof_ns;  // Standard deviation of ToF estimator
        double max_distance_m;  // Maximum valid distance
        bool use_uwb;  // Use UWB (true) or PHY-assisted C-V2X (false)
        double channel_noise_db;  // Channel noise level
    };

private:
    Config config_;
    std::mt19937_64 rng_;
    std::normal_distribution<double> jitter_dist_;

public:
    explicit ToFMeasurement(const Config& config, uint64_t seed = 0)
        : config_(config),
          rng_(seed == 0 ? std::random_device{}() : seed),
          jitter_dist_(0.0, config.sigma_tof_ns) {
    }

    /**
     * Perform ToF challenge-response measurement
     *
     * @param actual_distance_m True distance between nodes
     * @param is_relay_attack Simulate relay attack (adds delay)
     * @param relay_delay_ns Additional delay from relay (if attack)
     * @return ToF transcript with challenge/response timestamps
     */
    ToFTranscript measure(double actual_distance_m,
                         bool is_relay_attack = false,
                         double relay_delay_ns = 0.0) {
        ToFTranscript transcript;

        // CRITICAL: Use thread-local RNG for thread safety!
        // Each thread gets its own random number generator
        // Use thread ID + timestamp for unique seed per thread
        thread_local std::mt19937_64 local_rng(
            std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
            std::chrono::steady_clock::now().time_since_epoch().count()
        );

        // Generate random nonce for challenge
        std::uniform_int_distribution<Nonce> nonce_dist;
        transcript.nonce = nonce_dist(local_rng);

        // Challenge sent at t0
        transcript.t0 = std::chrono::system_clock::now();

        // Calculate propagation time (round trip)
        double propagation_ns = 2.0 * actual_distance_m / SPEED_OF_LIGHT_M_PER_NS;

        // Add measurement jitter (hardware noise)
        // Create distribution per call (lightweight, ensures correct sigma)
        std::normal_distribution<double> jitter_dist(0.0, config_.sigma_tof_ns);
        double measurement_jitter = jitter_dist(local_rng);

        // Add processing delay (realistic UWB/PHY timestamps)
        double processing_delay_ns = config_.use_uwb ?
            getUWBProcessingDelay() :
            getPHYProcessingDelay();

        // Total delay
        double total_delay_ns = propagation_ns +
                               processing_delay_ns +
                               measurement_jitter;

        // If relay attack, add relay delay
        if (is_relay_attack) {
            total_delay_ns += relay_delay_ns;
        }

        // Response received at t1
        auto delay_duration = std::chrono::nanoseconds(
            static_cast<int64_t>(total_delay_ns)
        );
        transcript.t1 = transcript.t0 + delay_duration;

        // Hardware proof (would contain cryptographic binding in real impl)
        // For simulation, just store some metadata
        transcript.pi_hw = generateHardwareProof(transcript.nonce);

        return transcript;
    }

    /**
     * Verify ToF transcript against policy
     *
     * @param transcript ToF measurement result
     * @param max_distance_m Maximum allowed distance
     * @return true if measurement is valid and within bounds
     */
    bool verify(const ToFTranscript& transcript, double max_distance_m) const {
        // Calculate RTT
        double rtt_ns = transcript.getRTT_ns();

        // Convert to distance
        double measured_distance_m = (rtt_ns * SPEED_OF_LIGHT_M_PER_NS) / 2.0;

        // Check against max distance with tolerance for processing delay
        // Processing delay can add up to 15ns (PHY mode), which is ~2.25m in distance
        // Add 5m tolerance to account for processing delay + measurement jitter
        double distance_tolerance_m = 5.0;
        if (measured_distance_m > (max_distance_m + distance_tolerance_m)) {
            return false;
        }

        // Estimate jitter from multiple measurements (simplified here)
        double estimated_jitter_ns = estimateJitter(transcript);

        // Check jitter tolerance (critical: ≤ 10ns)
        // STRICT: Always enforce 10ns tolerance for security evaluation
        if (estimated_jitter_ns > TOF_TOLERANCE_NS) {
            return false;
        }

        // Verify hardware proof (simplified)
        // In simulation, skip hardware proof verification
        #ifdef USE_LIBOQS
            if (!verifyHardwareProof(transcript.pi_hw, transcript.nonce)) {
                return false;
            }
        #endif

        return true;
    }

    /**
     * Calculate minimum spatial separation for diversity
     *
     * Per paper: d_min ≥ 3σ_tof
     */
    double getMinimumSpatialSeparation() const {
        return 3.0 * config_.sigma_tof_ns * SPEED_OF_LIGHT_M_PER_NS;
    }

    /**
     * Detect potential relay/mafia fraud
     *
     * @param transcript ToF measurement
     * @param expected_distance_m Expected distance from other sensors
     * @return true if relay attack is suspected
     */
    bool detectRelayFraud(const ToFTranscript& transcript,
                          double expected_distance_m) const {
        double rtt_ns = transcript.getRTT_ns();
        double measured_distance_m = (rtt_ns * SPEED_OF_LIGHT_M_PER_NS) / 2.0;

        // If measured distance significantly exceeds expected (beyond noise)
        double threshold = 3.0 * config_.sigma_tof_ns * SPEED_OF_LIGHT_M_PER_NS;
        if (measured_distance_m > expected_distance_m + threshold) {
            return true;  // Likely relay
        }

        // Check for suspiciously consistent timing (relay devices often have
        // very stable delays)
        // In real implementation, this would analyze multiple measurements

        return false;
    }

private:
    // UWB processing delay (typical range: 1-10 ns)
    static double getUWBProcessingDelay() {
        thread_local std::mt19937_64 local_rng(
            std::hash<std::thread::id>{}(std::this_thread::get_id()) + 1);
        std::uniform_real_distribution<double> dist(1.0, 5.0);
        return dist(local_rng);
    }

    // PHY-assisted C-V2X processing delay (typically higher than UWB)
    static double getPHYProcessingDelay() {
        thread_local std::mt19937_64 local_rng(
            std::hash<std::thread::id>{}(std::this_thread::get_id()) + 2);
        std::uniform_real_distribution<double> dist(5.0, 15.0);
        return dist(local_rng);
    }

    // Generate hardware proof (simplified for simulation)
    std::vector<uint8_t> generateHardwareProof(Nonce nonce) const {
        std::vector<uint8_t> proof(32);
        // In real implementation, this would be a cryptographic binding
        // For simulation, just hash the nonce
        uint64_t val = nonce;
        for (size_t i = 0; i < 32; ++i) {
            proof[i] = static_cast<uint8_t>((val >> (i % 8)) & 0xFF);
        }
        return proof;
    }

    // Verify hardware proof (simplified)
    bool verifyHardwareProof(const std::vector<uint8_t>& proof, Nonce nonce) const {
        if (proof.size() != 32) return false;
        // In real implementation, verify cryptographic binding
        return true;  // Simplified for simulation
    }

    // Estimate jitter from transcript (simplified)
    double estimateJitter(const ToFTranscript& transcript) const {
        // In real implementation, would compare multiple measurements
        // For simulation, estimate from configured sigma
        return config_.sigma_tof_ns;
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_TOF_MEASUREMENT_H
