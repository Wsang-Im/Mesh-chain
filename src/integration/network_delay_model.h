#ifndef MESHCHAIN_NETWORK_DELAY_MODEL_H
#define MESHCHAIN_NETWORK_DELAY_MODEL_H

#include <random>
#include <chrono>
#include <thread>
#include <cmath>

namespace meshchain {
namespace integration {

/**
 * IEEE 802.11p (WAVE) Network Delay Model
 * 
 * Simulates realistic V2V communication delays including:
 * - Propagation delay (distance-based)
 * - Transmission delay (packet size-based)
 * - Queuing delay (congestion-based)
 * - Processing delay (hardware/software)
 */
class NetworkDelayModel {
public:
    struct Config {
        double bandwidth_mbps = 6.0;         // DSRC/WAVE typical: 6 Mbps
        double processing_delay_ms = 2.0;    // PHY/MAC processing
        double base_queuing_delay_ms = 1.0;  // Minimum queue delay
        double congestion_factor = 1.5;      // Multiplier for congested networks
        bool enable_delays = true;           // Can disable for testing
    };

private:
    Config config_;
    std::mt19937 rng_;
    
    static constexpr double SPEED_OF_LIGHT_M_PER_MS = 299792.458;  // meters per millisecond

public:
    NetworkDelayModel()
        : config_() {
        std::random_device rd;
        rng_.seed(rd());
    }

    explicit NetworkDelayModel(const Config& config)
        : config_(config) {
        std::random_device rd;
        rng_.seed(rd());
    }

    /**
     * Calculate total network delay for a packet transmission
     * 
     * @param distance_m Distance between sender and receiver (meters)
     * @param packet_size_bytes Size of packet to transmit
     * @param num_active_nodes Number of active nodes (for congestion)
     * @return Total delay in milliseconds
     */
    double calculateDelay(double distance_m, size_t packet_size_bytes, size_t num_active_nodes = 10) {
        if (!config_.enable_delays) {
            return 0.0;
        }

        // 1. Propagation delay: time for signal to travel distance
        double propagation_ms = distance_m / SPEED_OF_LIGHT_M_PER_MS;

        // 2. Transmission delay: time to put bits on the wire
        //    delay = packet_size_bits / bandwidth_bps
        double packet_size_bits = packet_size_bytes * 8.0;
        double bandwidth_bps = config_.bandwidth_mbps * 1'000'000.0;
        double transmission_ms = (packet_size_bits / bandwidth_bps) * 1000.0;

        // 3. Queuing delay: depends on network congestion
        //    More active nodes = more contention for channel
        double congestion_level = std::min(2.0, num_active_nodes / 20.0);  // Cap at 2x
        double queuing_ms = config_.base_queuing_delay_ms * congestion_level * config_.congestion_factor;
        
        // Add randomness to queuing delay (exponential distribution)
        std::exponential_distribution<double> exp_dist(1.0 / queuing_ms);
        queuing_ms = exp_dist(rng_);

        // 4. Processing delay: PHY/MAC layer processing
        double processing_ms = config_.processing_delay_ms;

        // Add small random jitter to processing delay
        std::normal_distribution<double> jitter_dist(0.0, 0.5);
        processing_ms += std::abs(jitter_dist(rng_));

        // Total delay
        double total_ms = propagation_ms + transmission_ms + queuing_ms + processing_ms;

        return total_ms;
    }

    /**
     * Calculate delay for ML-KEM encapsulation message
     * (Typically ~1KB ciphertext + ~1KB public key)
     */
    double calculateKEMDelay(double distance_m, size_t num_active_nodes = 10) {
        constexpr size_t KEM_PACKET_SIZE = 2048;  // ~2KB for ML-KEM-768
        return calculateDelay(distance_m, KEM_PACKET_SIZE, num_active_nodes);
    }

    /**
     * Calculate delay for witness signature request
     * (Typically several KB with header, merkle path, etc.)
     */
    double calculateSigRequestDelay(double distance_m, size_t num_active_nodes = 10) {
        constexpr size_t SIG_REQ_SIZE = 4096;  // ~4KB for signature request
        return calculateDelay(distance_m, SIG_REQ_SIZE, num_active_nodes);
    }

    /**
     * Calculate delay for witness signature response
     * (Typically ~700 bytes for FALCON-512 signature)
     */
    double calculateSigResponseDelay(double distance_m, size_t num_active_nodes = 10) {
        constexpr size_t SIG_RESP_SIZE = 800;  // ~800 bytes for signature response
        return calculateDelay(distance_m, SIG_RESP_SIZE, num_active_nodes);
    }

    /**
     * Simulate network delay by actually sleeping
     * 
     * @param delay_ms Delay in milliseconds
     */
    static void simulateDelay(double delay_ms) {
        if (delay_ms > 0.0) {
            auto duration = std::chrono::microseconds(static_cast<long long>(delay_ms * 1000.0));
            std::this_thread::sleep_for(duration);
        }
    }

    /**
     * Get round-trip time (RTT) for request-response pattern
     */
    double calculateRTT(double distance_m, size_t request_size, size_t response_size, size_t num_active_nodes = 10) {
        double request_delay = calculateDelay(distance_m, request_size, num_active_nodes);
        double response_delay = calculateDelay(distance_m, response_size, num_active_nodes);
        return request_delay + response_delay;
    }
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_NETWORK_DELAY_MODEL_H
