#ifndef MESHCHAIN_GLOBAL_MAC_CHANNEL_H
#define MESHCHAIN_GLOBAL_MAC_CHANNEL_H

#include <mutex>
#include <queue>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <memory>
#include <functional>
#include <cmath>

namespace meshchain {
namespace integration {

/**
 * Global MAC Channel Simulator
 *
 * Implements a shared IEEE 802.11p wireless channel that coordinates
 * transmissions from all vehicles with realistic CSMA/CA timing.
 *
 * This is a singleton - only one instance exists for the entire simulation.
 */
class GlobalMACChannel {
public:
    struct MACTimingParams {
        static constexpr double SLOT_TIME_US = 13.0;
        static constexpr double SIFS_US = 32.0;
        static constexpr double DIFS_US = 58.0;  // SIFS + 2×SlotTime
        static constexpr int CW_MIN = 15;
        static constexpr int CW_MAX = 1023;
        static constexpr double DATA_RATE_MBPS = 6.0;
        static constexpr double PHY_HEADER_US = 40.0;
    };

    struct PHYParams {
        // IEEE 802.11p @ 5.9 GHz
        static constexpr double FREQUENCY_GHZ = 5.9;
        static constexpr double TX_POWER_DBM = 20.0;  // 100mW
        static constexpr double ANTENNA_GAIN_DBI = 0.0;
        static constexpr double NOISE_FLOOR_DBM = -99.0;
        static constexpr double SENSITIVITY_DBM = -85.0;  // Minimum receivable signal
        static constexpr double SINR_THRESHOLD_DB = 10.0; // Successful decode threshold
        static constexpr double SPEED_OF_LIGHT_MPS = 299792458.0;
        static constexpr double MAX_RANGE_M = 1000.0;  // Maximum communication range
    };

    struct Position {
        double x;
        double y;
        double z = 0.0;
    };

    struct TransmissionRequest {
        std::string node_id;
        std::vector<uint8_t> payload;
        std::chrono::high_resolution_clock::time_point submit_time;
        std::function<void(bool)> callback;  // Called when transmission completes

        // Position for PHY layer simulation
        Position sender_pos;
        bool has_position = false;

        // MAC state
        int backoff_slots;
        int retry_count = 0;
        int contention_window = MACTimingParams::CW_MIN;
    };

    // Singleton access
    static GlobalMACChannel& getInstance() {
        static GlobalMACChannel instance;
        return instance;
    }

    // Delete copy/move constructors
    GlobalMACChannel(const GlobalMACChannel&) = delete;
    GlobalMACChannel& operator=(const GlobalMACChannel&) = delete;

    /**
     * Submit a transmission request (non-blocking)
     * Callback will be invoked when transmission completes
     */
    void submitTransmission(const std::string& node_id,
                           const std::vector<uint8_t>& payload,
                           std::function<void(bool)> callback) {
        TransmissionRequest req;
        req.node_id = node_id;
        req.payload = payload;
        req.submit_time = std::chrono::high_resolution_clock::now();
        req.callback = std::move(callback);
        req.has_position = false;

        // Assign random initial backoff
        std::uniform_int_distribution<int> dist(0, MACTimingParams::CW_MIN);
        req.backoff_slots = dist(rng_);

        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_queue_.push(req);
    }

    /**
     * Submit a transmission request with position (for PHY layer simulation)
     * Callback will be invoked when transmission completes
     */
    void submitTransmission(const std::string& node_id,
                           const std::vector<uint8_t>& payload,
                           const Position& sender_pos,
                           std::function<void(bool)> callback) {
        TransmissionRequest req;
        req.node_id = node_id;
        req.payload = payload;
        req.submit_time = std::chrono::high_resolution_clock::now();
        req.callback = std::move(callback);
        req.sender_pos = sender_pos;
        req.has_position = true;

        // Assign random initial backoff
        std::uniform_int_distribution<int> dist(0, MACTimingParams::CW_MIN);
        req.backoff_slots = dist(rng_);

        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_queue_.push(req);
    }

    /**
     * Start the MAC channel processor thread
     */
    void start() {
        if (running_) return;

        running_ = true;
        processor_thread_ = std::thread(&GlobalMACChannel::processorLoop, this);

        std::cout << "[GlobalMACChannel] ✓ Started with IEEE 802.11p CSMA/CA\n";
        std::cout << "[GlobalMACChannel]   DIFS=" << MACTimingParams::DIFS_US << "μs, "
                  << "SlotTime=" << MACTimingParams::SLOT_TIME_US << "μs, "
                  << "CW=[" << MACTimingParams::CW_MIN << "," << MACTimingParams::CW_MAX << "]\n";

        if (enable_phy_layer_) {
            std::cout << "[GlobalMACChannel]   PHY Layer: ENABLED (FSPL, "
                      << "Range=" << PHYParams::MAX_RANGE_M << "m, "
                      << "TxPower=" << PHYParams::TX_POWER_DBM << "dBm)\n";
        } else {
            std::cout << "[GlobalMACChannel]   PHY Layer: DISABLED (all transmissions succeed)\n";
        }
    }

    /**
     * Stop the MAC channel processor
     */
    void stop() {
        if (!running_) return;

        running_ = false;
        if (processor_thread_.joinable()) {
            processor_thread_.join();
        }

        std::cout << "[GlobalMACChannel] ✓ Stopped (processed " << total_transmissions_ << " packets)\n";
    }

    struct Statistics {
        uint64_t total_transmissions;
        uint64_t total_collisions;
        double avg_backoff_us;
        double channel_utilization;
    };

    Statistics getStatistics() const {
        Statistics stats;
        stats.total_transmissions = total_transmissions_;
        stats.total_collisions = total_collisions_;
        stats.avg_backoff_us = (total_transmissions_ > 0) ?
            (total_backoff_time_us_ / total_transmissions_) : 0.0;
        stats.channel_utilization = 0.0;  // TODO: implement
        return stats;
    }

    /**
     * Enable/disable PHY layer simulation
     * When enabled, transmissions are subject to distance-based attenuation
     * Default: disabled for backward compatibility
     */
    void setEnablePHYLayer(bool enable) {
        enable_phy_layer_ = enable;
    }

    bool isPHYLayerEnabled() const {
        return enable_phy_layer_;
    }

    /**
     * Register/update node position (for PHY layer simulation)
     * Should be called periodically as nodes move
     */
    void updateNodePosition(const std::string& node_id, const Position& pos) {
        std::lock_guard<std::mutex> lock(positions_mutex_);
        node_positions_[node_id] = pos;
    }

    /**
     * Get registered node positions
     */
    std::map<std::string, Position> getNodePositions() const {
        std::lock_guard<std::mutex> lock(positions_mutex_);
        return node_positions_;
    }

private:
    GlobalMACChannel() : running_(false), total_transmissions_(0),
                         total_collisions_(0), total_backoff_time_us_(0.0),
                         channel_busy_until_(std::chrono::high_resolution_clock::now()),
                         enable_phy_layer_(false),
                         rng_(std::random_device{}()) {}

    ~GlobalMACChannel() {
        stop();
    }

    /**
     * Main processor loop - runs in dedicated thread
     */
    void processorLoop() {
        while (running_) {
            TransmissionRequest req;
            bool has_request = false;

            // Get next transmission request
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                if (!pending_queue_.empty()) {
                    req = pending_queue_.front();
                    pending_queue_.pop();
                    has_request = true;
                }
            }

            if (!has_request) {
                // No pending transmissions, sleep briefly
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                continue;
            }

            // Process transmission with CSMA/CA
            bool success = processTransmission(req);

            // Invoke callback
            if (req.callback) {
                req.callback(success);
            }
        }
    }

    /**
     * Process a single transmission with CSMA/CA
     * Returns: true if transmitted successfully
     */
    bool processTransmission(TransmissionRequest& req) {
        auto now = std::chrono::high_resolution_clock::now();

        // Step 1: Wait for DIFS if channel is busy
        if (now < channel_busy_until_) {
            auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(
                channel_busy_until_ - now).count();
            std::this_thread::sleep_for(std::chrono::microseconds(
                static_cast<long long>(wait_us + MACTimingParams::DIFS_US)));
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(
                static_cast<long long>(MACTimingParams::DIFS_US)));
        }

        // Step 2: Backoff countdown
        double backoff_time_us = req.backoff_slots * MACTimingParams::SLOT_TIME_US;
        total_backoff_time_us_ += backoff_time_us;

        std::this_thread::sleep_for(std::chrono::microseconds(
            static_cast<long long>(backoff_time_us)));

        // Step 3: Transmit packet
        double tx_time_us = calculateTransmissionTime(req.payload.size());

        // Mark channel as busy
        now = std::chrono::high_resolution_clock::now();
        channel_busy_until_ = now + std::chrono::microseconds(
            static_cast<long long>(tx_time_us));

        // Actually sleep for transmission time
        std::this_thread::sleep_for(std::chrono::microseconds(
            static_cast<long long>(tx_time_us)));

        total_transmissions_++;

        // PHY layer check is now handled by simulateMessagePropagation
        // GlobalMACChannel only handles MAC timing (CSMA/CA)
        return true;
    }

    /**
     * Calculate transmission time for a packet
     */
    double calculateTransmissionTime(size_t packet_size_bytes) const {
        double phy_header_us = MACTimingParams::PHY_HEADER_US;
        double data_time_us = (packet_size_bytes * 8.0) / MACTimingParams::DATA_RATE_MBPS;
        return phy_header_us + data_time_us;
    }

    /**
     * Calculate distance between two positions
     */
    double calculateDistance(const Position& a, const Position& b) const {
        double dx = a.x - b.x;
        double dy = a.y - b.y;
        double dz = a.z - b.z;
        return std::sqrt(dx*dx + dy*dy + dz*dz);
    }

    /**
     * Calculate path loss using Free Space Path Loss model
     * FSPL(d) = 20*log10(d) + 20*log10(f) + 20*log10(4π/c)
     * Returns: path loss in dB
     */
    double calculatePathLoss(double distance_m) const {
        if (distance_m < 1.0) distance_m = 1.0;  // Avoid log(0)

        double freq_hz = PHYParams::FREQUENCY_GHZ * 1e9;

        // Free space path loss
        double fspl_db = 20.0 * std::log10(distance_m) +
                         20.0 * std::log10(freq_hz) -
                         147.55;  // 20*log10(4π/c) constant

        return fspl_db;
    }

    /**
     * Calculate received signal strength
     * RSS = TX_POWER + TX_GAIN + RX_GAIN - PATH_LOSS
     * Returns: received power in dBm
     */
    double calculateRSS(double distance_m) const {
        double path_loss = calculatePathLoss(distance_m);
        double rss = PHYParams::TX_POWER_DBM +
                     PHYParams::ANTENNA_GAIN_DBI +
                     PHYParams::ANTENNA_GAIN_DBI -
                     path_loss;
        return rss;
    }

    /**
     * Check if signal can be received at given distance
     * Returns: true if RSS > sensitivity threshold
     */
    bool canReceive(double distance_m) const {
        if (distance_m > PHYParams::MAX_RANGE_M) {
            return false;
        }
        double rss = calculateRSS(distance_m);
        return rss >= PHYParams::SENSITIVITY_DBM;
    }

    /**
     * Calculate propagation delay
     * Returns: delay in microseconds
     */
    double calculatePropagationDelay(double distance_m) const {
        return (distance_m / PHYParams::SPEED_OF_LIGHT_MPS) * 1e6;  // Convert to μs
    }

    // Singleton instance state
    std::atomic<bool> running_;
    std::thread processor_thread_;

    // Transmission queue
    std::queue<TransmissionRequest> pending_queue_;
    std::mutex queue_mutex_;

    // Channel state
    std::chrono::high_resolution_clock::time_point channel_busy_until_;
    std::mutex channel_mutex_;

    // Statistics
    std::atomic<uint64_t> total_transmissions_;
    std::atomic<uint64_t> total_collisions_;
    double total_backoff_time_us_;  // Protected by queue_mutex_

    // PHY layer configuration
    std::atomic<bool> enable_phy_layer_;
    std::map<std::string, Position> node_positions_;  // Node positions for PHY simulation
    mutable std::mutex positions_mutex_;

    // RNG for backoff
    std::mt19937 rng_;
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_GLOBAL_MAC_CHANNEL_H
