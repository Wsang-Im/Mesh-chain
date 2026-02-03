#ifndef MESHCHAIN_REALISTIC_MAC_LAYER_H
#define MESHCHAIN_REALISTIC_MAC_LAYER_H

/**
 * Realistic IEEE 802.11p MAC Layer Simulation
 *
 * Implements actual CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance)
 * WITHOUT OMNeT++ dependency - pure C++ simulation
 *
 * Features:
 * - DIFS (Distributed Inter-Frame Space) waiting
 * - Random backoff with exponential increase
 * - Collision detection
 * - Channel busy sensing (CCA - Clear Channel Assessment)
 * - Actual transmission time calculation
 *
 * Based on IEEE 802.11p-2010 specification
 */

#include <chrono>
#include <queue>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <vector>

namespace meshchain {
namespace integration {

/**
 * IEEE 802.11p MAC timing parameters (from standard)
 */
struct MACTimingParams {
    // Slot time: duration of one backoff slot (13 μs for 802.11p @ 5.9 GHz)
    static constexpr double SLOT_TIME_US = 13.0;

    // SIFS: Short Inter-Frame Space (32 μs)
    static constexpr double SIFS_US = 32.0;

    // DIFS: Distributed Inter-Frame Space = SIFS + 2 × SlotTime = 58 μs
    static constexpr double DIFS_US = SIFS_US + 2.0 * SLOT_TIME_US;

    // Minimum contention window (CW_min = 15 for 802.11p)
    static constexpr int CW_MIN = 15;

    // Maximum contention window (CW_max = 1023 for 802.11p)
    static constexpr int CW_MAX = 1023;

    // Maximum number of retransmission attempts
    static constexpr int MAX_RETRIES = 7;

    // Data rate (6 Mbps for QPSK 1/2 in 802.11p)
    static constexpr double DATA_RATE_MBPS = 6.0;

    // PHY header transmission time (PLCP preamble + header, ~40 μs)
    static constexpr double PHY_HEADER_US = 40.0;
};

/**
 * Packet waiting for transmission
 */
struct PendingPacket {
    std::string packet_id;
    std::vector<uint8_t> payload;
    std::chrono::high_resolution_clock::time_point enqueue_time;
    int retry_count;
    int contention_window;  // Current CW value
    int backoff_slots;      // Remaining backoff slots

    PendingPacket() : retry_count(0), contention_window(MACTimingParams::CW_MIN), backoff_slots(0) {}
};

/**
 * Channel state for collision detection
 */
class ChannelState {
public:
    ChannelState() : busy_until_(std::chrono::high_resolution_clock::now()) {}

    // Check if channel is busy
    bool isBusy() const {
        auto now = std::chrono::high_resolution_clock::now();
        return now < busy_until_;
    }

    // Mark channel as busy for duration (in microseconds)
    void markBusy(double duration_us) {
        auto now = std::chrono::high_resolution_clock::now();
        auto busy_duration = std::chrono::microseconds(static_cast<long long>(duration_us));
        busy_until_ = now + busy_duration;
    }

    // Get remaining busy time in microseconds
    double getRemainingBusyTime() const {
        auto now = std::chrono::high_resolution_clock::now();
        if (now >= busy_until_) return 0.0;

        auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(busy_until_ - now);
        return static_cast<double>(remaining.count());
    }

private:
    std::chrono::high_resolution_clock::time_point busy_until_;
    mutable std::mutex mutex_;
};

/**
 * Realistic IEEE 802.11p MAC Layer
 *
 * This simulates the actual MAC behavior without requiring OMNeT++
 */
class RealisticMACLayer {
public:
    RealisticMACLayer()
        : rng_(std::random_device{}()),
          total_packets_sent_(0),
          total_collisions_(0),
          total_retries_(0),
          total_backoff_time_us_(0) {}

    /**
     * Enqueue packet for transmission
     *
     * @param packet_id Unique identifier
     * @param payload Packet data (already encrypted if using TLS)
     */
    void enqueuePacket(const std::string& packet_id, const std::vector<uint8_t>& payload) {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        PendingPacket pkt;
        pkt.packet_id = packet_id;
        pkt.payload = payload;
        pkt.enqueue_time = std::chrono::high_resolution_clock::now();

        // Initialize random backoff
        std::uniform_int_distribution<int> backoff_dist(0, pkt.contention_window);
        pkt.backoff_slots = backoff_dist(rng_);

        tx_queue_.push(pkt);
    }

    /**
     * Calculate MAC delay for next packet (non-blocking)
     *
     * Returns: delay in microseconds, or -1 if queue is empty
     */
    double calculateMACDelay() {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        if (tx_queue_.empty()) return -1.0;

        PendingPacket& pkt = tx_queue_.front();

        double total_delay_us = 0.0;

        // Step 1: DIFS wait
        if (channel_.isBusy()) {
            total_delay_us += channel_.getRemainingBusyTime() + MACTimingParams::DIFS_US;
        } else {
            total_delay_us += MACTimingParams::DIFS_US;
        }

        // Step 2: Backoff time
        total_delay_us += pkt.backoff_slots * MACTimingParams::SLOT_TIME_US;
        total_backoff_time_us_ += pkt.backoff_slots * MACTimingParams::SLOT_TIME_US;

        // Step 3: Transmission time
        double tx_time_us = calculateTransmissionTime(pkt.payload.size());
        total_delay_us += tx_time_us;

        // Mark channel as busy
        channel_.markBusy(tx_time_us);

        // Update stats
        total_packets_sent_++;
        tx_queue_.pop();

        return total_delay_us;
    }

    /**
     * Attempt to transmit next packet with CSMA/CA
     *
     * Returns: true if packet was transmitted, false if still waiting
     */
    bool processTransmission() {
        // Calculate delay without holding mutex during sleep
        double delay_us = calculateMACDelay();

        if (delay_us < 0) return false;  // Queue empty

        // Now sleep OUTSIDE the mutex
        std::this_thread::sleep_for(
            std::chrono::microseconds(static_cast<long long>(delay_us))
        );

        return true;
    }

    /**
     * Simulate collision (called when multiple nodes transmit simultaneously)
     *
     * In real 802.11p, collisions are detected by missing ACK (for unicast)
     * or by corruption (bit errors). For broadcast (V2X CAM/DENM), there's no ACK,
     * so collision just causes packet loss at receiver.
     */
    void handleCollision() {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        if (tx_queue_.empty()) return;

        PendingPacket& pkt = tx_queue_.front();

        total_collisions_++;
        pkt.retry_count++;

        if (pkt.retry_count >= MACTimingParams::MAX_RETRIES) {
            // Max retries reached, drop packet
            tx_queue_.pop();
            return;
        }

        // Exponential backoff: CW = min(2 × CW, CW_max)
        pkt.contention_window = std::min(pkt.contention_window * 2, MACTimingParams::CW_MAX);

        // Choose new random backoff
        std::uniform_int_distribution<int> backoff_dist(0, pkt.contention_window);
        pkt.backoff_slots = backoff_dist(rng_);

        total_retries_++;
    }

    /**
     * Calculate transmission time for a packet
     *
     * Time = PHY_header + (packet_size × 8 / data_rate)
     */
    double calculateTransmissionTime(size_t packet_size_bytes) const {
        // PHY header time (PLCP preamble + header)
        double phy_header_us = MACTimingParams::PHY_HEADER_US;

        // Data transmission time
        double data_time_us = (packet_size_bytes * 8.0) / MACTimingParams::DATA_RATE_MBPS;

        return phy_header_us + data_time_us;
    }

    /**
     * Check if transmission queue is empty
     */
    bool isEmpty() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return tx_queue_.empty();
    }

    /**
     * Get queue size
     */
    size_t getQueueSize() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return tx_queue_.size();
    }

    /**
     * Get statistics
     */
    struct Statistics {
        size_t packets_sent;
        size_t collisions;
        size_t retries;
        double avg_backoff_time_us;
    };

    Statistics getStatistics() const {
        Statistics stats;
        stats.packets_sent = total_packets_sent_.load();
        stats.collisions = total_collisions_.load();
        stats.retries = total_retries_.load();
        stats.avg_backoff_time_us = stats.packets_sent > 0
            ? (total_backoff_time_us_ / stats.packets_sent)
            : 0.0;
        return stats;
    }

    /**
     * Get channel state (for external coordination)
     */
    ChannelState& getChannel() { return channel_; }
    const ChannelState& getChannel() const { return channel_; }

private:
    std::queue<PendingPacket> tx_queue_;
    mutable std::mutex queue_mutex_;
    std::mt19937 rng_;
    ChannelState channel_;

    // Statistics
    std::atomic<size_t> total_packets_sent_;
    std::atomic<size_t> total_collisions_;
    std::atomic<size_t> total_retries_;
    double total_backoff_time_us_;  // Protected by queue_mutex_
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_REALISTIC_MAC_LAYER_H
