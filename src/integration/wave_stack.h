#ifndef MESHCHAIN_WAVE_STACK_H
#define MESHCHAIN_WAVE_STACK_H

#include "../common/types.h"
#include "../common/v2x_messages.h"
#include "traci_client.h"
#include <queue>
#include <random>
#include <chrono>
#include <functional>

namespace meshchain {
namespace integration {

/**
 * WAVE (IEEE 802.11p) Communication Stack
 *
 * Implements V2V and V2I communication using DSRC/WAVE:
 * - PHY layer: 5.9 GHz DSRC band, OFDM modulation
 * - MAC layer: CSMA/CA with priority access
 * - Network layer: WSMP (WAVE Short Message Protocol)
 * - Application layer: CAM, DENM, CPM messages
 *
 * Key parameters from IEEE 802.11p:
 * - Data rate: 3-27 Mbps (typically 6 Mbps)
 * - Range: 300m (DSRC) or 1000m (C-V2X)
 * - Latency: <100ms for safety messages
 * - Packet loss: 10-30% in urban environments
 */
class WaveStack {
public:
    struct Config {
        std::string node_id;
        double tx_power_dbm;        // Transmission power (default: 20 dBm)
        double frequency_ghz;       // Frequency (default: 5.9 GHz)
        double bandwidth_mhz;       // Bandwidth (default: 10 MHz)
        double data_rate_mbps;      // Data rate (default: 6 Mbps)
        double range_m;             // Communication range (default: 300m)
        double packet_loss_rate;    // Packet loss probability (default: 0.2)
        int cam_interval_ms;        // CAM broadcast interval (default: 100ms)
        int denm_priority;          // DENM priority (0-7, default: 6)
        bool enable_realistic_mac = false;  // Enable CSMA/CA MAC layer (default: false for backward compatibility)
    };

    enum class MessageType {
        CAM,    // Cooperative Awareness Message
        DENM,   // Decentralized Environmental Notification Message
        CPM,    // Collective Perception Message
        CUSTOM  // Custom application message
    };

    struct WaveMessage {
        MessageType type;
        std::string sender_id;
        std::string receiver_id;  // Empty for broadcast
        Timestamp sent_at;
        Timestamp received_at;
        std::vector<uint8_t> payload;
        int priority;  // 0-7 (7 = highest)

        // V2X message content (decoded)
        std::optional<CAM> cam;
        std::optional<DENM> denm;
        std::optional<CPM> cpm;
    };

    using MessageCallback = std::function<void(const WaveMessage&)>;

private:
    Config config_;
    std::shared_ptr<TraCIClient> traci_;

    // Message queues by priority
    std::array<std::queue<WaveMessage>, 8> tx_queues_;
    std::queue<WaveMessage> rx_queue_;

    // Statistics
    size_t messages_sent_;
    size_t messages_received_;
    size_t messages_lost_;

    // Random number generation for packet loss
    std::mt19937_64 rng_;
    std::uniform_real_distribution<double> loss_dist_;

    // Callbacks
    std::map<MessageType, std::vector<MessageCallback>> callbacks_;

    // Communication log for V2XRecord
    std::vector<CAM> cams_sent_;
    std::vector<CAM> cams_received_;
    std::vector<DENM> denms_sent_;
    std::vector<DENM> denms_received_;
    std::vector<CPM> cpms_sent_;
    std::vector<CPM> cpms_received_;

public:
    explicit WaveStack(const Config& config, std::shared_ptr<TraCIClient> traci)
        : config_(config),
          traci_(traci),
          messages_sent_(0),
          messages_received_(0),
          messages_lost_(0),
          rng_(std::random_device{}()),
          loss_dist_(0.0, 1.0) {
    }

    /**
     * Broadcast CAM (Cooperative Awareness Message)
     * Called periodically (every 100ms) to share vehicle state
     * @param sender_reputation Sender's reputation score (for witness selection)
     */
    void broadcastCAM(double sender_reputation = 0.5) {
        auto vehicle_state = traci_->getVehicleState(config_.node_id);
        if (!vehicle_state.has_value()) return;

        // Create CAM
        CAM cam;
        cam.sender_id = config_.node_id;
        cam.generation_time = std::chrono::system_clock::now();

        // Position and kinematics
        cam.position.timestamp = cam.generation_time;
        cam.position.latitude = vehicle_state->y;  // Simplified
        cam.position.longitude = vehicle_state->x;
        cam.position.altitude_m = vehicle_state->z;
        cam.position.speed_mps = vehicle_state->speed_mps;
        cam.position.heading_deg = vehicle_state->heading_deg;
        cam.position.acceleration_mps2 = 0.0; // Would need to calculate from speed history

        // Vehicle profile
        cam.vehicle_length_m = 4.5;
        cam.vehicle_width_m = 2.0;
        cam.vehicle_type = "passenger";

        // Sensor capabilities
        cam.has_radar = true;
        cam.has_lidar = false;
        cam.has_camera = true;

        // Reputation (for witness selection diversity)
        cam.sender_reputation = sender_reputation;

        // Serialize and send
        WaveMessage msg;
        msg.type = MessageType::CAM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = "";  // Broadcast
        msg.sent_at = cam.generation_time;
        msg.priority = 3;  // Medium priority for CAM
        msg.cam = cam;
        msg.payload = cam.serialize();

        sendMessage(msg);
        cams_sent_.push_back(cam);
    }

    /**
     * Send DENM (Decentralized Environmental Notification Message)
     * Used for event-driven warnings (accidents, hazards, etc.)
     */
    void sendDENM(const DENM& denm) {
        WaveMessage msg;
        msg.type = MessageType::DENM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = "";  // Broadcast
        msg.sent_at = std::chrono::system_clock::now();
        msg.priority = config_.denm_priority;  // High priority
        msg.denm = denm;
        msg.payload = denm.serialize();

        sendMessage(msg);
        denms_sent_.push_back(denm);
    }

    /**
     * Send CPM (Collective Perception Message)
     * Shares detected objects from sensors
     */
    void sendCPM(const CPM& cpm) {
        WaveMessage msg;
        msg.type = MessageType::CPM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = "";  // Broadcast
        msg.sent_at = std::chrono::system_clock::now();
        msg.priority = 4;  // Medium-high priority
        msg.cpm = cpm;
        msg.payload = cpm.serialize();

        sendMessage(msg);
        cpms_sent_.push_back(cpm);
    }

    /**
     * Send P2P message to specific vehicle
     */
    void sendP2P(const std::string& receiver_id, const std::vector<uint8_t>& payload) {
        WaveMessage msg;
        msg.type = MessageType::CUSTOM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = receiver_id;
        msg.sent_at = std::chrono::system_clock::now();
        msg.priority = 5;  // High priority for P2P
        msg.payload = payload;

        sendMessage(msg);
    }

    /**
     * Process received messages
     * Should be called regularly to handle incoming messages
     */
    void processReceivedMessages() {
        while (!rx_queue_.empty()) {
            WaveMessage msg = rx_queue_.front();
            rx_queue_.pop();

            // Invoke callbacks
            auto it = callbacks_.find(msg.type);
            if (it != callbacks_.end()) {
                for (auto& callback : it->second) {
                    callback(msg);
                }
            }

            // Log received messages
            if (msg.cam.has_value()) {
                cams_received_.push_back(*msg.cam);
            }
            if (msg.denm.has_value()) {
                denms_received_.push_back(*msg.denm);
            }
            if (msg.cpm.has_value()) {
                cpms_received_.push_back(*msg.cpm);
            }
        }
    }

    /**
     * Register callback for message type
     */
    void registerCallback(MessageType type, MessageCallback callback) {
        callbacks_[type].push_back(callback);
    }

    /**
     * Get communication log for creating V2XRecord
     */
    V2XRecord getV2XRecord() {
        V2XRecord record;
        auto now = std::chrono::system_clock::now();
        record.record_end = now;
        record.record_start = now - std::chrono::seconds(1);  // Last 1 second
        record.recorder_id = config_.node_id;

        // Copy communication logs
        record.cams_sent = cams_sent_;
        record.denms_sent = denms_sent_;
        record.cpms_sent = cpms_sent_;
        record.denms_received = denms_received_;
        record.cpms_received = cpms_received_;

        // Statistics
        record.total_neighbors = 0;  // Would count from neighbor list

        // Clear logs for next period
        cams_sent_.clear();
        cams_received_.clear();
        denms_sent_.clear();
        denms_received_.clear();
        cpms_sent_.clear();
        cpms_received_.clear();

        return record;
    }

    /**
     * Get statistics
     */
    void getStatistics(size_t& sent, size_t& received, size_t& lost) const {
        sent = messages_sent_;
        received = messages_received_;
        lost = messages_lost_;
    }

    /**
     * Simulate message propagation to all vehicles in range
     * In OMNET++, this would be handled by the wireless channel model
     */
    void simulateMessagePropagation(std::map<std::string, std::shared_ptr<WaveStack>>& all_stacks) {
        // Process all pending transmissions
        for (int priority = 7; priority >= 0; --priority) {
            while (!tx_queues_[priority].empty()) {
                WaveMessage msg = tx_queues_[priority].front();
                tx_queues_[priority].pop();

                // Get sender position
                auto sender_pos = traci_->getVehicleState(config_.node_id);
                if (!sender_pos.has_value()) continue;

                // Determine receivers based on message type
                std::vector<std::string> receivers;
                if (msg.receiver_id.empty()) {
                    // Broadcast: all vehicles in range
                    receivers = traci_->getVehiclesInRange(config_.node_id, config_.range_m);
                } else {
                    // Unicast: specific vehicle if in range
                    auto dist = traci_->getDistance(config_.node_id, msg.receiver_id);
                    if (dist.has_value() && *dist <= config_.range_m) {
                        receivers.push_back(msg.receiver_id);
                    }
                }

                // Deliver to receivers with packet loss
                for (const auto& receiver_id : receivers) {
                    // Simulate packet loss
                    if (loss_dist_(rng_) < config_.packet_loss_rate) {
                        messages_lost_++;
                        continue;
                    }

                    // Deliver message
                    auto it = all_stacks.find(receiver_id);
                    if (it != all_stacks.end()) {
                        WaveMessage rx_msg = msg;
                        rx_msg.received_at = std::chrono::system_clock::now();
                        it->second->receiveMessage(rx_msg);
                    }
                }

                messages_sent_++;
            }
        }
    }

private:
    /**
     * Send message (enqueue to appropriate priority queue)
     */
    void sendMessage(const WaveMessage& msg) {
        int priority = std::min(7, std::max(0, msg.priority));
        tx_queues_[priority].push(msg);
    }

    /**
     * Receive message (enqueue to RX queue)
     */
    void receiveMessage(const WaveMessage& msg) {
        rx_queue_.push(msg);
        messages_received_++;
    }
};

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_WAVE_STACK_H
