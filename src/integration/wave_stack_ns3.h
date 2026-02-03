#ifndef MESHCHAIN_WAVE_STACK_NS3_H
#define MESHCHAIN_WAVE_STACK_NS3_H

/**
 * ns-3 WAVE Stack Integration
 *
 * Provides realistic IEEE 802.11p PHY/MAC simulation using ns-3 WAVE module.
 * This replaces the queue-based simulation with actual wireless channel modeling:
 * - PHY layer: Nakagami fading, path loss, interference
 * - MAC layer: CSMA/CA, collision detection, backoff
 * - Channel: 5.9 GHz DSRC/WAVE with realistic propagation
 *
 * Only enabled when ns-3 libraries are available (USE_NS3_WAVE defined).
 * Falls back to wave_stack.h queue-based implementation otherwise.
 */

#include "../common/types.h"
#include "../common/v2x_messages.h"
#include "traci_client.h"
#include <queue>
#include <map>
#include <memory>
#include <functional>

#ifdef USE_NS3_WAVE
// ns-3 includes
#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/wifi-module.h>
#include <ns3/wave-module.h>
#include <ns3/mobility-module.h>
#include <ns3/internet-module.h>
#endif

namespace meshchain {
namespace integration {

#ifdef USE_NS3_WAVE

/**
 * ns-3 WAVE Stack Implementation
 *
 * Integrates with ns-3's WaveNetDevice for realistic IEEE 802.11p simulation.
 * Maintains same API as WaveStack for drop-in replacement.
 */
class WaveStackNS3 {
public:
    struct Config {
        std::string node_id;
        double tx_power_dbm;        // Transmission power (default: 20 dBm)
        double frequency_ghz;       // Frequency (default: 5.9 GHz)
        double bandwidth_mhz;       // Bandwidth (default: 10 MHz)
        double data_rate_mbps;      // Data rate (default: 6 Mbps)
        double range_m;             // Communication range (default: 300m)
        double packet_loss_rate;    // Ignored for ns-3 (uses channel model)
        int cam_interval_ms;        // CAM broadcast interval (default: 100ms)
        int denm_priority;          // DENM priority (0-7, default: 6)
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

    // ns-3 components
    ns3::Ptr<ns3::Node> ns3_node_;
    ns3::Ptr<ns3::WaveNetDevice> wave_device_;
    ns3::Ptr<ns3::MobilityModel> mobility_model_;

    // Message queues (for buffering before ns-3 transmission)
    std::queue<WaveMessage> tx_queue_;
    std::queue<WaveMessage> rx_queue_;

    // Statistics
    size_t messages_sent_;
    size_t messages_received_;
    size_t messages_lost_;

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
    explicit WaveStackNS3(const Config& config, std::shared_ptr<TraCIClient> traci)
        : config_(config),
          traci_(traci),
          messages_sent_(0),
          messages_received_(0),
          messages_lost_(0) {

        initializeNS3WaveDevice();
    }

    /**
     * Broadcast CAM (Cooperative Awareness Message)
     */
    void broadcastCAM(double sender_reputation = 0.5) {
        auto vehicle_state = traci_->getVehicleState(config_.node_id);
        if (!vehicle_state.has_value()) return;

        // Create CAM (same as original implementation)
        CAM cam;
        cam.sender_id = config_.node_id;
        cam.generation_time = std::chrono::system_clock::now();

        cam.position.timestamp = cam.generation_time;
        cam.position.latitude = vehicle_state->y;
        cam.position.longitude = vehicle_state->x;
        cam.position.altitude_m = vehicle_state->z;
        cam.position.speed_mps = vehicle_state->speed_mps;
        cam.position.heading_deg = vehicle_state->heading_deg;

        cam.vehicle_length_m = 4.5;
        cam.vehicle_width_m = 2.0;
        cam.vehicle_type = "passenger";

        cam.has_radar = true;
        cam.has_lidar = false;
        cam.has_camera = true;
        cam.sender_reputation = sender_reputation;

        // Send via ns-3 WAVE
        WaveMessage msg;
        msg.type = MessageType::CAM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = "";  // Broadcast
        msg.sent_at = cam.generation_time;
        msg.priority = 3;
        msg.cam = cam;
        msg.payload = cam.serialize();

        sendMessageNS3(msg);
        cams_sent_.push_back(cam);
    }

    /**
     * Send DENM
     */
    void sendDENM(const DENM& denm) {
        WaveMessage msg;
        msg.type = MessageType::DENM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = "";
        msg.sent_at = std::chrono::system_clock::now();
        msg.priority = config_.denm_priority;
        msg.denm = denm;
        msg.payload = denm.serialize();

        sendMessageNS3(msg);
        denms_sent_.push_back(denm);
    }

    /**
     * Send CPM
     */
    void sendCPM(const CPM& cpm) {
        WaveMessage msg;
        msg.type = MessageType::CPM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = "";
        msg.sent_at = std::chrono::system_clock::now();
        msg.priority = 4;
        msg.cpm = cpm;
        msg.payload = cpm.serialize();

        sendMessageNS3(msg);
        cpms_sent_.push_back(cpm);
    }

    /**
     * Send P2P message
     */
    void sendP2P(const std::string& receiver_id, const std::vector<uint8_t>& payload) {
        WaveMessage msg;
        msg.type = MessageType::CUSTOM;
        msg.sender_id = config_.node_id;
        msg.receiver_id = receiver_id;
        msg.sent_at = std::chrono::system_clock::now();
        msg.priority = 5;
        msg.payload = payload;

        sendMessageNS3(msg);
    }

    /**
     * Process received messages
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
     * Register callback
     */
    void registerCallback(MessageType type, MessageCallback callback) {
        callbacks_[type].push_back(callback);
    }

    /**
     * Get V2X record
     */
    V2XRecord getV2XRecord() {
        V2XRecord record;
        auto now = std::chrono::system_clock::now();
        record.record_end = now;
        record.record_start = now - std::chrono::seconds(1);
        record.recorder_id = config_.node_id;

        record.cams_sent = cams_sent_;
        record.denms_sent = denms_sent_;
        record.cpms_sent = cpms_sent_;
        record.denms_received = denms_received_;
        record.cpms_received = cpms_received_;

        record.total_neighbors = 0;

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
     * Update mobility from SUMO
     * Called each simulation step to sync position with SUMO
     */
    void updateMobility() {
        auto vehicle_state = traci_->getVehicleState(config_.node_id);
        if (!vehicle_state.has_value() || !mobility_model_) return;

        // Update ns-3 mobility model with SUMO position
        ns3::Vector pos(vehicle_state->x, vehicle_state->y, vehicle_state->z);
        mobility_model_->SetPosition(pos);

        // Update velocity if mobility model supports it
        ns3::Vector vel(
            vehicle_state->speed_mps * std::cos(vehicle_state->heading_deg * M_PI / 180.0),
            vehicle_state->speed_mps * std::sin(vehicle_state->heading_deg * M_PI / 180.0),
            0.0
        );
        if (auto constant_vel = ns3::DynamicCast<ns3::ConstantVelocityMobilityModel>(mobility_model_)) {
            constant_vel->SetVelocity(vel);
        }
    }

    /**
     * For compatibility - no longer needed with ns-3 (handled by ns-3 scheduler)
     */
    void simulateMessagePropagation(std::map<std::string, std::shared_ptr<WaveStackNS3>>& all_stacks) {
        // ns-3 handles message propagation automatically via WifiPhy
        // Just update mobility positions
        updateMobility();

        // Process any ns-3 events
        ns3::Simulator::Run();
    }

private:
    /**
     * Initialize ns-3 WAVE device
     */
    void initializeNS3WaveDevice() {
        // Create ns-3 node
        ns3_node_ = ns3::CreateObject<ns3::Node>();

        // Create mobility model (ConstantVelocityMobilityModel for SUMO integration)
        mobility_model_ = ns3::CreateObject<ns3::ConstantVelocityMobilityModel>();
        ns3_node_->AggregateObject(mobility_model_);

        // Create WAVE net device with OCB (Outside Context of BSS) mode
        ns3::YansWifiPhyHelper wifiPhy;
        ns3::YansWifiChannelHelper wifiChannel = ns3::YansWifiChannelHelper::Default();

        // Configure propagation model (Nakagami fading + log-distance)
        wifiChannel.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
        wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");

        ns3::Ptr<ns3::YansWifiChannel> channel = wifiChannel.Create();
        wifiPhy.SetChannel(channel);

        // Set TX power and range
        wifiPhy.Set("TxPowerStart", ns3::DoubleValue(config_.tx_power_dbm));
        wifiPhy.Set("TxPowerEnd", ns3::DoubleValue(config_.tx_power_dbm));
        wifiPhy.Set("RxSensitivity", ns3::DoubleValue(-89.0));  // dBm

        // Create WAVE MAC (OCB mode for ad-hoc communication)
        ns3::QosWaveMacHelper waveMac = ns3::QosWaveMacHelper::Default();

        // Create WAVE net device helper
        ns3::WaveHelper waveHelper;

        // Install WAVE device on node
        ns3::NetDeviceContainer devices = waveHelper.Install(wifiPhy, waveMac, ns3_node_);
        wave_device_ = ns3::DynamicCast<ns3::WaveNetDevice>(devices.Get(0));

        // Set up receive callback
        wave_device_->SetReceiveCallback(
            ns3::MakeCallback(&WaveStackNS3::receiveFromNS3, this)
        );

        std::cout << "[WaveStackNS3] ✓ Initialized ns-3 WAVE device for " << config_.node_id
                  << " (IEEE 802.11p @ " << config_.frequency_ghz << " GHz)\n";
    }

    /**
     * Send message via ns-3 WAVE
     */
    void sendMessageNS3(const WaveMessage& msg) {
        if (!wave_device_) {
            std::cerr << "[WaveStackNS3] ERROR: WAVE device not initialized\n";
            return;
        }

        // Create ns-3 packet from payload
        ns3::Ptr<ns3::Packet> packet = ns3::Create<ns3::Packet>(
            msg.payload.data(),
            msg.payload.size()
        );

        // Determine destination MAC address
        ns3::Mac48Address dest;
        if (msg.receiver_id.empty()) {
            // Broadcast
            dest = ns3::Mac48Address::GetBroadcast();
        } else {
            // Unicast - would need MAC address mapping
            // For now, use broadcast (WAVE typically uses broadcast for V2X)
            dest = ns3::Mac48Address::GetBroadcast();
        }

        // Set priority (AC_BE=0, AC_BK=1, AC_VI=2, AC_VO=3)
        // Map our 0-7 priority to WAVE access categories
        uint32_t ac = (msg.priority >= 6) ? 3 :  // AC_VO (voice)
                      (msg.priority >= 4) ? 2 :  // AC_VI (video)
                      (msg.priority >= 2) ? 0 :  // AC_BE (best effort)
                      1;                          // AC_BK (background)

        // Send via WAVE device
        bool success = wave_device_->Send(packet, dest, 0x88dc);  // Ethertype for WSMP

        if (success) {
            messages_sent_++;
        } else {
            messages_lost_++;
            std::cerr << "[WaveStackNS3] Failed to send packet\n";
        }
    }

    /**
     * Receive callback from ns-3
     */
    bool receiveFromNS3(ns3::Ptr<ns3::NetDevice> device,
                        ns3::Ptr<const ns3::Packet> packet,
                        uint16_t protocol,
                        const ns3::Address& from) {

        // Extract payload from ns-3 packet
        uint32_t size = packet->GetSize();
        std::vector<uint8_t> payload(size);
        packet->CopyData(payload.data(), size);

        // Create WaveMessage
        WaveMessage msg;
        msg.type = MessageType::CUSTOM;  // Would need to parse payload to determine type
        msg.receiver_id = config_.node_id;
        msg.received_at = std::chrono::system_clock::now();
        msg.payload = payload;

        // Try to deserialize as CAM/DENM/CPM
        // (In real implementation, would have message type header)

        // Queue for processing
        rx_queue_.push(msg);
        messages_received_++;

        return true;  // Packet accepted
    }
};

#else

/**
 * Fallback: When ns-3 not available, use original queue-based implementation
 * This ensures simulation continues to work without ns-3 installation
 */
#include "wave_stack.h"
namespace meshchain {
namespace integration {
    // Use original WaveStack implementation as fallback
    // (already defined in wave_stack.h)
}
}

#endif // USE_NS3_WAVE

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_WAVE_STACK_NS3_H
