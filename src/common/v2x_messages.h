#ifndef MESHCHAIN_V2X_MESSAGES_H
#define MESHCHAIN_V2X_MESSAGES_H

#include "types.h"
#include <vector>
#include <string>
#include <cstdint>

namespace meshchain {

/**
 * V2X Message Types and Payload Structures
 *
 * Based on ETSI ITS standards:
 * - CAM (Cooperative Awareness Message): Periodic beacons
 * - DENM (Decentralized Environmental Notification Message): Event-triggered
 * - CPM (Collective Perception Message): Sensor data sharing
 * - BSM (Basic Safety Message): US equivalent of CAM
 *
 * These messages are recorded in blocks as evidence of V2X communication
 */

// Message priority levels
enum class MessagePriority : uint8_t {
    ROUTINE = 0,      // Normal CAM/BSM
    IMPORTANT = 1,    // Pre-crash warning
    URGENT = 2,       // Collision imminent
    CRITICAL = 3      // Emergency vehicle
};

// V2X message types
enum class V2XMessageType : uint8_t {
    CAM = 1,          // Cooperative Awareness Message (ETSI)
    DENM = 2,         // Decentralized Environmental Notification
    CPM = 3,          // Collective Perception Message
    BSM = 4,          // Basic Safety Message (SAE J2735)
    SPAT = 5,         // Signal Phase and Timing
    MAP = 6,          // Map Data
    CUSTOM = 255      // Custom application messages
};

/**
 * Vehicle position and motion state
 */
struct PositionState {
    double latitude;       // Degrees
    double longitude;      // Degrees
    double altitude_m;     // Meters above sea level
    double heading_deg;    // 0-360, 0 = North
    double speed_mps;      // Meters per second
    double acceleration_mps2;  // Meters per second squared
    Timestamp timestamp;

    // Serialize to bytes
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        bytes.reserve(64);

        // Simplified serialization - in production use Protobuf or UPER
        auto append_double = [&bytes](double val) {
            const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&val);
            bytes.insert(bytes.end(), ptr, ptr + sizeof(double));
        };

        append_double(latitude);
        append_double(longitude);
        append_double(altitude_m);
        append_double(heading_deg);
        append_double(speed_mps);
        append_double(acceleration_mps2);

        return bytes;
    }
};

/**
 * CAM (Cooperative Awareness Message)
 *
 * Periodic beacon (1-10 Hz) containing vehicle state
 * Size: ~300-800 bytes (varies with optional fields)
 */
struct CAM {
    VehicleID sender_id;
    Timestamp generation_time;
    PositionState position;

    // Vehicle characteristics
    double vehicle_length_m;
    double vehicle_width_m;
    std::string vehicle_type;  // "car", "truck", "motorcycle", "bus"

    // Optional: sensor data
    bool has_radar;
    bool has_lidar;
    bool has_camera;

    // Station type
    bool is_emergency;
    bool is_public_transport;

    // Reputation score (for witness selection)
    double sender_reputation = 0.5;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;

        // Sender ID
        bytes.insert(bytes.end(), sender_id.begin(), sender_id.end());
        bytes.push_back(0);  // null terminator

        // Position state
        auto pos_bytes = position.serialize();
        bytes.insert(bytes.end(), pos_bytes.begin(), pos_bytes.end());

        // Vehicle characteristics
        const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&vehicle_length_m);
        bytes.insert(bytes.end(), len_ptr, len_ptr + sizeof(double));

        const uint8_t* wid_ptr = reinterpret_cast<const uint8_t*>(&vehicle_width_m);
        bytes.insert(bytes.end(), wid_ptr, wid_ptr + sizeof(double));

        // Flags
        uint8_t flags = 0;
        if (has_radar) flags |= 0x01;
        if (has_lidar) flags |= 0x02;
        if (has_camera) flags |= 0x04;
        if (is_emergency) flags |= 0x08;
        if (is_public_transport) flags |= 0x10;
        bytes.push_back(flags);

        return bytes;
    }
};

/**
 * DENM (Decentralized Environmental Notification Message)
 *
 * Event-triggered warning message
 * Examples: road hazard, accident, emergency brake, wrong-way driver
 */
struct DENM {
    VehicleID sender_id;
    Timestamp detection_time;
    Timestamp expiry_time;
    PositionState event_position;

    // Event type
    enum class EventType : uint8_t {
        TRAFFIC_JAM = 1,
        ACCIDENT = 2,
        ROAD_WORKS = 3,
        ADVERSE_WEATHER = 4,
        EMERGENCY_BRAKE = 5,
        WRONG_WAY_DRIVER = 6,
        STATIONARY_VEHICLE = 7,
        SLIPPERY_ROAD = 8
    } event_type;

    // Event severity
    MessagePriority priority;

    // Event description
    std::string description;

    // Affected area radius (meters)
    double affected_radius_m;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;

        bytes.insert(bytes.end(), sender_id.begin(), sender_id.end());
        bytes.push_back(0);

        auto pos_bytes = event_position.serialize();
        bytes.insert(bytes.end(), pos_bytes.begin(), pos_bytes.end());

        bytes.push_back(static_cast<uint8_t>(event_type));
        bytes.push_back(static_cast<uint8_t>(priority));

        const uint8_t* rad_ptr = reinterpret_cast<const uint8_t*>(&affected_radius_m);
        bytes.insert(bytes.end(), rad_ptr, rad_ptr + sizeof(double));

        return bytes;
    }
};

/**
 * CPM (Collective Perception Message)
 *
 * Shares perceived objects from sensors
 * Enables extended sensing beyond line-of-sight
 */
struct PerceivedObject {
    uint32_t object_id;
    PositionState position;
    double confidence;  // 0.0-1.0
    std::string object_class;  // "vehicle", "pedestrian", "cyclist", "obstacle"

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;

        const uint8_t* id_ptr = reinterpret_cast<const uint8_t*>(&object_id);
        bytes.insert(bytes.end(), id_ptr, id_ptr + sizeof(uint32_t));

        auto pos_bytes = position.serialize();
        bytes.insert(bytes.end(), pos_bytes.begin(), pos_bytes.end());

        const uint8_t* conf_ptr = reinterpret_cast<const uint8_t*>(&confidence);
        bytes.insert(bytes.end(), conf_ptr, conf_ptr + sizeof(double));

        return bytes;
    }
};

struct CPM {
    VehicleID sender_id;
    Timestamp generation_time;
    PositionState sender_position;

    // List of perceived objects
    std::vector<PerceivedObject> perceived_objects;

    // Sensor configuration
    double sensor_range_m;
    double sensor_fov_deg;  // Field of view

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;

        bytes.insert(bytes.end(), sender_id.begin(), sender_id.end());
        bytes.push_back(0);

        auto pos_bytes = sender_position.serialize();
        bytes.insert(bytes.end(), pos_bytes.begin(), pos_bytes.end());

        // Number of objects
        uint16_t num_objects = static_cast<uint16_t>(perceived_objects.size());
        const uint8_t* num_ptr = reinterpret_cast<const uint8_t*>(&num_objects);
        bytes.insert(bytes.end(), num_ptr, num_ptr + sizeof(uint16_t));

        // Serialize each object
        for (const auto& obj : perceived_objects) {
            auto obj_bytes = obj.serialize();
            bytes.insert(bytes.end(), obj_bytes.begin(), obj_bytes.end());
        }

        return bytes;
    }
};

/**
 * V2X Communication Record
 *
 * This is what gets stored in the blockchain payload
 * Records all V2X messages sent/received during block creation
 */
/**
 * P2P Communication Log (libp2p)
 */
struct P2PCommLog {
    Timestamp timestamp;
    std::string peer_id;      // libp2p PeerID
    std::string protocol;     // GOSSIPSUB, BITSWAP, DHT, etc.
    uint32_t bytes_sent;
    uint32_t bytes_received;
    std::string topic;        // For GossipSub
    std::string data_hash;    // For Bitswap/DHT

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        // peer_id
        bytes.insert(bytes.end(), peer_id.begin(), peer_id.end());
        bytes.push_back(0);
        // protocol
        bytes.insert(bytes.end(), protocol.begin(), protocol.end());
        bytes.push_back(0);
        // bytes_sent/received
        const uint8_t* sent_ptr = reinterpret_cast<const uint8_t*>(&bytes_sent);
        bytes.insert(bytes.end(), sent_ptr, sent_ptr + sizeof(uint32_t));
        const uint8_t* recv_ptr = reinterpret_cast<const uint8_t*>(&bytes_received);
        bytes.insert(bytes.end(), recv_ptr, recv_ptr + sizeof(uint32_t));
        return bytes;
    }
};

struct V2XRecord {
    Timestamp record_start;
    Timestamp record_end;
    VehicleID recorder_id;

    // WAVE V2V Messages (local, 300m range)
    std::vector<CAM> cams_sent;
    std::vector<DENM> denms_sent;
    std::vector<CPM> cpms_sent;
    std::vector<DENM> denms_received;
    std::vector<CPM> cpms_received;

    // libp2p P2P Communications (global, internet-wide)
    std::vector<P2PCommLog> p2p_logs;

    // Interaction statistics
    uint32_t total_neighbors;  // WAVE neighbors in range
    uint32_t total_messages_sent;
    uint32_t total_messages_received;
    uint32_t p2p_peers_connected;  // libp2p peers
    uint64_t p2p_bytes_sent;
    uint64_t p2p_bytes_received;

    // Serialize for block payload
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        bytes.reserve(4096);  // Typical size

        // Header
        bytes.insert(bytes.end(), recorder_id.begin(), recorder_id.end());
        bytes.push_back(0);

        // Statistics
        const uint8_t* neighbors_ptr = reinterpret_cast<const uint8_t*>(&total_neighbors);
        bytes.insert(bytes.end(), neighbors_ptr, neighbors_ptr + sizeof(uint32_t));

        const uint8_t* sent_ptr = reinterpret_cast<const uint8_t*>(&total_messages_sent);
        bytes.insert(bytes.end(), sent_ptr, sent_ptr + sizeof(uint32_t));

        const uint8_t* recv_ptr = reinterpret_cast<const uint8_t*>(&total_messages_received);
        bytes.insert(bytes.end(), recv_ptr, recv_ptr + sizeof(uint32_t));

        // Message counts
        auto append_count = [&bytes](uint16_t count) {
            const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&count);
            bytes.insert(bytes.end(), ptr, ptr + sizeof(uint16_t));
        };

        append_count(static_cast<uint16_t>(cams_sent.size()));
        append_count(static_cast<uint16_t>(denms_sent.size()));
        append_count(static_cast<uint16_t>(cpms_sent.size()));
        append_count(static_cast<uint16_t>(denms_received.size()));
        append_count(static_cast<uint16_t>(cpms_received.size()));
        append_count(static_cast<uint16_t>(p2p_logs.size()));

        // Serialize selected messages (not all, to keep size manageable)
        // In production: apply filtering/compression

        // Serialize up to 5 CAMs
        size_t cam_limit = std::min(cams_sent.size(), size_t(5));
        for (size_t i = 0; i < cam_limit; ++i) {
            auto cam_bytes = cams_sent[i].serialize();
            bytes.insert(bytes.end(), cam_bytes.begin(), cam_bytes.end());
        }

        // Serialize all DENMs (important events)
        for (const auto& denm : denms_sent) {
            auto denm_bytes = denm.serialize();
            bytes.insert(bytes.end(), denm_bytes.begin(), denm_bytes.end());
        }

        // Serialize received critical messages
        for (const auto& denm : denms_received) {
            auto denm_bytes = denm.serialize();
            bytes.insert(bytes.end(), denm_bytes.begin(), denm_bytes.end());
        }

        // Serialize libp2p communication logs
        for (const auto& log : p2p_logs) {
            auto log_bytes = log.serialize();
            bytes.insert(bytes.end(), log_bytes.begin(), log_bytes.end());
        }

        // Append libp2p statistics
        const uint8_t* p2p_peers_ptr = reinterpret_cast<const uint8_t*>(&p2p_peers_connected);
        bytes.insert(bytes.end(), p2p_peers_ptr, p2p_peers_ptr + sizeof(uint32_t));

        const uint8_t* p2p_tx_ptr = reinterpret_cast<const uint8_t*>(&p2p_bytes_sent);
        bytes.insert(bytes.end(), p2p_tx_ptr, p2p_tx_ptr + sizeof(uint64_t));

        const uint8_t* p2p_rx_ptr = reinterpret_cast<const uint8_t*>(&p2p_bytes_received);
        bytes.insert(bytes.end(), p2p_rx_ptr, p2p_rx_ptr + sizeof(uint64_t));

        return bytes;
    }

    // Get size estimate
    size_t estimateSize() const {
        // Rough estimate: header + stats + messages
        size_t size = 128;  // Header and metadata
        size += cams_sent.size() * 400;  // CAM ~400 bytes
        size += denms_sent.size() * 300;  // DENM ~300 bytes
        size += cpms_sent.size() * 600;  // CPM ~600 bytes
        size += denms_received.size() * 300;
        size += cpms_received.size() * 600;
        return size;
    }
};

/**
 * Inconsistency Report
 *
 * Used to report malicious block content
 * Witnesses report when block data is inconsistent with their observations
 */
struct InconsistencyReport {
    VehicleID reporter_id;          // Reporting witness
    VehicleID accused_id;            // Accused block creator
    Hash256 block_hash;              // Hash of the suspicious block

    // Inconsistency details
    std::vector<uint8_t> claimed_data;   // Data in the block
    std::vector<uint8_t> observed_data;  // What witness actually observed

    // Inconsistency severity (0.0 ~ 1.0)
    double inconsistency_score;

    // Reporter's signature (FALCON-512)
    std::vector<uint8_t> signature;
    Timestamp reported_at;

    InconsistencyReport() : inconsistency_score(0.0) {
        reported_at = std::chrono::system_clock::now();
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;

        // Reporter ID
        bytes.insert(bytes.end(), reporter_id.begin(), reporter_id.end());
        bytes.push_back(0);

        // Accused ID
        bytes.insert(bytes.end(), accused_id.begin(), accused_id.end());
        bytes.push_back(0);

        // Block hash
        bytes.insert(bytes.end(), block_hash.begin(), block_hash.end());

        // Claimed data length + data
        uint32_t claimed_len = static_cast<uint32_t>(claimed_data.size());
        const uint8_t* claimed_len_ptr = reinterpret_cast<const uint8_t*>(&claimed_len);
        bytes.insert(bytes.end(), claimed_len_ptr, claimed_len_ptr + sizeof(uint32_t));
        bytes.insert(bytes.end(), claimed_data.begin(), claimed_data.end());

        // Observed data length + data
        uint32_t observed_len = static_cast<uint32_t>(observed_data.size());
        const uint8_t* observed_len_ptr = reinterpret_cast<const uint8_t*>(&observed_len);
        bytes.insert(bytes.end(), observed_len_ptr, observed_len_ptr + sizeof(uint32_t));
        bytes.insert(bytes.end(), observed_data.begin(), observed_data.end());

        // Inconsistency score
        const uint8_t* score_ptr = reinterpret_cast<const uint8_t*>(&inconsistency_score);
        bytes.insert(bytes.end(), score_ptr, score_ptr + sizeof(double));

        // Signature
        uint16_t sig_len = static_cast<uint16_t>(signature.size());
        const uint8_t* sig_len_ptr = reinterpret_cast<const uint8_t*>(&sig_len);
        bytes.insert(bytes.end(), sig_len_ptr, sig_len_ptr + sizeof(uint16_t));
        bytes.insert(bytes.end(), signature.begin(), signature.end());

        return bytes;
    }

    // Get data for signing
    std::vector<uint8_t> getDataToSign() const {
        std::vector<uint8_t> bytes;

        bytes.insert(bytes.end(), reporter_id.begin(), reporter_id.end());
        bytes.push_back(0);
        bytes.insert(bytes.end(), accused_id.begin(), accused_id.end());
        bytes.push_back(0);
        bytes.insert(bytes.end(), block_hash.begin(), block_hash.end());
        bytes.insert(bytes.end(), claimed_data.begin(), claimed_data.end());
        bytes.insert(bytes.end(), observed_data.begin(), observed_data.end());

        const uint8_t* score_ptr = reinterpret_cast<const uint8_t*>(&inconsistency_score);
        bytes.insert(bytes.end(), score_ptr, score_ptr + sizeof(double));

        return bytes;
    }
};

/**
 * Create sample V2X record for testing
 */
inline V2XRecord createSampleV2XRecord(const VehicleID& vehicle_id) {
    V2XRecord record;
    record.recorder_id = vehicle_id;
    record.record_start = std::chrono::system_clock::now() - std::chrono::seconds(1);
    record.record_end = std::chrono::system_clock::now();
    record.total_neighbors = 8;
    record.total_messages_sent = 25;
    record.total_messages_received = 120;

    // Add sample CAM
    CAM cam;
    cam.sender_id = vehicle_id;
    cam.generation_time = std::chrono::system_clock::now();
    cam.position.latitude = 37.5665;
    cam.position.longitude = 126.9780;
    cam.position.altitude_m = 50.0;
    cam.position.heading_deg = 90.0;
    cam.position.speed_mps = 15.0;
    cam.position.acceleration_mps2 = 0.5;
    cam.position.timestamp = cam.generation_time;
    cam.vehicle_length_m = 4.5;
    cam.vehicle_width_m = 1.8;
    cam.vehicle_type = "car";
    cam.has_radar = true;
    cam.has_lidar = false;
    cam.has_camera = true;
    cam.is_emergency = false;
    cam.is_public_transport = false;

    record.cams_sent.push_back(cam);

    return record;
}

} // namespace meshchain

#endif // MESHCHAIN_V2X_MESSAGES_H
