#ifndef MESHCHAIN_OMNETPP_INTERFACE_H
#define MESHCHAIN_OMNETPP_INTERFACE_H

#include "../common/types.h"
#include "../common/block.h"
#include "../common/merkle_tree.h"
#include "../crypto/secure_channel.h"
#include <functional>
#include <queue>
#include <mutex>
#include <cstring>
#include <random>

namespace meshchain {
namespace network {

/**
 * OMNET++ Network Interface
 *
 * Provides integration with OMNET++ for V2X communication:
 * - DSRC (802.11p) ~300m range
 * - C-V2X PC5 ~1km range
 * - UDP multicast for SigReq
 * - QUIC streams for control plane
 *
 * Tolerates ~20% loss via FEC/gossip (per paper Section 2.2)
 */

// Message types
enum class MessageType {
    BLOCK_PROPOSAL,      // New block from creator
    SIG_REQUEST,         // Individual witness signature request
    SIG_RESPONSE,        // Witness signature response
    TOF_CHALLENGE,       // ToF distance-bounding challenge
    TOF_RESPONSE,        // ToF distance-bounding response
    ANCHOR_BROADCAST,    // RSU anchor announcement
    GOSSIP              // Block gossip for dissemination
};

// Network message wrapper
struct NetworkMessage {
    MessageType type;
    std::string sender_id;
    std::string receiver_id;  // Empty for broadcast
    Timestamp sent_at;
    std::vector<uint8_t> payload;
    bool is_multicast;
};

// Message handlers
using MessageHandler = std::function<void(const NetworkMessage&)>;

/**
 * Network interface for OMNET++ integration
 */
class OmnetppInterface {
public:
    struct Config {
        std::string node_id;
        double dsrc_range_m;     // Default: 300m
        double cv2x_range_m;     // Default: 1000m
        double packet_loss_rate; // Default: 0.2 (20%)
        bool use_fec;           // Forward error correction
    };

private:
    Config config_;
    std::map<MessageType, MessageHandler> handlers_;
    std::queue<NetworkMessage> send_queue_;
    std::mutex queue_mutex_;

public:
    explicit OmnetppInterface(const Config& config) : config_(config) {}

    /**
     * Register message handler for specific type
     */
    void registerHandler(MessageType type, MessageHandler handler) {
        handlers_[type] = handler;
    }

    /**
     * Send message (queued for OMNET++ processing)
     *
     * @param type Message type
     * @param receiver Target node ID (empty for broadcast)
     * @param payload Message payload
     * @param multicast Use multicast (for SigReq)
     */
    void send(MessageType type,
             const std::string& receiver,
             const std::vector<uint8_t>& payload,
             bool multicast = false) {

        NetworkMessage msg;
        msg.type = type;
        msg.sender_id = config_.node_id;
        msg.receiver_id = receiver;
        msg.sent_at = std::chrono::system_clock::now();
        msg.payload = payload;
        msg.is_multicast = multicast;

        std::lock_guard<std::mutex> lock(queue_mutex_);
        send_queue_.push(msg);
    }

    /**
     * Process incoming message
     * Called by OMNET++ simulation when message arrives
     */
    void receive(const NetworkMessage& msg) {
        // Simulate packet loss
        if (shouldDrop()) {
            return;  // Lost in transmission
        }

        // Dispatch to registered handler
        auto it = handlers_.find(msg.type);
        if (it != handlers_.end()) {
            it->second(msg);
        }
    }

    /**
     * Get next message from send queue
     * Called by OMNET++ to drain outgoing messages
     */
    std::optional<NetworkMessage> getNextMessage() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (send_queue_.empty()) {
            return std::nullopt;
        }

        NetworkMessage msg = send_queue_.front();
        send_queue_.pop();
        return msg;
    }

    /**
     * Broadcast block to neighbors (gossip protocol)
     */
    void broadcastBlock(const Block& block) {
        std::vector<uint8_t> payload = serializeBlock(block);
        send(MessageType::GOSSIP, "", payload, true);
    }

    /**
     * Send individual signature request to witness (with secure channel)
     *
     * CRITICAL: This is sent individually to each witness using ML-KEM + AEAD
     * to protect the signature request from eavesdropping
     */
    void sendSigRequest(const std::string& witness_id,
                       const crypto::SignatureRequest& sig_req,
                       const std::vector<uint8_t>& witness_kem_pubkey,
                       crypto::SecureChannel& secure_channel) {

        // Encrypt signature request with ML-KEM based secure channel
        auto [kem_ciphertext, encrypted_message] =
            secure_channel.encryptSigRequest(sig_req, witness_kem_pubkey);

        // Serialize encrypted payload
        std::vector<uint8_t> payload;

        // Add KEM ciphertext length
        uint16_t kem_len = static_cast<uint16_t>(kem_ciphertext.size());
        const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&kem_len);
        payload.insert(payload.end(), len_ptr, len_ptr + sizeof(uint16_t));

        // Add KEM ciphertext
        payload.insert(payload.end(), kem_ciphertext.begin(), kem_ciphertext.end());

        // Add encrypted message
        payload.insert(payload.end(), encrypted_message.begin(), encrypted_message.end());

        // Send to specific witness (unicast)
        send(MessageType::SIG_REQUEST, witness_id, payload, false);
    }

    /**
     * Send ToF challenge (for distance bounding)
     */
    void sendToFChallenge(const std::string& target_id, Nonce nonce) {
        std::vector<uint8_t> payload(sizeof(Nonce));
        std::memcpy(payload.data(), &nonce, sizeof(Nonce));

        send(MessageType::TOF_CHALLENGE, target_id, payload, false);
    }

private:
    bool shouldDrop() const {
        // Simulate packet loss
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_real_distribution<> dis(0.0, 1.0);

        return dis(gen) < config_.packet_loss_rate;
    }

    std::vector<uint8_t> serializeBlock(const Block& block) const {
        // Simplified serialization
        // In production: use Protobuf
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), block.block_hash.begin(), block.block_hash.end());
        // Add header fields...
        return bytes;
    }

    /**
     * Parse encrypted signature request from network message
     * Returns (kem_ciphertext, encrypted_message)
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> parseEncryptedSigRequest(
            const std::vector<uint8_t>& payload) const {

        if (payload.size() < sizeof(uint16_t)) {
            throw std::runtime_error("Invalid sig_req payload");
        }

        // Parse KEM ciphertext length
        uint16_t kem_len;
        std::memcpy(&kem_len, payload.data(), sizeof(uint16_t));

        if (payload.size() < sizeof(uint16_t) + kem_len) {
            throw std::runtime_error("Invalid sig_req payload size");
        }

        // Extract KEM ciphertext
        std::vector<uint8_t> kem_ciphertext(
            payload.begin() + sizeof(uint16_t),
            payload.begin() + sizeof(uint16_t) + kem_len
        );

        // Extract encrypted message
        std::vector<uint8_t> encrypted_message(
            payload.begin() + sizeof(uint16_t) + kem_len,
            payload.end()
        );

        return {kem_ciphertext, encrypted_message};
    }
};

} // namespace network
} // namespace meshchain

#endif // MESHCHAIN_OMNETPP_INTERFACE_H
