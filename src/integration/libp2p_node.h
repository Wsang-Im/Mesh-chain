#ifndef MESHCHAIN_LIBP2P_NODE_H
#define MESHCHAIN_LIBP2P_NODE_H

/**
 * libp2p Integration for Mesh-Chain
 *
 * Provides P2P networking capabilities beyond WAVE's 300m range:
 * - DHT (Distributed Hash Table) for peer/witness discovery
 * - GossipSub for block propagation
 * - Bitswap for block synchronization
 * - Multi-transport (TCP, QUIC, WebSockets for internet connectivity)
 * - Peer routing and NAT traversal
 *
 * Architecture:
 * - WAVE: Local V2V (300m, real-time, safety-critical)
 * - libp2p: Global P2P (internet, blockchain sync, witness discovery)
 *
 * Implementation modes:
 * - USE_CPP_LIBP2P defined: Real cpp-libp2p library integration
 * - USE_CPP_LIBP2P not defined: Stub implementation for testing
 */

#ifdef USE_CPP_LIBP2P
// Use real cpp-libp2p implementation
#include "libp2p_node_real.h"

namespace meshchain {
namespace integration {
    // Alias real implementation as LibP2PNode
    using LibP2PNode = LibP2PNodeReal;
}
}

#else
// Use simulation-optimized implementation (current code below)

#include "../common/types.h"
#include "../common/block.h"
#include "../common/v2x_messages.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <memory>
#include <chrono>
#include <iostream>
#include <cmath>
#include <cstdio>

namespace meshchain {
namespace integration {

/**
 * libp2p Simulation-Optimized Implementation
 *
 * In-process message passing implementation optimized for V2X simulation.
 * For distributed deployment, install cpp-libp2p and rebuild with USE_CPP_LIBP2P.
 */
class LibP2PNode {
public:
    /**
     * PeerID - Unique identifier derived from public key
     */
    struct PeerID {
        std::string id;  // Base58 encoded multihash of pubkey
        std::vector<uint8_t> pubkey;

        std::string toString() const { return id; }

        bool operator==(const PeerID& other) const {
            return id == other.id;
        }

        bool operator<(const PeerID& other) const {
            return id < other.id;
        }
    };

    /**
     * Multiaddr - Flexible addressing scheme
     * Examples:
     * - /ip4/192.168.1.1/tcp/4001
     * - /ip4/1.2.3.4/udp/4001/quic
     * - /dns4/example.com/tcp/443/wss
     */
    struct Multiaddr {
        std::string addr;

        static Multiaddr fromString(const std::string& s) {
            return Multiaddr{s};
        }

        std::string toString() const { return addr; }
    };

    /**
     * Peer information
     */
    struct PeerInfo {
        PeerID peer_id;
        std::vector<Multiaddr> addrs;
        Timestamp last_seen;
        double reputation;  // For witness selection

        // Vehicle-specific info (if available)
        std::string vehicle_id;
        std::optional<PositionState> position;
    };

    /**
     * Communication protocols
     */
    enum class Protocol {
        GOSSIPSUB,   // Pub/Sub for block propagation
        BITSWAP,     // Block/data exchange
        DHT,         // Peer discovery and routing
        PING,        // Keepalive
        IDENTIFY,    // Peer information exchange
        CUSTOM       // Custom mesh-chain protocol
    };

    /**
     * Message types
     */
    struct Message {
        PeerID sender;
        PeerID receiver;  // Empty for broadcast
        Protocol protocol;
        Timestamp sent_at;
        std::vector<uint8_t> data;
    };

    using MessageHandler = std::function<void(const Message&)>;

    struct Config {
        std::string vehicle_id;
        std::vector<uint8_t> private_key;  // For PeerID generation
        std::vector<Multiaddr> listen_addrs;
        std::vector<Multiaddr> bootstrap_peers;
        bool enable_dht;
        bool enable_gossipsub;
        bool enable_bitswap;
    };

private:
    Config config_;
    PeerID self_peer_id_;

    // Peer registry
    std::map<PeerID, PeerInfo> known_peers_;
    std::set<PeerID> connected_peers_;

    // DHT - Distributed Hash Table
    std::map<std::string, std::vector<PeerID>> dht_table_;  // key -> peer list

    // GossipSub - Topics and subscriptions
    std::map<std::string, std::set<PeerID>> topic_peers_;
    std::map<std::string, std::vector<MessageHandler>> topic_handlers_;

    // Bitswap - Block/data exchange
    std::map<Hash256, Block> block_cache_;
    std::set<Hash256> want_list_;  // Blocks we want
    std::map<PeerID, std::set<Hash256>> peer_have_list_;  // What peers have

    // Communication logs for V2XRecord
    struct P2PCommLog {
        Timestamp timestamp;
        PeerID peer;
        Protocol protocol;
        size_t bytes_sent;
        size_t bytes_received;
        std::string topic;  // For GossipSub
        std::optional<Hash256> block_hash;  // For Bitswap
    };
    std::vector<P2PCommLog> comm_logs_;

    // Statistics
    size_t messages_sent_;
    size_t messages_received_;
    size_t bytes_sent_;
    size_t bytes_received_;

public:
    explicit LibP2PNode(const Config& config)
        : config_(config),
          messages_sent_(0),
          messages_received_(0),
          bytes_sent_(0),
          bytes_received_(0) {

        // Generate PeerID from private key
        self_peer_id_ = generatePeerID(config.private_key);

        std::cout << "[libp2p] Initializing simulation-optimized node\n";
    }

    /**
     * Start libp2p node
     */
    bool start() {
        std::cout << "[libp2p] Starting node: " << self_peer_id_.toString() << "\n";

        // Initialize DHT
        if (config_.enable_dht) {
            initializeDHT();
        }

        // Connect to bootstrap peers
        for (const auto& addr : config_.bootstrap_peers) {
            connectToPeer(addr);
        }

        return true;
    }

    /**
     * Stop libp2p node
     */
    void stop() {
        std::cout << "[libp2p] Stopping node: " << self_peer_id_.toString() << "\n";
        connected_peers_.clear();
    }

    /**
     * Get self PeerID
     */
    PeerID getSelfPeerID() const {
        return self_peer_id_;
    }

    /**
     * Publish message to GossipSub topic
     */
    void publish(const std::string& topic, const std::vector<uint8_t>& data) {
        if (!config_.enable_gossipsub) return;

        // Get subscribers
        auto it = topic_peers_.find(topic);
        if (it == topic_peers_.end()) return;

        // Broadcast to all subscribers
        for (const auto& peer : it->second) {
            Message msg;
            msg.sender = self_peer_id_;
            msg.receiver = peer;
            msg.protocol = Protocol::GOSSIPSUB;
            msg.sent_at = std::chrono::system_clock::now();
            msg.data = data;

            sendMessage(msg);

            // Log communication
            P2PCommLog log;
            log.timestamp = msg.sent_at;
            log.peer = peer;
            log.protocol = Protocol::GOSSIPSUB;
            log.bytes_sent = data.size();
            log.bytes_received = 0;
            log.topic = topic;
            comm_logs_.push_back(log);
        }

        messages_sent_ += it->second.size();
        bytes_sent_ += data.size() * it->second.size();
    }

    /**
     * Subscribe to GossipSub topic
     */
    void subscribe(const std::string& topic, MessageHandler handler) {
        if (!config_.enable_gossipsub) return;

        topic_handlers_[topic].push_back(handler);
        std::cout << "[libp2p] Subscribed to topic: " << topic << "\n";
    }

    /**
     * Find peers in DHT
     */
    std::vector<PeerID> findPeers(const std::string& key) {
        if (!config_.enable_dht) return {};

        auto it = dht_table_.find(key);
        if (it != dht_table_.end()) {
            return it->second;
        }
        return {};
    }

    /**
     * Announce presence in DHT
     */
    void provideToDHT(const std::string& key) {
        if (!config_.enable_dht) return;

        dht_table_[key].push_back(self_peer_id_);
        std::cout << "[libp2p] Announced to DHT: " << key << "\n";
    }

    /**
     * Request block via Bitswap
     */
    void wantBlock(const Hash256& block_hash) {
        if (!config_.enable_bitswap) return;

        want_list_.insert(block_hash);

        // Send WANT to connected peers
        std::vector<uint8_t> want_msg;
        want_msg.insert(want_msg.end(), block_hash.begin(), block_hash.end());

        for (const auto& peer : connected_peers_) {
            Message msg;
            msg.sender = self_peer_id_;
            msg.receiver = peer;
            msg.protocol = Protocol::BITSWAP;
            msg.sent_at = std::chrono::system_clock::now();
            msg.data = want_msg;

            sendMessage(msg);
        }
    }

    /**
     * Provide block via Bitswap
     */
    void provideBlock(const Block& block) {
        if (!config_.enable_bitswap) return;

        block_cache_[block.block_hash] = block;

        // Announce to peers
        for (const auto& peer : connected_peers_) {
            // Would send HAVE message
        }
    }

    /**
     * Get connected peers
     */
    std::vector<PeerInfo> getConnectedPeers() const {
        std::vector<PeerInfo> peers;
        for (const auto& peer_id : connected_peers_) {
            auto it = known_peers_.find(peer_id);
            if (it != known_peers_.end()) {
                peers.push_back(it->second);
            }
        }
        return peers;
    }

    /**
     * Get communication logs for V2XRecord
     */
    std::vector<P2PCommLog> getCommLogs() {
        std::vector<P2PCommLog> logs = comm_logs_;
        comm_logs_.clear();
        return logs;
    }

    /**
     * Get statistics
     */
    void getStatistics(size_t& sent, size_t& received,
                      size_t& bytes_tx, size_t& bytes_rx) const {
        sent = messages_sent_;
        received = messages_received_;
        bytes_tx = bytes_sent_;
        bytes_rx = bytes_received_;
    }

    /**
     * Discover witnesses via DHT
     * Returns peers that can serve as witnesses based on:
     * - Geographic proximity (if position known)
     * - Reputation
     * - Availability
     */
    std::vector<WitnessCandidate> discoverWitnesses(
            const std::optional<PositionState>& my_position,
            double max_distance_km = 10.0) {

        std::vector<WitnessCandidate> candidates;

        // Query DHT for witnesses in region
        auto regional_peers = findPeers("witnesses:region");

        for (const auto& peer_id : regional_peers) {
            auto it = known_peers_.find(peer_id);
            if (it == known_peers_.end()) continue;

            const auto& peer_info = it->second;

            // Check distance if positions known
            if (my_position.has_value() && peer_info.position.has_value()) {
                double distance_km = calculateDistance(*my_position, *peer_info.position);
                if (distance_km > max_distance_km) continue;
            }

            // Convert to WitnessCandidate
            WitnessCandidate candidate;
            candidate.id = peer_info.vehicle_id.empty() ?
                          peer_id.toString() : peer_info.vehicle_id;
            candidate.public_key = peer_id.pubkey;
            candidate.kem_public_key = peer_id.pubkey;  // Would be separate
            candidate.reputation.R = peer_info.reputation;
            candidate.oem = "Unknown";  // Would get from peer info
            candidate.distance_m = my_position.has_value() && peer_info.position.has_value() ?
                                  calculateDistance(*my_position, *peer_info.position) * 1000.0 : 0.0;
            candidate.first_contact = peer_info.last_seen;

            candidates.push_back(candidate);
        }

        return candidates;
    }

private:
    /**
     * Generate PeerID from private key
     */
    PeerID generatePeerID(const std::vector<uint8_t>& privkey) {
        PeerID peer_id;

        // In real implementation: Hash(PublicKey(privkey))
        // For simulation: Use first 32 bytes of privkey hash
        std::string id_str = "Qm";  // Base58 multihash prefix
        for (size_t i = 0; i < std::min(size_t(32), privkey.size()); ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", privkey[i]);
            id_str += hex;
        }

        peer_id.id = id_str;
        peer_id.pubkey = privkey;  // Simplified

        return peer_id;
    }

    /**
     * Initialize DHT
     */
    void initializeDHT() {
        // Announce self to bootstrap peers
        provideToDHT("vehicles");
        provideToDHT("witnesses:region");
    }

    /**
     * Connect to peer
     */
    void connectToPeer(const Multiaddr& addr) {
        // In real implementation: Establish connection
        // For simulation: Just mark as connected
        std::cout << "[libp2p] Connecting to: " << addr.toString() << "\n";
    }

    /**
     * Send message to peer
     */
    void sendMessage(const Message& msg) {
        // In real implementation: Send via network
        // For simulation: Log the send
        messages_sent_++;
        bytes_sent_ += msg.data.size();
    }

    /**
     * Calculate distance between two positions (Haversine)
     */
    double calculateDistance(const PositionState& pos1, const PositionState& pos2) const {
        const double R = 6371.0;  // Earth radius in km

        double lat1 = pos1.latitude * M_PI / 180.0;
        double lat2 = pos2.latitude * M_PI / 180.0;
        double dlat = (pos2.latitude - pos1.latitude) * M_PI / 180.0;
        double dlon = (pos2.longitude - pos1.longitude) * M_PI / 180.0;

        double a = std::sin(dlat/2) * std::sin(dlat/2) +
                  std::cos(lat1) * std::cos(lat2) *
                  std::sin(dlon/2) * std::sin(dlon/2);
        double c = 2 * std::atan2(std::sqrt(a), std::sqrt(1-a));

        return R * c;  // Distance in km
    }
};

} // namespace integration
} // namespace meshchain

#endif // USE_CPP_LIBP2P (simulation-optimized implementation)

#endif // MESHCHAIN_LIBP2P_NODE_H
