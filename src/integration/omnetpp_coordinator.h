#ifndef MESHCHAIN_OMNETPP_COORDINATOR_H
#define MESHCHAIN_OMNETPP_COORDINATOR_H

/**
 * OMNeT++ Simulation Coordinator
 *
 * Bridges C++ application logic with OMNeT++/Veins network simulation.
 * Uses shared memory and IPC to communicate between:
 * - Mesh-Chain application (C++ standalone)
 * - OMNeT++ network simulation (separate process)
 */

#include "../common/types.h"
#include "../common/v2x_messages.h"
#include <string>
#include <map>
#include <queue>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace meshchain {
namespace integration {

#ifdef USE_OMNETPP_VEINS

/**
 * Message format for IPC with OMNeT++ process
 */
struct OMNeTIPCMessage {
    enum class Type {
        REGISTER_NODE,      // Register vehicle node with OMNeT++
        UPDATE_POSITION,    // Update node position from SUMO
        SEND_PACKET,        // Send packet via IEEE 802.11p
        RECV_PACKET,        // Receive packet from OMNeT++
        STEP_SIMULATION,    // Advance OMNeT++ simulation
        SHUTDOWN            // Terminate OMNeT++ process
    };

    Type type;
    std::string node_id;
    double x, y, z;           // Position
    double speed, heading;    // Mobility
    std::vector<uint8_t> payload;
    Timestamp timestamp;
};

/**
 * OMNeT++ Coordinator
 *
 * Manages communication with OMNeT++ simulation process.
 * Uses Unix domain sockets for low-latency IPC.
 */
class OMNeTCoordinator {
public:
    struct Config {
        std::string socket_path = "/tmp/meshchain_omnetpp.sock";
        bool auto_start_omnetpp = true;
        std::string omnetpp_config_file = "omnetpp.ini";
        int timeout_ms = 5000;
    };

    using PacketReceivedCallback = std::function<void(const std::string& sender_id,
                                                       const std::string& receiver_id,
                                                       const std::vector<uint8_t>& payload,
                                                       Timestamp received_at)>;

private:
    Config config_;
    int socket_fd_;
    std::atomic<bool> connected_;
    std::atomic<bool> running_;

    std::map<std::string, PacketReceivedCallback> callbacks_;
    std::mutex callback_mutex_;

    pid_t omnetpp_pid_;  // OMNeT++ process ID

public:
    explicit OMNeTCoordinator(const Config& config)
        : config_(config),
          socket_fd_(-1),
          connected_(false),
          running_(false),
          omnetpp_pid_(-1) {
    }

    ~OMNeTCoordinator() {
        shutdown();
    }

    /**
     * Initialize coordinator and connect to OMNeT++ process
     */
    bool initialize() {
        if (config_.auto_start_omnetpp) {
            if (!startOMNeTProcess()) {
                std::cerr << "[OMNeTCoordinator] Failed to start OMNeT++ process\n";
                return false;
            }
        }

        if (!connectToOMNeT()) {
            std::cerr << "[OMNeTCoordinator] Failed to connect to OMNeT++\n";
            return false;
        }

        connected_ = true;
        running_ = true;

        std::cout << "[OMNeTCoordinator] ✓ Connected to OMNeT++ simulation\n";
        return true;
    }

    /**
     * Register vehicle node with OMNeT++
     */
    bool registerNode(const std::string& node_id) {
        OMNeTIPCMessage msg;
        msg.type = OMNeTIPCMessage::Type::REGISTER_NODE;
        msg.node_id = node_id;
        msg.timestamp = std::chrono::system_clock::now();

        return sendMessage(msg);
    }

    /**
     * Update node position (from SUMO)
     */
    bool updatePosition(const std::string& node_id,
                       double x, double y, double z,
                       double speed, double heading) {
        OMNeTIPCMessage msg;
        msg.type = OMNeTIPCMessage::Type::UPDATE_POSITION;
        msg.node_id = node_id;
        msg.x = x;
        msg.y = y;
        msg.z = z;
        msg.speed = speed;
        msg.heading = heading;
        msg.timestamp = std::chrono::system_clock::now();

        return sendMessage(msg);
    }

    /**
     * Send packet via OMNeT++ IEEE 802.11p
     */
    bool sendPacket(const std::string& sender_id,
                   const std::string& receiver_id,
                   const std::vector<uint8_t>& payload) {
        OMNeTIPCMessage msg;
        msg.type = OMNeTIPCMessage::Type::SEND_PACKET;
        msg.node_id = sender_id;
        msg.payload = payload;
        msg.timestamp = std::chrono::system_clock::now();

        return sendMessage(msg);
    }

    /**
     * Advance OMNeT++ simulation by dt milliseconds
     */
    bool stepSimulation(int dt_ms) {
        OMNeTIPCMessage msg;
        msg.type = OMNeTIPCMessage::Type::STEP_SIMULATION;
        msg.timestamp = std::chrono::system_clock::now();

        return sendMessage(msg);
    }

    /**
     * Register callback for received packets
     */
    void registerCallback(const std::string& node_id, PacketReceivedCallback callback) {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        callbacks_[node_id] = callback;
    }

    /**
     * Process received packets from OMNeT++
     */
    void processReceivedPackets() {
        // Poll socket for incoming messages
        fd_set readfds;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 1000;  // 1ms timeout

        FD_ZERO(&readfds);
        FD_SET(socket_fd_, &readfds);

        int ret = select(socket_fd_ + 1, &readfds, nullptr, nullptr, &tv);
        if (ret > 0 && FD_ISSET(socket_fd_, &readfds)) {
            OMNeTIPCMessage msg;
            if (receiveMessage(msg)) {
                handleReceivedPacket(msg);
            }
        }
    }

    /**
     * Shutdown coordinator and OMNeT++ process
     */
    void shutdown() {
        if (!running_) return;

        running_ = false;

        // Send shutdown message to OMNeT++
        OMNeTIPCMessage msg;
        msg.type = OMNeTIPCMessage::Type::SHUTDOWN;
        sendMessage(msg);

        // Close socket
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }

        // Wait for OMNeT++ process to terminate
        if (omnetpp_pid_ > 0) {
            int status;
            waitpid(omnetpp_pid_, &status, 0);
            omnetpp_pid_ = -1;
        }

        connected_ = false;

        std::cout << "[OMNeTCoordinator] Shutdown complete\n";
    }

    bool isConnected() const { return connected_.load(); }
    bool isRunning() const { return running_.load(); }

private:
    /**
     * Start OMNeT++ simulation process
     */
    bool startOMNeTProcess() {
        std::cout << "[OMNeTCoordinator] Starting OMNeT++ process...\n";

        // Fork and exec OMNeT++
        omnetpp_pid_ = fork();

        if (omnetpp_pid_ < 0) {
            std::cerr << "[OMNeTCoordinator] Fork failed\n";
            return false;
        }

        if (omnetpp_pid_ == 0) {
            // Child process: exec OMNeT++
            // NOTE: This requires a custom OMNeT++ simulation executable
            execl("omnetpp/meshchain_omnetpp",
                  "meshchain_omnetpp",
                  "-u", "Cmdenv",  // Command-line interface
                  "-c", "MeshChain",
                  "-f", config_.omnetpp_config_file.c_str(),
                  nullptr);

            // If exec fails
            std::cerr << "[OMNeTCoordinator] Failed to exec OMNeT++\n";
            exit(1);
        }

        // Parent process: wait for OMNeT++ to initialize
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::cout << "[OMNeTCoordinator] ✓ OMNeT++ process started (PID: "
                  << omnetpp_pid_ << ")\n";
        return true;
    }

    /**
     * Connect to OMNeT++ via Unix domain socket
     */
    bool connectToOMNeT() {
        socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            std::cerr << "[OMNeTCoordinator] Failed to create socket\n";
            return false;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, config_.socket_path.c_str(), sizeof(addr.sun_path) - 1);

        // Retry connection for timeout period
        auto start = std::chrono::steady_clock::now();
        while (true) {
            if (connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                return true;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

            if (elapsed > config_.timeout_ms) {
                std::cerr << "[OMNeTCoordinator] Connection timeout\n";
                close(socket_fd_);
                socket_fd_ = -1;
                return false;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    /**
     * Send message to OMNeT++ process
     */
    bool sendMessage(const OMNeTIPCMessage& msg) {
        if (socket_fd_ < 0) return false;

        // Serialize message (simplified - real implementation needs proper serialization)
        std::vector<uint8_t> buffer;
        // TODO: Implement proper serialization

        ssize_t sent = send(socket_fd_, buffer.data(), buffer.size(), 0);
        return sent == static_cast<ssize_t>(buffer.size());
    }

    /**
     * Receive message from OMNeT++ process
     */
    bool receiveMessage(OMNeTIPCMessage& msg) {
        if (socket_fd_ < 0) return false;

        std::vector<uint8_t> buffer(4096);
        ssize_t received = recv(socket_fd_, buffer.data(), buffer.size(), 0);

        if (received <= 0) return false;

        // Deserialize message
        // TODO: Implement proper deserialization

        return true;
    }

    /**
     * Handle received packet from OMNeT++
     */
    void handleReceivedPacket(const OMNeTIPCMessage& msg) {
        if (msg.type != OMNeTIPCMessage::Type::RECV_PACKET) return;

        std::lock_guard<std::mutex> lock(callback_mutex_);
        auto it = callbacks_.find(msg.node_id);
        if (it != callbacks_.end()) {
            it->second(msg.node_id, "", msg.payload, msg.timestamp);
        }
    }
};

#else

/**
 * Fallback: Dummy coordinator when OMNeT++ not available
 */
class OMNeTCoordinator {
public:
    struct Config {};
    using PacketReceivedCallback = std::function<void(const std::string&, const std::string&,
                                                       const std::vector<uint8_t>&, Timestamp)>;

    explicit OMNeTCoordinator(const Config&) {}
    bool initialize() { return false; }
    bool registerNode(const std::string&) { return false; }
    bool updatePosition(const std::string&, double, double, double, double, double) { return false; }
    bool sendPacket(const std::string&, const std::string&, const std::vector<uint8_t>&) { return false; }
    bool stepSimulation(int) { return false; }
    void registerCallback(const std::string&, PacketReceivedCallback) {}
    void processReceivedPackets() {}
    void shutdown() {}
    bool isConnected() const { return false; }
    bool isRunning() const { return false; }
};

#endif // USE_OMNETPP_VEINS

} // namespace integration
} // namespace meshchain

#endif // MESHCHAIN_OMNETPP_COORDINATOR_H
