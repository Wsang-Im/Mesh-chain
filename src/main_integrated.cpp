/**
 * Mesh-Chain Integrated Simulation with SUMO and WAVE
 *
 * Integrates:
 * - SUMO for vehicular mobility (via TraCI)
 * - WAVE (IEEE 802.11p) for V2V/V2I communication
 * - RSU (Roadside Units) for L1/L2/L3 Anchoring
 * - ToF distance bounding with real SUMO distances
 * - PQC crypto (FALCON, ML-KEM, ML-DSA)
 * - Mesh-chain protocol with witness diversity
 */

#include "common/types.h"
#include "common/config_loader.h"
#include "integration/traci_client.h"
// wave_stack.h is included via integrated_vehicle.h (with OMNeT++/Veins support)
#include "integration/tof_adapter.h"
#include "integration/integrated_vehicle.h"
#include "infrastructure/rsu.h"
#include "vehicle/witness_selection.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <memory>
#include <map>
#include <thread>
#include <chrono>

using namespace meshchain;
using namespace meshchain::integration;
using namespace meshchain::infrastructure;
using namespace meshchain::config;

/**
 * Integrated Simulation Controller
 */
class IntegratedSimulation {
private:
    SimulationConfig config_;
    std::shared_ptr<TraCIClient> traci_;
    std::map<std::string, std::shared_ptr<IntegratedVehicle>> vehicles_;
    std::map<std::string, std::shared_ptr<WaveStack>> wave_stacks_;

    // RSU infrastructure
    std::vector<std::shared_ptr<RSU>> rsus_;

    // Statistics
    size_t total_blocks_created_;
    size_t total_blocks_failed_;
    double total_latency_ms_;

    // Web dashboard data
    std::ofstream dashboard_file_;

public:
    IntegratedSimulation(const SimulationConfig& config) :
        config_(config),
        total_blocks_created_(0),
        total_blocks_failed_(0),
        total_latency_ms_(0.0) {}

    /**
     * Initialize simulation with SUMO
     */
    bool initialize() {
        std::cout << "=== Initializing Mesh-Chain + SUMO Simulation ===\n\n";

        // Initialize TraCI client from config
        TraCIClient::Config traci_config;
        traci_config.sumo_host = config_.sumo_host;
        traci_config.sumo_port = config_.sumo_port;
        traci_config.sumo_config = config_.sumo_config_file;
        traci_config.auto_start_sumo = config_.sumo_auto_start;
        traci_config.use_gui = config_.sumo_use_gui;
        traci_config.step_length_s = config_.step_length;
        traci_config.max_duration_s = config_.duration_seconds;

        traci_ = std::make_shared<TraCIClient>(traci_config);

        if (!traci_->connect()) {
            std::cerr << "❌ Failed to connect to SUMO\n";
            std::cerr << "   Config file: " << config_.sumo_config_file << "\n";
            std::cerr << "   Ensure SUMO is installed and paths are correct.\n";
            return false;
        }

        std::cout << "✓ Connected to SUMO via TraCI\n";
        std::cout << "✓ Scenario: " << config_.sumo_config_file << "\n";
        std::cout << "✓ GUI: " << (config_.sumo_use_gui ? "활성화" : "비활성화") << "\n\n";

        // Open dashboard data file for web GUI
        // Path is relative to build/ directory, so need ../
        dashboard_file_.open("../visualization/data/simulation_data.json", std::ios::trunc);
        if (dashboard_file_.is_open()) {
            std::cout << "✓ Dashboard data file opened: ../visualization/data/simulation_data.json\n\n";
        } else {
            std::cerr << "⚠ Warning: Could not open dashboard data file\n\n";
        }

        // Initialize RSUs along highway (400m spacing for optimal coverage)
        initializeRSUs();

        return true;
    }

    /**
     * Initialize RSU infrastructure
     *
     * Deployment strategy based on real-world standards:
     * - Highway length: 1000m (SUMO scenario)
     * - DSRC range: 300m (IEEE 802.11p)
     * - Spacing: 400m (optimal coverage with overlap)
     * - RSU count: 3 units
     * - Positions: 200m, 500m, 800m
     * - L1 anchor period: 60s (per-RSU local anchoring)
     */
    void initializeRSUs() {
        std::cout << "=== Initializing RSU Infrastructure ===\n\n";

        // RSU configuration from sim config
        uint32_t l1_period = config_.rsu_l1_anchor_period;
        uint32_t l2_period = config_.rsu_l2_anchor_period;
        uint32_t l3_period = config_.rsu_l3_anchor_period;
        double range_m = config_.wave_range_m;

        // RSU positions along 3km curved highway
        struct RSUPosition {
            std::string id;
            double x;
            double y;
        };

        std::vector<RSUPosition> positions = {
            // 3km highway with 1km RSU spacing (300m coverage each)
            // 도로 실제 좌표: y=172~213 범위
            // North side (도로 북쪽 바로 옆, +10m)
            {"RSU-1N", 0.0, 203.0},      // 0km mark (road: 172-193)
            {"RSU-2N", 1000.0, 223.0},   // 1km mark (road: 204-213)
            {"RSU-3N", 2000.0, 223.0},   // 2km mark (road: 192-213)
            {"RSU-4N", 3000.0, 188.0},   // 3km mark (road: 172-178)
            // South side (도로 남쪽 바로 옆, -15m) - 500m 엇갈림 배치
            {"RSU-1S", 500.0, 169.0},    // 0.5km mark (road: 184-191)
            {"RSU-2S", 1500.0, 192.0},   // 1.5km mark (road: 207-223)
            {"RSU-3S", 2500.0, 177.0}    // 2.5km mark (road: 192-208)
        };

        for (const auto& pos : positions) {
            RSUConfig rsu_config;
            rsu_config.rsu_id = pos.id;
            rsu_config.simulation_id = "integrated";  // Identify this simulation
            rsu_config.position_x = pos.x;
            rsu_config.position_y = pos.y;
            rsu_config.communication_range_m = range_m;
            rsu_config.l1_anchor_period_sec = l1_period;
            rsu_config.l2_anchor_period_sec = l2_period;
            rsu_config.l3_anchor_period_sec = l3_period;
            rsu_config.max_blocks_stored = 10000;
            rsu_config.has_cloud_connection = false;  // L3 anchor disabled for now
            rsu_config.l1_export_dir = "/tmp/meshchain_l1";  // Export L1 anchors for L2 aggregation

            auto rsu = std::make_shared<RSU>(rsu_config);
            rsu->start();  // Start L1 anchoring thread
            rsus_.push_back(rsu);
        }

        std::cout << "✓ Deployed " << rsus_.size() << " RSUs along 5km highway\n";
        std::cout << "  - Configuration: 5 North (y=15m) + 5 South (y=-15m)\n";
        std::cout << "  - North RSUs: x=500m, 1500m, 2500m, 3500m, 4500m\n";
        std::cout << "  - South RSUs: x=750m, 1750m, 2750m, 3750m, 4750m (staggered 250m)\n";
        std::cout << "  - Spacing: ~1km between RSUs (optimal coverage)\n";
        std::cout << "  - Range: " << range_m << "m\n";
        std::cout << "  - L1 Anchor Period: " << l1_period << "s\n\n";
    }

    /**
     * Run simulation
     */
    void run() {
        std::cout << "=== Running Simulation for " << config_.duration_seconds << "s ===\n\n";

        auto start_time = std::chrono::steady_clock::now();
        auto last_anchor_time = start_time;  // Track last L1 anchor time
        const double L1_ANCHOR_PERIOD = 60.0;  // 60 seconds
        size_t step_count = 0;

        while (true) {
            auto current = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(current - start_time).count();

            if (elapsed >= config_.duration_seconds) {
                break;
            }

            // Step SUMO
            if (!traci_->step()) {
                std::cout << "SUMO simulation ended\n";
                break;
            }

            step_count++;

            // Update vehicle list from SUMO
            updateVehicles();

            // Step all vehicles
            for (auto& [vid, vehicle] : vehicles_) {
                vehicle->step(vehicles_);  // Pass vehicles map for witness signing
            }

            // Process WAVE message propagation
            for (auto& [vid, vehicle] : vehicles_) {
                vehicle->processMessagePropagation(wave_stacks_);
            }

            // Pull-based L1 Anchoring: RSU requests blocks from vehicles every 60s
            double anchor_elapsed = std::chrono::duration<double>(current - last_anchor_time).count();
            if (anchor_elapsed >= L1_ANCHOR_PERIOD) {
                std::cout << "\n=== L1 Anchoring Period (60s) ===\n";
                for (auto& rsu : rsus_) {
                    rsu->requestBlocksFromVehicles(vehicles_);
                    // Create L1 anchor with collected blocks
                    rsu->createL1Anchor();
                }
                last_anchor_time = current;
                std::cout << "=== L1 Anchoring Completed ===\n\n";
            }

            // Print status every 10 seconds
            if (step_count % 100 == 0) {
                printStatus();

                // Print micro-chain status for first 3 active vehicles
                std::cout << "\n--- Micro-Chain Status ---\n";
                int count = 0;
                for (const auto& [vid, vehicle] : vehicles_) {
                    size_t chain_len = vehicle->getMicroChainLength();
                    size_t created, failed;
                    vehicle->getBlockStatistics(created, failed);
                    std::cout << "  " << vid << ": chain=" << chain_len
                              << " (created=" << created << ", failed=" << failed << ")\n";
                    if (++count >= 3) break;
                }
            }

            // Sleep to match simulation time (100ms per step)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));  // 10x speedup
        }

        std::cout << "\n=== Simulation Complete ===\n";
        std::cout << "Total steps: " << step_count << "\n";
        std::cout << "Total vehicles seen: " << vehicles_.size() << "\n";
        printFinalStatistics();
    }

    /**
     * Shutdown simulation
     */
    void shutdown() {
        std::cout << "\n=== Shutting down simulation ===\n";

        // STEP 1: Stop RSU anchoring threads FIRST
        // This prevents RSUs from accessing vehicles during cleanup
        std::cout << "Stopping RSU infrastructure...\n";
        for (auto& rsu : rsus_) {
            rsu->stop();
        }
        std::cout << "✓ All RSU threads stopped\n";

        // STEP 2: Wait for all async block creation operations to complete
        // This prevents "free(): invalid pointer" errors caused by:
        // 1. std::async tasks still running when objects are destroyed
        // 2. Multiple threads accessing liboqs objects during destruction

        std::cout << "Waiting for all async operations to complete...\n";

        // Wait much longer (5 seconds) to ensure all pending async tasks finish
        // This includes:
        // - Block creation operations (~100ms each)
        // - TLS handshakes and signature requests
        // - Network delay simulations
        // - Crypto operations (FALCON-512 signatures)
        // With many vehicles, multiple operations may be in flight
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));

        std::cout << "✓ Async operations should be completed\n";
        std::cout << "Clearing " << vehicles_.size() << " vehicles (slowly to avoid crashes)...\n";

        // Clear vehicles one by one VERY slowly to avoid race conditions
        // The memory corruption happens when async operations are still using
        // crypto objects (liboqs) while they're being destroyed
        size_t total = vehicles_.size();
        size_t count = 0;
        for (auto it = vehicles_.begin(); it != vehicles_.end(); ) {
            it = vehicles_.erase(it);
            count++;
            if (count % 5 == 0) {
                std::cout << "  Cleared " << count << "/" << total << " vehicles...\n";
                // Longer delay between smaller batches
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }

        wave_stacks_.clear();

        if (traci_) {
            traci_->disconnect();
        }
        if (dashboard_file_.is_open()) {
            dashboard_file_.close();
        }

        std::cout << "✓ Shutdown complete\n";
    }

private:
    /**
     * Update vehicle list from SUMO
     * Create IntegratedVehicle instances for new vehicles
     */
    void updateVehicles() {
        const auto& vehicle_states = traci_->getVehicleStates();

        for (const auto& [vid, state] : vehicle_states) {
            // Check if vehicle already exists
            if (vehicles_.find(vid) != vehicles_.end()) {
                continue;
            }

            // Create new IntegratedVehicle
            IntegratedVehicle::Config config;
            config.vehicle_id = vid;
            config.traci = traci_;

            // WAVE config (from config file)
            config.wave_config.node_id = vid;
            config.wave_config.tx_power_dbm = config_.wave_tx_power_dbm;
            config.wave_config.frequency_ghz = config_.wave_frequency_ghz;
            config.wave_config.bandwidth_mhz = config_.wave_bandwidth_mhz;
            config.wave_config.data_rate_mbps = config_.wave_data_rate_mbps;
            config.wave_config.range_m = config_.wave_range_m;
            config.wave_config.packet_loss_rate = config_.wave_packet_loss_rate;
            config.wave_config.cam_interval_ms = config_.wave_cam_interval_ms;
            config.wave_config.denm_priority = config_.wave_denm_priority;

            // ToF config (from config file)
            config.tof_config.vehicle_id = vid;
            config.tof_config.sigma_tof_ns = config_.tof_sigma_ns;
            config.tof_config.use_uwb = config_.tof_use_uwb;
            config.tof_config.channel_noise_db = config_.tof_channel_noise_db;

            // libp2p config (from config file)
            config.libp2p_config.vehicle_id = vid;
            // Generate unique private key from vehicle ID
            std::vector<uint8_t> privkey(32);
            for (size_t k = 0; k < 32; ++k) {
                privkey[k] = static_cast<uint8_t>((vid[k % vid.size()] + k) % 256);
            }
            config.libp2p_config.private_key = privkey;
            config.libp2p_config.enable_dht = config_.libp2p_enable_dht;
            config.libp2p_config.enable_gossipsub = config_.libp2p_enable_gossipsub;
            config.libp2p_config.enable_bitswap = config_.libp2p_enable_bitswap;

            // Diversity policy (from config file)
            config.diversity_policy.min_H_m = config_.diversity_min_oem_entropy;
            config.diversity_policy.p_max = config_.diversity_max_per_oem_ratio;
            config.diversity_policy.min_d_m = config_.diversity_min_spatial_separation;
            config.diversity_policy.min_MAD_t = config_.diversity_min_temporal_mad;
            config.diversity_policy.min_R = config_.diversity_min_reputation;
            config.diversity_policy.min_R_diff = config_.diversity_min_reputation_diff;

            config.sigma_tof_ns = config_.tof_sigma_ns;

            // SIMPLE: V2X 통신 기록 받으면 즉시 블록 생성 (no config needed)

            // Register block creation callback for statistics
            config.on_block_created = [this](bool success, double latency_ms) {
                if (success) {
                    total_blocks_created_++;
                    total_latency_ms_ += latency_ms;
                } else {
                    total_blocks_failed_++;
                }
            };

            auto vehicle = std::make_shared<IntegratedVehicle>(config);
            vehicle->setRSUs(&rsus_);  // Set RSU infrastructure pointer
            vehicles_[vid] = vehicle;
            wave_stacks_[vid] = vehicle->getWaveStack();

            std::cout << "[NEW] Vehicle " << vid << " entered simulation\n";
        }

        // Remove vehicles that left SUMO
        std::vector<std::string> to_remove;
        for (const auto& [vid, vehicle] : vehicles_) {
            if (vehicle_states.find(vid) == vehicle_states.end()) {
                to_remove.push_back(vid);
            }
        }

        for (const auto& vid : to_remove) {
            std::cout << "[EXIT] Vehicle " << vid << " left simulation\n";
            vehicles_.erase(vid);
            wave_stacks_.erase(vid);
        }
    }

    /**
     * Print current simulation status
     */
    void printStatus() {
        size_t active_vehicles = vehicles_.size();
        double sim_time = traci_->getCurrentTime();

        std::cout << "[t=" << std::fixed << std::setprecision(1) << sim_time << "s] "
                  << "Vehicles: " << active_vehicles << "\n";

        // Print WAVE statistics for first 3 vehicles
        int count = 0;
        for (const auto& [vid, vehicle] : vehicles_) {
            if (count >= 3) break;

            size_t sent, received, lost;
            vehicle->getStatistics(sent, received, lost);

            std::cout << "  " << vid << ": TX=" << sent << " RX=" << received
                     << " LOST=" << lost << "\n";
            count++;
        }

        // Update dashboard data (JSON)
        updateDashboardData(sim_time);
    }

    /**
     * Update dashboard JSON data for web GUI
     */
    void updateDashboardData(double sim_time) {
        if (!dashboard_file_.is_open()) return;

        // Collect statistics
        size_t total_sent = 0;
        size_t total_received = 0;
        size_t total_lost = 0;

        for (const auto& [vid, vehicle] : vehicles_) {
            size_t sent, received, lost;
            vehicle->getStatistics(sent, received, lost);
            total_sent += sent;
            total_received += received;
            total_lost += lost;
        }

        double loss_rate = (total_sent + total_lost) > 0 ?
            (100.0 * total_lost / (total_sent + total_lost)) : 0.0;

        double avg_latency = total_blocks_created_ > 0 ?
            (total_latency_ms_ / total_blocks_created_) : 0.0;

        // Write JSON data
        dashboard_file_.seekp(0);
        dashboard_file_ << "{\n";
        dashboard_file_ << "  \"time\": " << sim_time << ",\n";
        dashboard_file_ << "  \"vehicles\": [\n";

        // Vehicle positions
        bool first = true;
        for (const auto& [vid, vehicle] : vehicles_) {
            auto vehicle_state = traci_->getVehicleState(vid);
            if (!vehicle_state.has_value()) continue;

            if (!first) dashboard_file_ << ",\n";
            first = false;

            dashboard_file_ << "    {\n";
            dashboard_file_ << "      \"id\": \"" << vid << "\",\n";
            dashboard_file_ << "      \"x\": " << vehicle_state->x << ",\n";
            dashboard_file_ << "      \"y\": " << vehicle_state->y << ",\n";
            dashboard_file_ << "      \"speed\": " << vehicle_state->speed_mps << ",\n";
            dashboard_file_ << "      \"lane\": \"" << vehicle_state->lane_id << "\",\n";
            dashboard_file_ << "      \"status\": \"normal\"\n";
            dashboard_file_ << "    }";
        }
        dashboard_file_ << "\n  ],\n";

        // RSU positions (infrastructure)
        dashboard_file_ << "  \"rsus\": [\n";
        first = true;
        for (const auto& rsu : rsus_) {
            if (!first) dashboard_file_ << ",\n";
            first = false;

            dashboard_file_ << "    {\n";
            dashboard_file_ << "      \"id\": \"" << rsu->getID() << "\",\n";
            dashboard_file_ << "      \"x\": " << rsu->getX() << ",\n";
            dashboard_file_ << "      \"y\": " << rsu->getY() << ",\n";
            dashboard_file_ << "      \"range\": " << rsu->getRange() << "\n";
            dashboard_file_ << "    }";
        }
        dashboard_file_ << "\n  ],\n";

        dashboard_file_ << "  \"stats\": {\n";
        dashboard_file_ << "    \"activeVehicles\": " << vehicles_.size() << ",\n";
        dashboard_file_ << "    \"blocksCreated\": " << total_blocks_created_ << ",\n";
        dashboard_file_ << "    \"blocksFailed\": " << total_blocks_failed_ << ",\n";
        dashboard_file_ << "    \"waveSent\": " << total_sent << ",\n";
        dashboard_file_ << "    \"waveReceived\": " << total_received << ",\n";
        dashboard_file_ << "    \"waveLost\": " << total_lost << ",\n";
        dashboard_file_ << "    \"lossRate\": " << loss_rate << ",\n";
        dashboard_file_ << "    \"avgLatency\": " << avg_latency << ",\n";
        dashboard_file_ << "    \"p2pPeers\": " << vehicles_.size() << "\n";
        dashboard_file_ << "  }\n";
        dashboard_file_ << "}\n";
        dashboard_file_.flush();
    }

    /**
     * Print final statistics
     */
    void printFinalStatistics() {
        size_t total_sent = 0;
        size_t total_received = 0;
        size_t total_lost = 0;

        for (const auto& [vid, vehicle] : vehicles_) {
            size_t sent, received, lost;
            vehicle->getStatistics(sent, received, lost);
            total_sent += sent;
            total_received += received;
            total_lost += lost;
        }

        std::cout << "\n--- WAVE Communication Statistics ---\n";
        std::cout << "Total messages sent (broadcasts): " << total_sent << "\n";
        std::cout << "Total messages received: " << total_received << "\n";
        std::cout << "Total messages lost: " << total_lost << "\n";

        if (total_sent > 0) {
            // Correct calculation: loss_rate = lost / (received + lost)
            // NOT lost / (sent + lost) because sent is broadcast count, not reception count
            size_t expected_receives = total_received + total_lost;
            double loss_rate = expected_receives > 0 ?
                100.0 * total_lost / expected_receives : 0.0;
            double avg_receivers = static_cast<double>(expected_receives) / total_sent;

            std::cout << "Expected receives: " << expected_receives << "\n";
            std::cout << "Average receivers per broadcast: " << std::fixed << std::setprecision(1)
                     << avg_receivers << "\n";
            std::cout << "Packet loss rate: " << std::fixed << std::setprecision(1)
                     << loss_rate << "%\n";
        }

        std::cout << "\n--- Blockchain Statistics ---\n";
        std::cout << "Blocks created: " << total_blocks_created_ << "\n";
        std::cout << "Blocks failed: " << total_blocks_failed_ << "\n";
        if (total_blocks_created_ > 0) {
            std::cout << "Average latency: " << std::fixed << std::setprecision(2)
                     << (total_latency_ms_ / total_blocks_created_) << "ms\n";
        }

        // Print micro-chain summaries for all vehicles
        std::cout << "\n--- Micro-Chain Summaries (Per Vehicle) ---\n";
        if (vehicles_.empty()) {
            std::cout << "No vehicles remaining in simulation\n";
        } else {
            int vehicle_count = 0;
            for (const auto& [vid, vehicle] : vehicles_) {
                vehicle->printMicroChainSummary();
                vehicle_count++;
                // Limit to first 5 vehicles to avoid too much output
                if (vehicle_count >= 5) {
                    std::cout << "... (showing first 5 vehicles only)\n";
                    break;
                }
            }
        }

        // Print RSU statistics
        std::cout << "\n--- RSU Infrastructure Statistics ---\n";
        size_t total_blocks_received = 0;
        size_t total_blocks_anchored = 0;
        size_t total_l1_anchors = 0;

        for (const auto& rsu : rsus_) {
            size_t received, anchored, l1_anchors;
            rsu->getStatistics(received, anchored, l1_anchors);
            total_blocks_received += received;
            total_blocks_anchored += anchored;
            total_l1_anchors += l1_anchors;

            std::cout << "[" << rsu->getID() << "] "
                      << "Received=" << received << " "
                      << "Anchored=" << anchored << " "
                      << "L1_Anchors=" << l1_anchors << "\n";
        }

        std::cout << "\nRSU Totals:\n";
        std::cout << "  Total blocks received by RSUs: " << total_blocks_received << "\n";
        std::cout << "  Total blocks anchored: " << total_blocks_anchored << "\n";
        std::cout << "  Total L1 anchors created: " << total_l1_anchors << "\n";

        // Stop all RSUs
        for (auto& rsu : rsus_) {
            rsu->stop();
        }
    }
};

int main(int argc, char** argv) {
    std::cout << "==================================================\n";
    std::cout << "  Mesh-Chain V2X Blockchain Simulation\n";
    std::cout << "  with SUMO Integration and WAVE Communication\n";
    std::cout << "==================================================\n\n";

    std::cout << "Core Components:\n";
    std::cout << "✓ SUMO mobility via TraCI\n";
    std::cout << "✓ WAVE (IEEE 802.11p) V2V/V2I\n";
    std::cout << "✓ Real-distance ToF measurement\n";
    std::cout << "✓ PQC-only fast path (FALCON-512)\n";
    std::cout << "✓ ML-KEM secure channels\n";
    std::cout << "✓ P2P communication logs in payload\n";
    std::cout << "✓ Target: ≤100ms local finality\n\n";

    // Load configuration
    SimulationConfig config;

    // Check for --help first
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--help" || std::string(argv[i]) == "-h") {
            config.printUsage(argv[0]);
            return 0;
        }
    }

    // Determine config file path
    // Try both relative paths for root and build directory execution
    std::string config_file;
    bool config_specified = false;
    for (int i = 1; i < argc - 1; i++) {
        if (std::string(argv[i]) == "--config") {
            config_file = argv[i + 1];
            config_specified = true;
            break;
        }
    }

    if (!config_specified) {
        // Try from build directory first
        if (std::ifstream("../config/simulation_config.yaml").good()) {
            config_file = "../config/simulation_config.yaml";
        }
        // Then try from root directory
        else if (std::ifstream("config/simulation_config.yaml").good()) {
            config_file = "config/simulation_config.yaml";
        }
        else {
            config_file = "config/simulation_config.yaml";  // Default
        }
    }

    // Load configuration from YAML
    if (!config.loadFromFile(config_file)) {
        std::cerr << "⚠ Warning: Could not load config file: " << config_file << "\n";
        std::cerr << "   Using default configuration values\n\n";
    }

    // Apply command-line overrides
    config.applyCommandLineOverrides(argc, argv);

    // Print configuration summary
    config.printSummary();

    // Run simulation
    IntegratedSimulation sim(config);

    if (!sim.initialize()) {
        std::cerr << "\n❌ Failed to initialize simulation\n";
        std::cerr << "Hint: Ensure SUMO is installed and paths are correct.\n";
        std::cerr << "      Config file: " << config_file << "\n";
        return 1;
    }

    sim.run();
    sim.shutdown();

    std::cout << "\n✓ Simulation completed successfully\n";
    return 0;
}
