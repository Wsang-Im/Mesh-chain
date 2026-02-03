/**
 * Mesh-Chain Integrated Simulation with Attack Scenarios
 *
 * Extends meshchain_integrated to validate attacker models in real-time.
 *
 * Key features:
 * 1. Preserve existing simulation logic (do not break)
 * 2. Optional attacker injection (--attack-mode flag)
 * 3. Real-time mitigation mechanism monitoring
 * 4. Attack statistics collection and analysis
 */

#include "common/types.h"
#include "integration/traci_client.h"
#include "integration/wave_stack.h"
#include "integration/tof_adapter.h"
#include "integration/integrated_vehicle.h"
#include "infrastructure/rsu.h"
#include "vehicle/witness_selection.h"
#include "security/attacker_models.h"  // Add attacker models

#include <iostream>
#include <iomanip>
#include <fstream>
#include <memory>
#include <map>
#include <thread>
#include <chrono>
#include <cstring>

using namespace meshchain;
using namespace meshchain::integration;
using namespace meshchain::infrastructure;
using namespace meshchain::security;

/**
 * Simulation Configuration
 */
struct SimulationConfig {
    int duration_seconds = 60;
    double step_length = 0.1;
    int num_vehicles = 50;
    std::string sumo_config_file = "../sumo/highway.sumocfg";
    std::string sumo_host = "localhost";
    int sumo_port = 8813;
    bool sumo_use_gui = false;
    bool sumo_auto_start = false;

    // WAVE config
    double wave_tx_power_dbm = 20.0;
    double wave_frequency_ghz = 5.9;
    double wave_bandwidth_mhz = 10.0;
    double wave_data_rate_mbps = 6.0;
    double wave_range_m = 300.0;
    double wave_packet_loss_rate = 0.2;
    int wave_cam_interval_ms = 100;
    int wave_denm_priority = 6;

    // ToF config
    double tof_sigma_ns = 3.0;
    bool tof_use_uwb = false;

    // Diversity config
    double diversity_min_oem_entropy = 1.0;
    double diversity_max_per_oem_ratio = 0.5;
    double diversity_min_spatial_separation = 50.0;
    double diversity_min_temporal_mad = 0.1;
    double diversity_min_reputation = 0.3;
    double diversity_min_reputation_diff = 0.05;
};

/**
 * Attack Scenario Configuration
 */
struct AttackScenarioConfig {
    bool enabled = false;
    std::string attack_type = "regional";  // regional, sybil, spam
    double beta_global = 0.2;
    double beta_regional = 0.4;
    double sybil_rate = 0.05;
    double spam_rate = 100.0;

    void parseCommandLine(int argc, char** argv) {
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--attack-mode") {
                enabled = true;
                if (i + 1 < argc) {
                    attack_type = argv[++i];
                }
            } else if (arg == "--attack-beta") {
                if (i + 1 < argc) {
                    beta_regional = std::atof(argv[++i]);
                }
            }
        }
    }
};

/**
 * Extended Integrated Simulation with Attack Capabilities
 */
class AttackIntegratedSimulation {
private:
    SimulationConfig config_;
    AttackScenarioConfig attack_config_;
    std::shared_ptr<TraCIClient> traci_;
    std::map<std::string, std::shared_ptr<IntegratedVehicle>> vehicles_;
    std::map<std::string, std::shared_ptr<WaveStack>> wave_stacks_;
    std::vector<std::shared_ptr<RSU>> rsus_;

    // 공격자 모듈
    std::unique_ptr<AttackCoordinator> attack_coordinator_;
    std::unique_ptr<RegionalMajorityAttacker> regional_attacker_;

    // 통계
    size_t total_blocks_created_;
    size_t total_blocks_failed_;
    size_t total_blocks_with_adversary_;
    size_t total_diversity_checks_;
    size_t total_diversity_failures_;

    std::ofstream dashboard_file_;
    std::ofstream attack_log_file_;

public:
    AttackIntegratedSimulation(const SimulationConfig& config, const AttackScenarioConfig& attack_config) :
        config_(config),
        attack_config_(attack_config),
        total_blocks_created_(0),
        total_blocks_failed_(0),
        total_blocks_with_adversary_(0),
        total_diversity_checks_(0),
        total_diversity_failures_(0) {

        // 공격 모드가 활성화된 경우 공격자 초기화
        if (attack_config_.enabled) {
            attack_coordinator_ = std::make_unique<AttackCoordinator>();

            if (attack_config_.attack_type == "regional") {
                regional_attacker_ = std::make_unique<RegionalMajorityAttacker>(
                    "regional_attacker_1",
                    attack_config_.beta_global,
                    attack_config_.beta_regional,
                    "MaliciousOEM",
                    100.0  // clustering radius
                );
                regional_attacker_->setEnabled(true);
                std::cout << "\n🔴 ATTACK MODE ENABLED: Regional Majority\n";
                std::cout << "   β_global = " << attack_config_.beta_global << "\n";
                std::cout << "   β_regional = " << attack_config_.beta_regional << "\n\n";
            }
        }
    }

    bool initialize() {
        std::cout << "=== Initializing Mesh-Chain + SUMO Simulation ";
        if (attack_config_.enabled) {
            std::cout << "(WITH ATTACK SCENARIOS) ";
        }
        std::cout << "===\n\n";

        // TraCI 초기화
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
            return false;
        }

        std::cout << "✓ Connected to SUMO via TraCI\n";
        std::cout << "✓ Scenario: " << config_.sumo_config_file << "\n\n";

        // 공격 로그 파일 열기
        if (attack_config_.enabled) {
            attack_log_file_.open("attack_analysis.log", std::ios::trunc);
            if (attack_log_file_.is_open()) {
                attack_log_file_ << "=== Mesh-Chain Attack Analysis Log ===\n";
                attack_log_file_ << "Attack Type: " << attack_config_.attack_type << "\n";
                attack_log_file_ << "β_global: " << attack_config_.beta_global << "\n";
                attack_log_file_ << "β_regional: " << attack_config_.beta_regional << "\n";
                attack_log_file_ << "======================================\n\n";
            }
        }

        return true;
    }

    void run() {
        std::cout << "\n=== Starting Simulation ===\n\n";

        auto start_time = std::chrono::steady_clock::now();
        size_t step_count = 0;
        const double STEP_DURATION = config_.step_length;
        const double MAX_DURATION = config_.duration_seconds;

        size_t adversary_injection_count = 0;

        while (step_count * STEP_DURATION < MAX_DURATION) {
            traci_->step();
            auto current = std::chrono::steady_clock::now();
            step_count++;

            // Update vehicles
            updateVehicles(adversary_injection_count);

            // Execute step for all vehicles
            for (auto& [vid, vehicle] : vehicles_) {
                vehicle->step(vehicles_);
            }

            // WAVE message propagation
            for (auto& [vid, vehicle] : vehicles_) {
                vehicle->processMessagePropagation(wave_stacks_);
            }

            // Attack analysis (every 10 seconds)
            if (attack_config_.enabled && step_count % 100 == 0) {
                analyzeAttackEffectiveness();
            }

            // 상태 출력 (10초마다)
            if (step_count % 100 == 0) {
                printStatus();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        std::cout << "\n=== Simulation Complete ===\n";
        printFinalStatistics();

        if (attack_config_.enabled && regional_attacker_) {
            printAttackAnalysis();
        }
    }

    void shutdown() {
        std::cout << "\n=== Shutting down simulation ===\n";

        vehicles_.clear();
        wave_stacks_.clear();

        if (traci_) {
            traci_->disconnect();
        }

        if (attack_log_file_.is_open()) {
            attack_log_file_.close();
        }

        std::cout << "✓ Shutdown complete\n";
    }

private:
    /**
     * Update vehicles (including attacker injection)
     */
    void updateVehicles(size_t& adversary_count) {
        const auto& vehicle_states = traci_->getVehicleStates();

        for (const auto& [vid, state] : vehicle_states) {
            if (vehicles_.find(vid) != vehicles_.end()) {
                continue;  // Vehicle already exists
            }

            // Create new vehicle
            IntegratedVehicle::Config veh_config;
            veh_config.vehicle_id = vid;
            veh_config.traci = traci_;

            // WAVE configuration
            veh_config.wave_config.node_id = vid;
            veh_config.wave_config.tx_power_dbm = config_.wave_tx_power_dbm;
            veh_config.wave_config.frequency_ghz = config_.wave_frequency_ghz;
            veh_config.wave_config.bandwidth_mhz = config_.wave_bandwidth_mhz;
            veh_config.wave_config.data_rate_mbps = config_.wave_data_rate_mbps;
            veh_config.wave_config.range_m = config_.wave_range_m;
            veh_config.wave_config.packet_loss_rate = config_.wave_packet_loss_rate;
            veh_config.wave_config.cam_interval_ms = config_.wave_cam_interval_ms;
            veh_config.wave_config.denm_priority = config_.wave_denm_priority;

            // ToF configuration
            veh_config.tof_config.vehicle_id = vid;
            veh_config.tof_config.sigma_tof_ns = config_.tof_sigma_ns;
            veh_config.tof_config.use_uwb = config_.tof_use_uwb;
            veh_config.sigma_tof_ns = config_.tof_sigma_ns;

            // Diversity policy
            veh_config.diversity_policy.min_H_m = config_.diversity_min_oem_entropy;
            veh_config.diversity_policy.p_max = config_.diversity_max_per_oem_ratio;
            veh_config.diversity_policy.min_d_m = config_.diversity_min_spatial_separation;
            veh_config.diversity_policy.min_MAD_t = config_.diversity_min_temporal_mad;
            veh_config.diversity_policy.min_R = config_.diversity_min_reputation;
            veh_config.diversity_policy.min_R_diff = config_.diversity_min_reputation_diff;

            // Red circle: Attacker injection logic
            bool is_adversary = false;
            if (attack_config_.enabled && regional_attacker_) {
                // Set as attacker for β_regional ratio
                double total_vehicles = vehicles_.size() + 1.0;
                double desired_adversaries = total_vehicles * attack_config_.beta_regional;

                if (adversary_count < static_cast<size_t>(desired_adversaries)) {
                    is_adversary = true;
                    adversary_count++;
                    regional_attacker_->registerAdversaryVehicle(vid);

                    // Set OEM to MaliciousOEM
                    std::cout << "🔴 Injecting adversary vehicle: " << vid
                             << " (total: " << adversary_count << ")\n";

                    if (attack_log_file_.is_open()) {
                        attack_log_file_ << "Adversary vehicle: " << vid
                                       << " at time " << (traci_->getCurrentTime())
                                       << "s\n";
                    }
                }
            }

            auto vehicle = std::make_shared<IntegratedVehicle>(veh_config);
            vehicles_[vid] = vehicle;

            // WAVE stack 생성
            auto wave = std::make_shared<WaveStack>(veh_config.wave_config, traci_);
            wave_stacks_[vid] = wave;

            std::cout << "  Created vehicle: " << vid;
            if (is_adversary) {
                std::cout << " [ADVERSARY]";
            }
            std::cout << "\n";
        }
    }

    /**
     * 공격 효과성 분석
     */
    void analyzeAttackEffectiveness() {
        if (!regional_attacker_) return;

        std::cout << "\n--- Attack Analysis ---\n";

        // 전체 차량 수
        size_t total = vehicles_.size();
        size_t adversary = regional_attacker_->getAdversaryCount();
        double actual_fraction = total > 0 ? static_cast<double>(adversary) / total : 0.0;

        std::cout << "  Total vehicles: " << total << "\n";
        std::cout << "  Adversary vehicles: " << adversary
                 << " (" << std::fixed << std::setprecision(1)
                 << (actual_fraction * 100.0) << "%)\n";
        std::cout << "  Target β_regional: " << (attack_config_.beta_regional * 100.0) << "%\n";

        // 공격 통계
        auto stats = regional_attacker_->getStatistics();
        std::cout << "  Attack attempts: " << stats.total_attempts << "\n";
        std::cout << "  Successful attacks: " << stats.successful_attacks << "\n";
        std::cout << "  Success rate: " << std::fixed << std::setprecision(1)
                 << (stats.getSuccessRate() * 100.0) << "%\n";

        if (attack_log_file_.is_open()) {
            attack_log_file_ << "[" << traci_->getCurrentTime() << "s] "
                           << "Adversary fraction: " << (actual_fraction * 100.0) << "%, "
                           << "Attacks: " << stats.total_attempts << "/"
                           << stats.successful_attacks << "\n";
        }
    }

    /**
     * 최종 공격 분석 보고서
     */
    void printAttackAnalysis() {
        std::cout << "\n╔════════════════════════════════════════════════════════╗\n";
        std::cout <<   "║       ATTACK SCENARIO ANALYSIS REPORT              ║\n";
        std::cout <<   "╚════════════════════════════════════════════════════════╝\n\n";

        if (regional_attacker_) {
            std::cout << "Attack Type: Regional Majority (T2)\n";
            std::cout << "─────────────────────────────────────\n";

            auto stats = regional_attacker_->getStatistics();
            size_t total = vehicles_.size();
            size_t adversary = regional_attacker_->getAdversaryCount();
            double actual_fraction = total > 0 ? static_cast<double>(adversary) / total : 0.0;

            std::cout << "\n📊 Attack Configuration:\n";
            std::cout << "  Target β_global: " << std::fixed << std::setprecision(1)
                     << (attack_config_.beta_global * 100.0) << "%\n";
            std::cout << "  Target β_regional: " << (attack_config_.beta_regional * 100.0) << "%\n";
            std::cout << "  Actual adversary fraction: " << (actual_fraction * 100.0) << "%\n";

            std::cout << "\n📈 Attack Results:\n";
            regional_attacker_->getStatistics().printSummary();

            std::cout << "\n🛡️ Mitigation Effectiveness:\n";
            if (stats.total_attempts > 0) {
                double mitigation_rate = 1.0 - stats.getSuccessRate();
                std::cout << "  Mitigation rate: " << std::fixed << std::setprecision(1)
                         << (mitigation_rate * 100.0) << "%\n";

                if (mitigation_rate > 0.9) {
                    std::cout << "  ✅ EXCELLENT: Diversity policy effectively prevents regional majority\n";
                } else if (mitigation_rate > 0.7) {
                    std::cout << "  ⚠️  GOOD: Most attacks mitigated, some vulnerabilities remain\n";
                } else {
                    std::cout << "  ❌ WEAK: Mitigation insufficient, policy needs strengthening\n";
                }
            } else {
                std::cout << "  No attacks attempted during simulation\n";
            }

            std::cout << "\n📝 Key Findings:\n";
            std::cout << "  • OEM diversity (Hm): " << config_.diversity_min_oem_entropy << " bits required\n";
            std::cout << "  • OEM cap (pmax): " << std::fixed << std::setprecision(0)
                     << (config_.diversity_max_per_oem_ratio * 100.0) << "% max per OEM\n";
            std::cout << "  • Spatial separation: " << config_.diversity_min_spatial_separation << "m minimum\n";
            std::cout << "  • Reputation threshold: " << config_.diversity_min_reputation << " minimum\n";
        }

        std::cout << "\n╚════════════════════════════════════════════════════════╝\n";
    }

    void printStatus() {
        std::cout << "\n[Step " << (traci_->getCurrentTime()) << "s] "
                 << "Vehicles: " << vehicles_.size();
        if (attack_config_.enabled && regional_attacker_) {
            std::cout << " (Adversary: " << regional_attacker_->getAdversaryCount() << ")";
        }
        std::cout << "\n";
    }

    void printFinalStatistics() {
        std::cout << "\n=== Final Statistics ===\n";
        std::cout << "Total vehicles: " << vehicles_.size() << "\n";

        if (attack_config_.enabled && regional_attacker_) {
            std::cout << "Adversary vehicles: " << regional_attacker_->getAdversaryCount() << "\n";
        }
    }
};

/**
 * Main Entry Point
 */
int main(int argc, char** argv) {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║   Mesh-Chain V2X Blockchain - Attack Scenario Simulation     ║
║   Purpose: Validate robustness in real SUMO environment      ║
╚═══════════════════════════════════════════════════════════════╝
)" << "\n";

    // Parse attack configuration
    AttackScenarioConfig attack_config;
    attack_config.parseCommandLine(argc, argv);

    // Load simulation configuration
    SimulationConfig config;
    // Use default configuration (config_loader.h not available)
    config.duration_seconds = 60;
    config.step_length = 0.1;
    config.num_vehicles = 50;
    config.sumo_config_file = "../sumo/highway_5km.sumo.cfg";
    config.sumo_use_gui = false;
    config.sumo_auto_start = true;

    // Command line overrides
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--duration" && i + 1 < argc) {
            config.duration_seconds = std::atoi(argv[++i]);
        } else if (arg == "--gui") {
            config.sumo_use_gui = true;
        }
    }

    // Create and run simulation
    AttackIntegratedSimulation sim(config, attack_config);

    if (!sim.initialize()) {
        std::cerr << "Failed to initialize simulation\n";
        return 1;
    }

    sim.run();
    sim.shutdown();

    return 0;
}
