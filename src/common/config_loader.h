#ifndef MESHCHAIN_CONFIG_LOADER_H
#define MESHCHAIN_CONFIG_LOADER_H

#include "types.h"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>

namespace meshchain {
namespace config {

/**
 * YAML Configuration File Parser
 * Lightweight implementation without yaml-cpp (minimize external dependencies)
 *
 * Supported formats:
 * - Simple key: value
 * - Nested sections (section:)
 * - Lists (- item)
 * - Comments (# comment)
 */
class SimpleYAMLParser {
private:
    std::map<std::string, std::string> values_;
    std::vector<std::string> section_stack_;  // Stack to track nested sections

public:
    bool parseFile(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            std::cerr << "[ConfigLoader] Failed to open: " << filepath << "\n";
            return false;
        }

        std::string line;
        int line_num = 0;
        int prev_indent = 0;

        while (std::getline(file, line)) {
            line_num++;
            parseLine(line, prev_indent);
        }

        return true;
    }

    std::optional<std::string> getString(const std::string& key) const {
        auto it = values_.find(key);
        if (it != values_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::optional<int> getInt(const std::string& key) const {
        auto str = getString(key);
        if (str.has_value()) {
            try {
                return std::stoi(*str);
            } catch (...) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<double> getDouble(const std::string& key) const {
        auto str = getString(key);
        if (str.has_value()) {
            try {
                return std::stod(*str);
            } catch (...) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<bool> getBool(const std::string& key) const {
        auto str = getString(key);
        if (str.has_value()) {
            std::string lower = *str;
            for (auto& c : lower) c = std::tolower(c);
            if (lower == "true" || lower == "yes" || lower == "1") return true;
            if (lower == "false" || lower == "no" || lower == "0") return false;
        }
        return std::nullopt;
    }

    void dump() const {
        std::cout << "[ConfigLoader] Loaded values:\n";
        for (const auto& [key, value] : values_) {
            std::cout << "  " << key << " = " << value << "\n";
        }
    }

private:
    void parseLine(std::string line, int& prev_indent) {
        // Calculate indentation before trimming
        int indent = 0;
        while (indent < line.size() && std::isspace(line[indent])) {
            indent++;
        }

        // Trim whitespace
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') return;

        // Check if it's a section header (ends with :)
        if (line.back() == ':' && line.find(':') == line.size() - 1) {
            std::string section_name = line.substr(0, line.size() - 1);

            // Handle nested sections based on indentation
            if (indent <= prev_indent && !section_stack_.empty()) {
                // Pop sections until we match the indent level
                while (!section_stack_.empty() && indent <= prev_indent) {
                    section_stack_.pop_back();
                    prev_indent -= 2;  // Assume 2-space indentation
                }
            }

            section_stack_.push_back(section_name);
            prev_indent = indent;
            return;
        }

        // Skip list items (- item) for now
        if (line[0] == '-') return;

        // Parse key: value
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = trim(line.substr(0, colon_pos));
            std::string value = trim(line.substr(colon_pos + 1));

            // Skip if value is empty (it's a section)
            if (value.empty()) return;

            // Remove quotes from value
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }

            // Build full key with all sections in stack
            std::string full_key = key;
            if (!section_stack_.empty()) {
                std::string section_path;
                for (size_t i = 0; i < section_stack_.size(); ++i) {
                    if (i > 0) section_path += ".";
                    section_path += section_stack_[i];
                }
                full_key = section_path + "." + key;
            }

            values_[full_key] = value;
        }
    }

    std::string trim(const std::string& str) {
        size_t start = 0;
        while (start < str.size() && std::isspace(str[start])) start++;

        size_t end = str.size();
        while (end > start && std::isspace(str[end - 1])) end--;

        return str.substr(start, end - start);
    }
};

/**
 * Mesh-Chain Simulation Configuration
 */
struct SimulationConfig {
    // Simulation basic settings
    double duration_seconds = 60.0;
    double step_length = 0.1;
    std::string output_directory = "results";
    std::string log_level = "INFO";

    // Vehicle settings
    int vehicle_count = 20;
    double vehicle_spawn_interval = 1.0;
    double vehicle_communication_range = 300.0;
    // Block creation: Create immediately upon V2X message reception

    // RSU settings
    int rsu_count = 3;
    double rsu_l1_anchor_period = 60.0;
    double rsu_l2_anchor_period = 180.0;
    double rsu_l3_anchor_period = 600.0;

    // SUMO settings
    bool sumo_enabled = true;
    std::string sumo_config_file = "../sumo/highway.sumo.cfg";
    bool sumo_use_gui = true;
    std::string sumo_host = "localhost";
    int sumo_port = 8813;
    bool sumo_auto_start = true;

    // WAVE settings
    double wave_tx_power_dbm = 20.0;
    double wave_frequency_ghz = 5.9;
    double wave_bandwidth_mhz = 10.0;
    double wave_data_rate_mbps = 6.0;
    double wave_range_m = 300.0;
    double wave_packet_loss_rate = 0.2;
    int wave_cam_interval_ms = 100;
    int wave_denm_priority = 6;

    // ToF settings
    double tof_sigma_ns = 3.0;
    double tof_max_tolerance_ns = 10.0;
    bool tof_use_uwb = true;
    double tof_channel_noise_db = 20.0;

    // Witness selection settings
    int witness_default_profile = 1; // 0=3/2, 1=5/3, 2=7/5

    // Diversity policy
    double diversity_min_oem_entropy = 1.2;
    double diversity_max_per_oem_ratio = 0.25;
    double diversity_min_spatial_separation = 0.5;  // Changed from 10.0 for testing
    double diversity_min_temporal_mad = 1.0;
    double diversity_min_reputation = 0.3;
    double diversity_min_reputation_diff = 0.0;

    // Cryptography settings
    std::string pqc_vehicle_signature = "FALCON-512";
    std::string pqc_rsu_signature = "DILITHIUM-3";
    std::string pqc_kem = "ML-KEM-768";
    std::string aead_algorithm = "XChaCha20-Poly1305";
    std::string aead_kdf = "HKDF-SHA3-256";

    // Off-chain storage
    int shamir_threshold = 3;
    int shamir_total_shares = 5;

    // libp2p settings
    bool libp2p_enabled = true;
    bool libp2p_enable_dht = true;
    bool libp2p_enable_gossipsub = true;
    bool libp2p_enable_bitswap = true;

    // Performance targets
    double performance_local_finality_target_ms = 100.0;
    int performance_max_block_size_kb = 10;
    int performance_max_signature_bandwidth_kbps = 50;

    // Evaluation settings
    bool evaluation_collect_metrics = true;
    int evaluation_metrics_interval = 10;
    bool evaluation_verbose_logging = false;
    bool evaluation_realtime_dashboard = true;

    // Advanced settings
    bool advanced_enable_multithreading = true;
    int advanced_worker_threads = 0;
    int advanced_memory_limit_mb = 2048;

    /**
     * Load configuration from YAML file
     */
    bool loadFromFile(const std::string& filepath) {
        SimpleYAMLParser parser;
        if (!parser.parseFile(filepath)) {
            return false;
        }

        std::cout << "[ConfigLoader] Loading configuration from: " << filepath << "\n";

        // Simulation settings
        if (auto v = parser.getDouble("simulation.duration_seconds")) duration_seconds = *v;
        if (auto v = parser.getDouble("simulation.step_length")) step_length = *v;
        if (auto v = parser.getString("simulation.output_directory")) output_directory = *v;
        if (auto v = parser.getString("simulation.log_level")) log_level = *v;

        // Vehicle settings
        if (auto v = parser.getInt("vehicles.count")) vehicle_count = *v;
        if (auto v = parser.getDouble("vehicles.spawn_interval")) vehicle_spawn_interval = *v;
        if (auto v = parser.getDouble("vehicles.communication_range")) vehicle_communication_range = *v;

        // RSU settings
        if (auto v = parser.getInt("rsu.count")) rsu_count = *v;
        if (auto v = parser.getDouble("rsu.l1_anchor_period")) rsu_l1_anchor_period = *v;
        if (auto v = parser.getDouble("rsu.l2_anchor_period")) rsu_l2_anchor_period = *v;
        if (auto v = parser.getDouble("rsu.l3_anchor_period")) rsu_l3_anchor_period = *v;

        // SUMO settings
        if (auto v = parser.getBool("sumo.enabled")) sumo_enabled = *v;
        if (auto v = parser.getString("sumo.config_file")) sumo_config_file = *v;
        if (auto v = parser.getBool("sumo.use_gui")) sumo_use_gui = *v;
        if (auto v = parser.getString("sumo.host")) sumo_host = *v;
        if (auto v = parser.getInt("sumo.port")) sumo_port = *v;
        if (auto v = parser.getBool("sumo.auto_start")) sumo_auto_start = *v;

        // WAVE settings
        if (auto v = parser.getDouble("wave.tx_power_dbm")) wave_tx_power_dbm = *v;
        if (auto v = parser.getDouble("wave.frequency_ghz")) wave_frequency_ghz = *v;
        if (auto v = parser.getDouble("wave.bandwidth_mhz")) wave_bandwidth_mhz = *v;
        if (auto v = parser.getDouble("wave.data_rate_mbps")) wave_data_rate_mbps = *v;
        if (auto v = parser.getDouble("wave.range_m")) wave_range_m = *v;
        if (auto v = parser.getDouble("wave.packet_loss_rate")) wave_packet_loss_rate = *v;
        if (auto v = parser.getInt("wave.cam_interval_ms")) wave_cam_interval_ms = *v;
        if (auto v = parser.getInt("wave.denm_priority")) wave_denm_priority = *v;

        // ToF settings
        if (auto v = parser.getDouble("tof.sigma_tof_ns")) tof_sigma_ns = *v;
        if (auto v = parser.getDouble("tof.max_tolerance_ns")) tof_max_tolerance_ns = *v;
        if (auto v = parser.getBool("tof.use_uwb")) tof_use_uwb = *v;
        if (auto v = parser.getDouble("tof.channel_noise_db")) tof_channel_noise_db = *v;

        // Witness settings
        if (auto v = parser.getInt("witness.default_profile")) witness_default_profile = *v;

        // Diversity policy
        if (auto v = parser.getDouble("witness.diversity.min_oem_entropy")) diversity_min_oem_entropy = *v;
        if (auto v = parser.getDouble("witness.diversity.max_per_oem_ratio")) diversity_max_per_oem_ratio = *v;
        if (auto v = parser.getDouble("witness.diversity.min_spatial_separation")) diversity_min_spatial_separation = *v;
        if (auto v = parser.getDouble("witness.diversity.min_temporal_mad")) diversity_min_temporal_mad = *v;
        if (auto v = parser.getDouble("witness.diversity.min_reputation")) diversity_min_reputation = *v;
        if (auto v = parser.getDouble("witness.diversity.min_reputation_diff")) diversity_min_reputation_diff = *v;

        // Cryptography settings
        if (auto v = parser.getString("crypto.pqc.vehicle_signature")) pqc_vehicle_signature = *v;
        if (auto v = parser.getString("crypto.pqc.rsu_signature")) pqc_rsu_signature = *v;
        if (auto v = parser.getString("crypto.pqc.kem")) pqc_kem = *v;
        if (auto v = parser.getString("crypto.aead.algorithm")) aead_algorithm = *v;
        if (auto v = parser.getString("crypto.aead.kdf")) aead_kdf = *v;

        // Off-chain storage
        if (auto v = parser.getInt("offchain.shamir.threshold")) shamir_threshold = *v;
        if (auto v = parser.getInt("offchain.shamir.total_shares")) shamir_total_shares = *v;

        // libp2p
        if (auto v = parser.getBool("libp2p.enabled")) libp2p_enabled = *v;
        if (auto v = parser.getBool("libp2p.enable_dht")) libp2p_enable_dht = *v;
        if (auto v = parser.getBool("libp2p.enable_gossipsub")) libp2p_enable_gossipsub = *v;
        if (auto v = parser.getBool("libp2p.enable_bitswap")) libp2p_enable_bitswap = *v;

        // Performance
        if (auto v = parser.getDouble("performance.local_finality_target_ms")) performance_local_finality_target_ms = *v;
        if (auto v = parser.getInt("performance.max_block_size_kb")) performance_max_block_size_kb = *v;
        if (auto v = parser.getInt("performance.max_signature_bandwidth_kbps")) performance_max_signature_bandwidth_kbps = *v;

        // Evaluation
        if (auto v = parser.getBool("evaluation.collect_metrics")) evaluation_collect_metrics = *v;
        if (auto v = parser.getInt("evaluation.metrics_interval")) evaluation_metrics_interval = *v;
        if (auto v = parser.getBool("evaluation.verbose_logging")) evaluation_verbose_logging = *v;
        if (auto v = parser.getBool("evaluation.realtime_dashboard")) evaluation_realtime_dashboard = *v;

        // Advanced
        if (auto v = parser.getBool("advanced.enable_multithreading")) advanced_enable_multithreading = *v;
        if (auto v = parser.getInt("advanced.worker_threads")) advanced_worker_threads = *v;
        if (auto v = parser.getInt("advanced.memory_limit_mb")) advanced_memory_limit_mb = *v;

        std::cout << "[ConfigLoader] ✓ Configuration loaded successfully\n";
        return true;
    }

    /**
     * Override configuration with CLI arguments
     */
    void applyCommandLineOverrides(int argc, char** argv) {
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];

            if (arg == "--vehicles" && i + 1 < argc) {
                vehicle_count = std::atoi(argv[++i]);
                std::cout << "[ConfigLoader] Override: vehicles = " << vehicle_count << "\n";
            }
            else if (arg == "--rsus" && i + 1 < argc) {
                rsu_count = std::atoi(argv[++i]);
                std::cout << "[ConfigLoader] Override: rsus = " << rsu_count << "\n";
            }
            else if (arg == "--duration" && i + 1 < argc) {
                duration_seconds = std::atof(argv[++i]);
                std::cout << "[ConfigLoader] Override: duration = " << duration_seconds << "s\n";
            }
            else if (arg == "--gui") {
                sumo_use_gui = true;
                std::cout << "[ConfigLoader] Override: SUMO GUI enabled\n";
            }
            else if (arg == "--no-gui") {
                sumo_use_gui = false;
                std::cout << "[ConfigLoader] Override: SUMO GUI disabled\n";
            }
            else if (arg == "--witnesses" && i + 1 < argc) {
                int w = std::atoi(argv[++i]);
                if (w == 3) witness_default_profile = 0;
                else if (w == 5) witness_default_profile = 1;
                else if (w == 7) witness_default_profile = 2;
                std::cout << "[ConfigLoader] Override: witness profile = " << witness_default_profile << " (w=" << w << ")\n";
            }
            else if (arg == "--range" && i + 1 < argc) {
                vehicle_communication_range = std::atof(argv[++i]);
                wave_range_m = vehicle_communication_range;
                std::cout << "[ConfigLoader] Override: communication range = " << vehicle_communication_range << "m\n";
            }
            else if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                exit(0);
            }
        }
    }

    /**
     * Print usage information
     */
    void printUsage(const char* program_name) const {
        std::cout << "\nUsage: " << program_name << " [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --config <file>      YAML config file path (default: config/simulation_config.yaml)\n";
        std::cout << "  --vehicles <count>   Number of vehicles (default: 20)\n";
        std::cout << "  --rsus <count>       Number of RSUs (default: 3)\n";
        std::cout << "  --duration <sec>     Simulation duration in seconds (default: 60.0)\n";
        std::cout << "  --witnesses <3|5|7>  Witness count profile (default: 5)\n";
        std::cout << "  --range <meters>     Communication range (default: 300.0)\n";
        std::cout << "  --gui                Use SUMO GUI\n";
        std::cout << "  --no-gui             Disable SUMO GUI\n";
        std::cout << "  --help, -h           Show this help message\n\n";
        std::cout << "Examples:\n";
        std::cout << "  " << program_name << " --vehicles 50 --duration 120\n";
        std::cout << "  " << program_name << " --rsus 5 --witnesses 7 --gui\n";
        std::cout << "  " << program_name << " --config my_config.yaml --vehicles 30\n\n";
    }

    /**
     * Print configuration summary
     */
    void printSummary() const {
        std::cout << "\n=== Mesh-Chain Simulation Configuration ===\n";
        std::cout << "Simulation time: " << duration_seconds << "s\n";
        std::cout << "Vehicle count: " << vehicle_count << "\n";
        std::cout << "RSU count: " << rsu_count << "\n";
        std::cout << "Communication range: " << vehicle_communication_range << "m\n";
        std::cout << "Witness profile: " << witness_default_profile << " (";
        if (witness_default_profile == 0) std::cout << "w=3, τ=2";
        else if (witness_default_profile == 1) std::cout << "w=5, τ=3";
        else std::cout << "w=7, τ=5";
        std::cout << ")\n";
        std::cout << "SUMO GUI: " << (sumo_use_gui ? "Enabled" : "Disabled") << "\n";
        std::cout << "ToF std deviation: " << tof_sigma_ns << "ns\n";
        std::cout << "Target latency: " << performance_local_finality_target_ms << "ms\n";
        std::cout << "==========================================\n\n";
    }
};

} // namespace config
} // namespace meshchain

#endif // MESHCHAIN_CONFIG_LOADER_H
