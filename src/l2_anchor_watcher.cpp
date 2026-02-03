/**
 * L2 Anchor Watcher
 *
 * Purpose: Collect L1 anchors from multiple simulations (integrated, rural) and create L2 anchors
 *
 * Features:
 * 1. Monitor /tmp/meshchain_l1 directory
 * 2. Parse L1 anchor JSON files
 * 3. Bundle L1 Merkle Roots from multiple RSUs to create L2 Merkle Tree
 * 4. Generate and output L2 anchor blocks
 *
 * Usage:
 *   ./l2_anchor_watcher --period 120 --threshold 5
 *
 * Parameters:
 *   --period <sec>     L2 creation period (default: 120 seconds)
 *   --threshold <n>    Minimum L1 anchor count (default: 3)
 *   --watch-dir <path> L1 anchor directory (default: /tmp/meshchain_l1)
 *   --output-dir <path> L2 anchor output directory (default: /tmp/meshchain_l2)
 */

#include "common/types.h"
#include "common/merkle_tree.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <thread>
#include <iomanip>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <algorithm>

using namespace meshchain;

/**
 * L1 Anchor Information
 */
struct L1AnchorInfo {
    std::string simulation_id;  // "integrated" or "rural"
    std::string rsu_id;
    uint64_t sequence;
    uint64_t timestamp_ms;
    std::string merkle_root;
    size_t block_count;

    // Cryptographic proofs
    std::string prev_anchor_hash;  // Chain verification
    std::string rsu_signature;     // Dilithium signature (hex)
    size_t signature_size;
    bool has_zkp_proof;
    std::string zkp_proof;         // STARK proof (hex)
    size_t zkp_proof_size;

    std::string filename;  // Original file name
};

/**
 * L2 Anchor Block
 */
struct L2AnchorBlock {
    uint64_t sequence;
    uint64_t timestamp_ms;
    std::vector<L1AnchorInfo> l1_sources;
    Hash256 l2_merkle_root;
    size_t total_l1_count;
    size_t total_blocks;
};

/**
 * Simple JSON parser (simple implementation)
 */
std::string extractJsonString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\": \"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos += search.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";

    return json.substr(pos, end - pos);
}

uint64_t extractJsonNumber(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\": ";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return 0;

    pos += search.length();
    size_t end = json.find_first_of(",\n}", pos);
    if (end == std::string::npos) return 0;

    std::string num_str = json.substr(pos, end - pos);
    try {
        return std::stoull(num_str);
    } catch (...) {
        return 0;
    }
}

/**
 * Parse L1 anchor JSON file
 */
bool parseL1Anchor(const std::string& filepath, L1AnchorInfo& info) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    std::string json((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();

    info.simulation_id = extractJsonString(json, "simulation_id");
    info.rsu_id = extractJsonString(json, "rsu_id");
    info.merkle_root = extractJsonString(json, "merkle_root");
    info.sequence = extractJsonNumber(json, "sequence");
    info.timestamp_ms = extractJsonNumber(json, "timestamp_ms");
    info.block_count = extractJsonNumber(json, "block_count");

    // Cryptographic proofs
    info.prev_anchor_hash = extractJsonString(json, "prev_anchor_hash");
    info.rsu_signature = extractJsonString(json, "rsu_signature");
    info.signature_size = extractJsonNumber(json, "signature_size");

    // ZKP/STARK proof
    std::string has_zkp = extractJsonString(json, "has_zkp_proof");
    info.has_zkp_proof = (has_zkp == "true");

    if (info.has_zkp_proof) {
        info.zkp_proof = extractJsonString(json, "zkp_proof");
        info.zkp_proof_size = extractJsonNumber(json, "zkp_proof_size");
    } else {
        info.zkp_proof = "";
        info.zkp_proof_size = 0;
    }

    info.filename = filepath;

    return !info.simulation_id.empty() && !info.rsu_id.empty();
}

/**
 * Scan directory and collect L1 anchors
 */
std::vector<L1AnchorInfo> scanL1Anchors(const std::string& watch_dir,
                                        std::set<std::string>& processed_files) {
    std::vector<L1AnchorInfo> new_anchors;

    DIR* dir = opendir(watch_dir.c_str());
    if (!dir) {
        return new_anchors;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;

        // Process only .json files
        if (filename.length() < 5 || filename.substr(filename.length() - 5) != ".json") {
            continue;
        }

        // Skip already processed files
        if (processed_files.find(filename) != processed_files.end()) {
            continue;
        }

        std::string filepath = watch_dir + "/" + filename;
        L1AnchorInfo info;

        if (parseL1Anchor(filepath, info)) {
            new_anchors.push_back(info);
            processed_files.insert(filename);
        }
    }

    closedir(dir);
    return new_anchors;
}

/**
 * Create L2 anchor
 */
L2AnchorBlock createL2Anchor(const std::vector<L1AnchorInfo>& l1_anchors, uint64_t l2_sequence) {
    L2AnchorBlock l2;
    l2.sequence = l2_sequence;

    // Current time
    auto now = std::chrono::system_clock::now();
    l2.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    l2.l1_sources = l1_anchors;
    l2.total_l1_count = l1_anchors.size();
    l2.total_blocks = 0;

    // Bundle L1 Merkle Roots to create L2 Merkle Tree
    std::vector<std::string> l1_roots;
    for (const auto& l1 : l1_anchors) {
        l1_roots.push_back(l1.merkle_root);
        l2.total_blocks += l1.block_count;
    }

    // Create L2 Merkle Tree
    auto merkle_tree = MerkleTree::build(l1_roots);
    l2.l2_merkle_root = merkle_tree.getRoot();

    return l2;
}

/**
 * Save L2 anchor to JSON file
 */
void saveL2Anchor(const L2AnchorBlock& l2, const std::string& output_dir) {
    // Create directory if not exists
    mkdir(output_dir.c_str(), 0755);

    // Generate filename
    std::ostringstream filename;
    filename << output_dir << "/l2_anchor_"
             << std::setw(6) << std::setfill('0') << l2.sequence
             << ".json";

    std::ofstream file(filename.str());
    if (!file.is_open()) {
        std::cerr << "⚠️  Failed to write L2 anchor: " << filename.str() << "\n";
        return;
    }

    // Write JSON
    file << "{\n";
    file << "  \"level\": \"L2\",\n";
    file << "  \"sequence\": " << l2.sequence << ",\n";
    file << "  \"timestamp_ms\": " << l2.timestamp_ms << ",\n";
    file << "  \"l2_merkle_root\": \"";

    // Convert Hash256 to hex
    for (uint8_t byte : l2.l2_merkle_root) {
        file << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    file << std::dec << "\",\n";

    file << "  \"total_l1_anchors\": " << l2.total_l1_count << ",\n";
    file << "  \"total_blocks\": " << l2.total_blocks << ",\n";
    file << "  \"l1_sources\": [\n";

    for (size_t i = 0; i < l2.l1_sources.size(); i++) {
        const auto& l1 = l2.l1_sources[i];
        file << "    {\n";
        file << "      \"simulation\": \"" << l1.simulation_id << "\",\n";
        file << "      \"rsu\": \"" << l1.rsu_id << "\",\n";
        file << "      \"sequence\": " << l1.sequence << ",\n";
        file << "      \"merkle_root\": \"" << l1.merkle_root << "\",\n";
        file << "      \"block_count\": " << l1.block_count << "\n";
        file << "    }";
        if (i < l2.l1_sources.size() - 1) {
            file << ",";
        }
        file << "\n";
    }

    file << "  ]\n";
    file << "}\n";

    file.close();

    std::cout << "💾 L2 anchor saved: " << filename.str() << "\n";
}

/**
 * Print L2 anchor statistics
 */
void printL2Statistics(const L2AnchorBlock& l2) {
    std::cout << "\n========================================\n";
    std::cout << "⚓ L2 Anchor #" << l2.sequence << " Created\n";
    std::cout << "========================================\n";
    std::cout << "Timestamp: " << l2.timestamp_ms << " ms\n";
    std::cout << "L1 Anchors: " << l2.total_l1_count << "\n";
    std::cout << "Total Blocks: " << l2.total_blocks << "\n";
    std::cout << "L2 Merkle Root: ";

    // Print first 16 bytes
    for (size_t i = 0; i < 16 && i < l2.l2_merkle_root.size(); i++) {
        printf("%02x", l2.l2_merkle_root[i]);
    }
    std::cout << "...\n\n";

    std::cout << "L1 Sources:\n";
    std::map<std::string, int> sim_count;
    for (const auto& l1 : l2.l1_sources) {
        sim_count[l1.simulation_id]++;
        std::cout << "  - " << l1.simulation_id << "/" << l1.rsu_id
                  << " (seq=" << l1.sequence << ", blocks=" << l1.block_count << ")\n";
        std::cout << "    └─ Dilithium sig: " << l1.signature_size << " bytes";
        if (l1.has_zkp_proof) {
            std::cout << ", STARK proof: " << l1.zkp_proof_size << " bytes";
        }
        std::cout << "\n";
    }

    std::cout << "\nBy Simulation:\n";
    for (const auto& [sim, count] : sim_count) {
        std::cout << "  - " << sim << ": " << count << " L1 anchors\n";
    }
    std::cout << "========================================\n\n";
}

/**
 * Main function
 */
int main(int argc, char** argv) {
    // Default configuration
    int period_sec = 120;
    int threshold = 3;
    std::string watch_dir = "/tmp/meshchain_l1";
    std::string output_dir = "/tmp/meshchain_l2";

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--period" && i + 1 < argc) {
            period_sec = std::atoi(argv[++i]);
        } else if (arg == "--threshold" && i + 1 < argc) {
            threshold = std::atoi(argv[++i]);
        } else if (arg == "--watch-dir" && i + 1 < argc) {
            watch_dir = argv[++i];
        } else if (arg == "--output-dir" && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --period <sec>     L2 creation period (default: 120)\n";
            std::cout << "  --threshold <n>    Minimum L1 anchors (default: 3)\n";
            std::cout << "  --watch-dir <path> L1 anchor directory (default: /tmp/meshchain_l1)\n";
            std::cout << "  --output-dir <path> L2 output directory (default: /tmp/meshchain_l2)\n";
            return 0;
        }
    }

    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════╗\n";
    std::cout << "║  L2 Anchor Watcher - Multi-Simulation Aggregator  ║\n";
    std::cout << "╚════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    std::cout << "Configuration:\n";
    std::cout << "  - L2 Period: " << period_sec << " seconds\n";
    std::cout << "  - L1 Threshold: " << threshold << " anchors\n";
    std::cout << "  - Watch Directory: " << watch_dir << "\n";
    std::cout << "  - Output Directory: " << output_dir << "\n";
    std::cout << "\n";

    // Create directories
    mkdir(watch_dir.c_str(), 0755);
    mkdir(output_dir.c_str(), 0755);

    // State variables
    std::set<std::string> processed_files;
    std::vector<L1AnchorInfo> pending_l1_anchors;
    uint64_t l2_sequence = 0;
    auto last_l2_time = std::chrono::steady_clock::now();

    std::cout << "🔍 Watching for L1 anchors...\n\n";

    // Main loop
    while (true) {
        // Scan L1 anchors
        auto new_anchors = scanL1Anchors(watch_dir, processed_files);

        if (!new_anchors.empty()) {
            std::cout << "📥 Found " << new_anchors.size() << " new L1 anchor(s)\n";
            for (const auto& anchor : new_anchors) {
                std::cout << "   - " << anchor.simulation_id << "/" << anchor.rsu_id
                          << " seq=" << anchor.sequence
                          << " blocks=" << anchor.block_count << "\n";
                pending_l1_anchors.push_back(anchor);
            }
        }

        // Check L2 creation conditions
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_l2_time).count();

        bool should_create_l2 = false;
        std::string reason;

        if (pending_l1_anchors.size() >= static_cast<size_t>(threshold)) {
            should_create_l2 = true;
            reason = "threshold reached (" + std::to_string(pending_l1_anchors.size()) + " >= " + std::to_string(threshold) + ")";
        } else if (elapsed >= period_sec && !pending_l1_anchors.empty()) {
            should_create_l2 = true;
            reason = "period elapsed (" + std::to_string(elapsed) + "s >= " + std::to_string(period_sec) + "s)";
        }

        if (should_create_l2) {
            std::cout << "\n🔨 Creating L2 anchor (" << reason << ")...\n";

            auto l2 = createL2Anchor(pending_l1_anchors, l2_sequence++);
            printL2Statistics(l2);
            saveL2Anchor(l2, output_dir);

            // Reset
            pending_l1_anchors.clear();
            last_l2_time = now;
        }

        // Wait 1 second
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
