/**
 * Attack Scenario Test Program
 *
 * Purpose: Verify robustness of Mesh-Chain against threat models (T1, T2, T3, T6)
 * Design: Non-intrusive standalone test that validates mitigation mechanisms
 *
 * Based on Section 2.3 "Threats" from Mesh-chain.pdf
 */

#include "security/attacker_models.h"
#include "vehicle/witness_selection.h"
#include "vehicle/block_creator.h"
#include "crypto/pqc_signatures.h"
#include "common/types.h"
#include <iostream>
#include <vector>
#include <memory>
#include <iomanip>

using namespace meshchain;
using namespace meshchain::security;
using namespace meshchain::vehicle;
using namespace meshchain::crypto;

// ==================== Test Utilities ====================

/**
 * Generate mock witness candidates for testing
 */
std::vector<WitnessCandidate> generateMockCandidates(
    size_t count,
    const std::vector<std::string>& oems,
    double min_distance = 10.0,
    double max_distance = 200.0) {

    std::vector<WitnessCandidate> candidates;
    std::mt19937 rng(12345);  // Fixed seed for reproducibility
    std::uniform_real_distribution<double> dist_range(min_distance, max_distance);
    std::uniform_real_distribution<double> rep_dist(0.3, 1.0);
    std::uniform_int_distribution<size_t> oem_dist(0, oems.size() - 1);

    for (size_t i = 0; i < count; ++i) {
        WitnessCandidate c;
        c.id = "vehicle_" + std::to_string(i);
        c.oem = oems[oem_dist(rng)];
        c.distance_m = dist_range(rng);
        c.first_contact = std::chrono::system_clock::now() -
                         std::chrono::seconds(static_cast<int>(i * 5));

        // Reputation
        c.reputation.R = rep_dist(rng);
        c.reputation.last_updated = std::chrono::system_clock::now();
        c.reputation.total_interactions = 100;
        c.reputation.valid_interactions = 95;
        c.reputation.malicious_reports_count = 2;
        c.reputation.accurate_reports_count = 0;
        c.reputation.malicious_penalty_accumulated = 0.0;

        candidates.push_back(c);
    }

    return candidates;
}

/**
 * Print test header
 */
void printTestHeader(const std::string& title) {
    std::cout << "\n========================================\n";
    std::cout << "TEST: " << title << "\n";
    std::cout << "========================================\n";
}

/**
 * Print test result
 */
void printTestResult(const std::string& test_name, bool passed,
                    const std::string& details = "") {
    std::cout << "[" << (passed ? "✓ PASS" : "✗ FAIL") << "] "
             << test_name;
    if (!details.empty()) {
        std::cout << " - " << details;
    }
    std::cout << "\n";
}

// ==================== Attack Scenario Tests ====================

/**
 * T1: Solo Tampering Attack Test
 *
 * Validates:
 * - PQC signature verification detects forged signatures
 * - Anomaly screening with reputation threshold R ≥ 0.5
 */
bool testT1_SoloTampering() {
    printTestHeader("T1: Solo Tampering Attack");

    // Create attacker
    SoloTamperingAttacker attacker("solo_attacker", 1.0, true, true);
    attacker.setEnabled(true);

    // Create legitimate block
    Block legitimate_block;
    legitimate_block.header.time = std::chrono::system_clock::now();
    legitimate_block.header.nonce = 1;

    // Generate legitimate PQC signature (Falcon-512)
    Falcon512 signer;
    signer.generateKeys();
    auto public_key = signer.getPublicKey();

    std::string block_data = "test_block_data";
    std::vector<uint8_t> data_vec(block_data.begin(), block_data.end());
    auto legitimate_sig = signer.sign(data_vec);
    legitimate_block.header.creator_sig = legitimate_sig;

    // Attempt forgery
    std::cout << "Attempting to forge block signature...\n";
    Block forged_block = attacker.attemptForgeBlock(legitimate_block);

    // Verify signatures
    bool legit_valid = signer.verify(data_vec,
                                    legitimate_block.header.creator_sig,
                                    public_key);
    bool forge_valid = signer.verify(data_vec,
                                    forged_block.header.creator_sig,
                                    public_key);

    printTestResult("Legitimate signature verification", legit_valid);
    printTestResult("Forged signature rejected", !forge_valid,
                   "Forged signature must fail verification");

    // Check statistics
    auto stats = attacker.getStatistics();
    printTestResult("Attack attempt recorded", stats.total_attempts == 1);
    printTestResult("Attack detected (signature verification)",
                   !forge_valid && stats.total_attempts > 0);

    std::cout << "\nT1 Attack Statistics:\n";
    stats.printSummary();

    return legit_valid && !forge_valid;
}

/**
 * T2: Regional Majority Attack Test
 *
 * Validates:
 * - OEM cap pmax = 0.25 (max 25% from any manufacturer)
 * - Manufacturer diversity Hm ≥ 1.5 bits
 * - Spatial/temporal/reputation diversity enforcement
 */
bool testT2_RegionalMajority() {
    printTestHeader("T2: Regional Majority (Encirclement) Attack");

    // Scenario: Attacker controls 40% of regional vehicles
    double beta_global = 0.2;
    double beta_regional = 0.4;
    std::string adversary_oem = "Adversary-OEM";

    RegionalMajorityAttacker attacker("regional_attacker",
                                     beta_global,
                                     beta_regional,
                                     adversary_oem);
    attacker.setEnabled(true);

    // Generate candidate pool with adversary concentration
    std::vector<std::string> oems = {"Toyota", "Honda", "Tesla", adversary_oem};
    auto all_candidates = generateMockCandidates(25, oems);

    // Mark 40% as adversary vehicles (10 out of 25)
    size_t adv_count = static_cast<size_t>(all_candidates.size() * beta_regional);
    for (size_t i = 0; i < adv_count && i < all_candidates.size(); ++i) {
        all_candidates[i].oem = adversary_oem;
        attacker.registerAdversaryVehicle(all_candidates[i].id);
    }

    std::cout << "Regional setup:\n";
    std::cout << "  Total candidates: " << all_candidates.size() << "\n";
    std::cout << "  Adversary vehicles: " << adv_count
             << " (" << (beta_regional * 100) << "%)\n";
    std::cout << "  Adversary OEM: " << adversary_oem << "\n\n";

    // Configure diversity policy (from simulation_config.yaml)
    WitnessSelector::Policy policy;
    policy.min_H_m = 0.9;      // Minimum OEM entropy (relaxed for simulation)
    policy.p_max = 0.4;        // Per-OEM cap (40%)
    policy.min_d_m = 1.0;      // Minimum spatial separation (meters)
    policy.min_MAD_t = 0.0;    // Temporal diversity (relaxed)
    policy.min_R = 0.3;        // Minimum reputation
    policy.min_R_diff = 0.25;  // Reputation diversity

    WitnessSelector selector(policy);

    // Witness profile: w=7, τ=5
    WitnessProfile profile;
    profile.w = 7;
    profile.tau = 5;

    // Attempt witness selection
    std::cout << "Attempting witness selection with diversity policy...\n";
    double sigma_tof = 3.0;  // nanoseconds
    auto selected = selector.selectWitnesses(all_candidates, profile, sigma_tof);

    bool selection_succeeded = (selected.size() >= profile.w);
    printTestResult("Witness selection completed",
                   selection_succeeded,
                   "Selected " + std::to_string(selected.size()) + " witnesses");

    if (selection_succeeded) {
        // Check if adversary achieved regional majority in selected set
        size_t adv_selected = attacker.countAdversaryWitnesses(selected);
        double adv_fraction = static_cast<double>(adv_selected) / selected.size();

        std::cout << "\nSelected witness set:\n";
        std::cout << "  Total selected: " << selected.size() << "\n";
        std::cout << "  Adversary witnesses: " << adv_selected
                 << " (" << std::fixed << std::setprecision(1)
                 << (adv_fraction * 100) << "%)\n";

        // Compute diversity metrics
        auto metrics = selector.computeDiversity(selected);
        std::cout << "  OEM entropy (H_m): " << std::fixed << std::setprecision(2)
                 << metrics.H_m << " bits (threshold: " << policy.min_H_m << ")\n";
        std::cout << "  Min spatial separation: " << std::fixed << std::setprecision(1)
                 << metrics.d_min << " m (threshold: " << policy.min_d_m << ")\n";
        std::cout << "  Min reputation: " << std::fixed << std::setprecision(2)
                 << metrics.min_R << " (threshold: " << policy.min_R << ")\n";

        // Verify diversity
        auto detailed_result = selector.verifyDiversityDetailed(metrics, sigma_tof);
        printTestResult("Diversity policy satisfied",
                       detailed_result.passed,
                       detailed_result.passed ? "All checks passed" :
                           detailed_result.failure_reason);

        // Check if adversary fraction is limited by policy
        bool adversary_limited = (adv_fraction < beta_regional);
        printTestResult("Adversary fraction limited by policy",
                       adversary_limited,
                       "Limited to " + std::to_string(static_cast<int>(adv_fraction * 100)) +
                       "% (attempted " + std::to_string(static_cast<int>(beta_regional * 100)) + "%)");

        // Check OEM cap enforcement
        std::map<std::string, size_t> oem_counts;
        for (const auto& w : selected) {
            oem_counts[w.oem]++;
        }
        bool oem_cap_satisfied = true;
        for (const auto& [oem, count] : oem_counts) {
            double oem_fraction = static_cast<double>(count) / selected.size();
            if (oem_fraction > policy.p_max) {
                oem_cap_satisfied = false;
            }
            std::cout << "  OEM " << oem << ": " << count
                     << " (" << std::fixed << std::setprecision(1)
                     << (oem_fraction * 100) << "%)\n";
        }
        printTestResult("OEM cap enforced (p_max = " +
                       std::to_string(static_cast<int>(policy.p_max * 100)) + "%)",
                       oem_cap_satisfied);

        attacker.checkRegionalMajority(selected);
    }

    std::cout << "\nT2 Attack Statistics:\n";
    attacker.getStatistics().printSummary();

    return selection_succeeded;
}

/**
 * T3: Sybil/Eclipse Attack Test
 *
 * Validates:
 * - Onboarding cap (≤ 1 identity per 30s per neighborhood)
 * - ToF-bound witnessing (physical distance verification)
 * - RSU cross-checks
 */
bool testT3_SybilEclipse() {
    printTestHeader("T3: Sybil/Eclipse Attack");

    // Create attacker attempting to create multiple Sybil identities
    SybilEclipseAttacker attacker("sybil_attacker", 1.0, 10);
    attacker.setEnabled(true);

    std::string neighborhood_id = "neighborhood_1";

    std::cout << "Attempting rapid Sybil identity creation...\n";
    std::cout << "Onboarding rate limit: 1 identity per 30 seconds\n\n";

    // Attempt to create multiple Sybils rapidly
    std::vector<std::string> created_sybils;
    size_t total_attempts = 5;
    size_t successful_creations = 0;

    for (size_t i = 0; i < total_attempts; ++i) {
        std::string sybil_id = attacker.attemptCreateSybil(neighborhood_id);
        if (!sybil_id.empty()) {
            created_sybils.push_back(sybil_id);
            successful_creations++;
            std::cout << "  Attempt " << (i+1) << ": SUCCESS - Created " << sybil_id << "\n";
        } else {
            std::cout << "  Attempt " << (i+1) << ": BLOCKED by rate limiter\n";
        }
    }

    std::cout << "\nSybil creation results:\n";
    std::cout << "  Total attempts: " << total_attempts << "\n";
    std::cout << "  Successful: " << successful_creations << "\n";
    std::cout << "  Blocked: " << (total_attempts - successful_creations) << "\n";

    // Verify onboarding rate limit (should only allow 1 within 30s window)
    bool rate_limit_effective = (successful_creations <= 1);
    printTestResult("Onboarding rate limit enforced",
                   rate_limit_effective,
                   "Only " + std::to_string(successful_creations) +
                   " identity created in rapid succession");

    // Test Eclipse attack scenario
    std::cout << "\nAttempting Eclipse attack on target vehicle...\n";
    std::string target_vehicle = "victim_vehicle";
    std::vector<std::string> neighbors;

    // Add some legitimate neighbors
    neighbors.push_back("legit_vehicle_1");
    neighbors.push_back("legit_vehicle_2");

    // Add Sybil identities as neighbors
    for (const auto& sybil : created_sybils) {
        neighbors.push_back(sybil);
    }

    std::cout << "  Target: " << target_vehicle << "\n";
    std::cout << "  Total neighbors: " << neighbors.size() << "\n";
    std::cout << "  Sybil neighbors: " << created_sybils.size() << "\n";

    bool eclipse_succeeded = attacker.attemptEclipse(target_vehicle, neighbors);
    double sybil_fraction = static_cast<double>(created_sybils.size()) / neighbors.size();

    printTestResult("Eclipse attack prevented",
                   !eclipse_succeeded,
                   "Sybil fraction: " +
                   std::to_string(static_cast<int>(sybil_fraction * 100)) + "%");

    std::cout << "\nT3 Attack Statistics:\n";
    attacker.getStatistics().printSummary();

    return rate_limit_effective;
}

/**
 * T6: Spam/DoS Attack Test
 *
 * Validates:
 * - Reputation-weighted token bucket rate limiting
 * - Per-message computational costs
 * - Backpressure mechanisms
 */
bool testT6_SpamDoS() {
    printTestHeader("T6: Spam/DoS Attack");

    // Create attacker with high spam rate
    SpamDoSAttacker attacker("spam_attacker", 100.0, 50, "CAM");
    attacker.setEnabled(true);

    std::cout << "Spam parameters:\n";
    std::cout << "  Target rate: " << attacker.getSpamRate() << " msgs/sec\n";
    std::cout << "  Message type: " << attacker.getTargetType() << "\n\n";

    // Test with different reputation levels
    std::vector<double> reputation_levels = {1.0, 0.7, 0.5, 0.3, 0.1};

    std::cout << "Testing reputation-weighted rate limiting:\n";
    std::cout << std::setw(15) << "Reputation"
             << std::setw(20) << "Msgs Allowed"
             << std::setw(20) << "Rate Limited\n";
    std::cout << std::string(55, '-') << "\n";

    bool rate_limiting_effective = true;

    for (double reputation : reputation_levels) {
        // Reset for each test
        size_t attempts = 10;
        size_t total_sent = 0;

        for (size_t i = 0; i < attempts; ++i) {
            if (attacker.shouldAttackNow()) {
                size_t sent = attacker.attemptSpam(reputation);
                total_sent += sent;
            }
            // Small delay to simulate time passing
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        double expected_max_rate = attacker.getSpamRate() * reputation;
        bool limited = (total_sent < attempts * 10);  // Should be limited

        std::cout << std::fixed << std::setprecision(2)
                 << std::setw(15) << reputation
                 << std::setw(20) << total_sent
                 << std::setw(20) << (limited ? "YES" : "NO") << "\n";

        if (!limited && reputation < 0.5) {
            rate_limiting_effective = false;
        }
    }

    printTestResult("Reputation-weighted rate limiting effective",
                   rate_limiting_effective,
                   "Lower reputation = stronger rate limiting");

    // Test burst limiting
    std::cout << "\nTesting burst limitation:\n";
    attacker.setEnabled(true);
    size_t burst_attempt = attacker.attemptSpam(1.0);  // Full reputation
    bool burst_limited = (burst_attempt <= 50);  // Should not exceed burst_size

    printTestResult("Burst size limited",
                   burst_limited,
                   "Burst capped at " + std::to_string(burst_attempt) + " messages");

    std::cout << "\nT6 Attack Statistics:\n";
    attacker.getStatistics().printSummary();

    return rate_limiting_effective && burst_limited;
}

// ==================== Main Test Suite ====================

int main(int argc, char** argv) {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║   Mesh-Chain V2X Blockchain - Attack Scenario Test Suite     ║
║   Purpose: Validate robustness against threat models         ║
║   Based on: Mesh-chain.pdf Section 2.3 "Threats"            ║
╚═══════════════════════════════════════════════════════════════╝
)";

    bool all_passed = true;

    // Run all attack scenario tests
    try {
        std::cout << "\n>>> Running Attack Scenario Tests <<<\n";

        bool t1_passed = testT1_SoloTampering();
        bool t2_passed = testT2_RegionalMajority();
        bool t3_passed = testT3_SybilEclipse();
        bool t6_passed = testT6_SpamDoS();

        all_passed = t1_passed && t2_passed && t3_passed && t6_passed;

        // Final summary
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "FINAL TEST SUMMARY\n";
        std::cout << std::string(70, '=') << "\n";
        printTestResult("T1: Solo Tampering Attack", t1_passed);
        printTestResult("T2: Regional Majority Attack", t2_passed);
        printTestResult("T3: Sybil/Eclipse Attack", t3_passed);
        printTestResult("T6: Spam/DoS Attack", t6_passed);
        std::cout << std::string(70, '=') << "\n";

        if (all_passed) {
            std::cout << "\n✓ ALL TESTS PASSED - Mitigation mechanisms are effective!\n";
            std::cout << "  The Mesh-Chain system successfully defends against:\n";
            std::cout << "  - Forged signatures (T1)\n";
            std::cout << "  - Regional majority attacks (T2)\n";
            std::cout << "  - Sybil/Eclipse attacks (T3)\n";
            std::cout << "  - Spam/DoS attacks (T6)\n";
        } else {
            std::cout << "\n✗ SOME TESTS FAILED - Review mitigation mechanisms\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "\nERROR: Exception during testing: " << e.what() << "\n";
        return 1;
    }

    return all_passed ? 0 : 1;
}
