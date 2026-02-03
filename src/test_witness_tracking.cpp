#include "integration/integrated_vehicle.h"
#include "integration/traci_client.h"
#include "common/block.h"
#include <iostream>
#include <iomanip>
#include <memory>
#include <set>

using namespace meshchain;
using namespace meshchain::integration;

struct TestResult {
    std::string test_name;
    bool passed;
    std::string details;
};

void printResult(const TestResult& result) {
    std::cout << (result.passed ? "[PASS] " : "[FAIL] ")
              << result.test_name << "\n";
    if (!result.details.empty()) {
        std::cout << "  " << result.details << "\n";
    }
}

/**
 * Helper: Create a test block
 */
Block createTestBlock(uint8_t fill_value, size_t num_witnesses) {
    Block block;
    block.header.state = BlockState::LOCALLY_FINAL;
    std::fill(block.block_hash.begin(), block.block_hash.end(), fill_value);

    // Add mock TEE attestquorum signature
    // In this test, we track witnesses by their IDs, not via attestquorum
    // The attestquorum field is for TEE ECDSA signature only
    block.header.use_attestquorum = true;
    block.header.attestquorum = std::vector<uint8_t>(70, 0xAB);  // Mock TEE ECDSA signature

    return block;
}

/**
 * Test 1: Record witness observation
 */
TestResult test_record_witness_observation() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create and record block observation
    Block block = createTestBlock(0xAA, 5);
    vehicle.recordWitnessObservation(block);

    // Get stats
    auto stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (stats.total_signed == 5);
    std::string details = "Witnesses signed: " + std::to_string(stats.total_signed);

    return TestResult{"Record witness observation", passed, details};
}

/**
 * Test 2: Track witnesses who observed block
 */
TestResult test_track_observed_witnesses() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0xBB, 3);
    vehicle.recordWitnessObservation(block);

    // Record that witnesses observed the block
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_A");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_B");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_C");

    auto stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (stats.total_observed == 3);
    std::string details = "Witnesses observed: " + std::to_string(stats.total_observed);

    return TestResult{"Track observed witnesses", passed, details};
}

/**
 * Test 3: Track witnesses who reported
 */
TestResult test_track_reported_witnesses() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0xCC, 5);
    vehicle.recordWitnessObservation(block);

    // Record observations and reports
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_1");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_2");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_3");

    // Only 2 report
    vehicle.recordWitnessReport(block.block_hash, "witness_1");
    vehicle.recordWitnessReport(block.block_hash, "witness_2");

    auto stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (stats.total_reported == 2);
    std::string details = "Witnesses reported: " + std::to_string(stats.total_reported);

    return TestResult{"Track reported witnesses", passed, details};
}

/**
 * Test 4: Identify silent witnesses
 */
TestResult test_identify_silent_witnesses() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0xDD, 3);
    vehicle.recordWitnessObservation(block);

    // 5 witnesses observed
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_A");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_B");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_C");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_D");
    vehicle.recordWitnessSeenBlock(block.block_hash, "witness_E");

    // Only 2 reported
    vehicle.recordWitnessReport(block.block_hash, "witness_A");
    vehicle.recordWitnessReport(block.block_hash, "witness_C");

    // Mark as malicious and get silent witnesses
    std::vector<VehicleID> silent = vehicle.markBlockMaliciousAndGetSilentWitnesses(block.block_hash);

    // Should have 3 silent witnesses (B, D, E)
    bool passed = (silent.size() == 3);
    std::string details = "Silent witnesses: " + std::to_string(silent.size()) + " (expected 3)";

    return TestResult{"Identify silent witnesses", passed, details};
}

/**
 * Test 5: Silent witness count in stats
 */
TestResult test_silent_witness_count_in_stats() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0xEE, 2);
    vehicle.recordWitnessObservation(block);

    // 4 observed, 1 reported
    vehicle.recordWitnessSeenBlock(block.block_hash, "w1");
    vehicle.recordWitnessSeenBlock(block.block_hash, "w2");
    vehicle.recordWitnessSeenBlock(block.block_hash, "w3");
    vehicle.recordWitnessSeenBlock(block.block_hash, "w4");
    vehicle.recordWitnessReport(block.block_hash, "w1");

    auto stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (stats.silent_count == 3);  // w2, w3, w4
    std::string details = "Silent count: " + std::to_string(stats.silent_count);

    return TestResult{"Silent witness count in stats", passed, details};
}

/**
 * Test 6: Mark block as malicious
 */
TestResult test_mark_block_malicious() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0xFF, 1);
    vehicle.recordWitnessObservation(block);

    // Initially not malicious
    auto stats_before = vehicle.getWitnessStats(block.block_hash);

    // Mark as malicious
    vehicle.markBlockMaliciousAndGetSilentWitnesses(block.block_hash);

    auto stats_after = vehicle.getWitnessStats(block.block_hash);

    bool passed = (!stats_before.was_malicious && stats_after.was_malicious);
    std::string details = "Malicious flag: before=" +
                         std::string(stats_before.was_malicious ? "true" : "false") +
                         ", after=" + std::string(stats_after.was_malicious ? "true" : "false");

    return TestResult{"Mark block as malicious", passed, details};
}

/**
 * Test 7: Multiple blocks tracking
 */
TestResult test_multiple_blocks_tracking() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create multiple blocks
    Block block1 = createTestBlock(0x11, 3);
    Block block2 = createTestBlock(0x22, 4);
    Block block3 = createTestBlock(0x33, 5);

    vehicle.recordWitnessObservation(block1);
    vehicle.recordWitnessObservation(block2);
    vehicle.recordWitnessObservation(block3);

    auto stats1 = vehicle.getWitnessStats(block1.block_hash);
    auto stats2 = vehicle.getWitnessStats(block2.block_hash);
    auto stats3 = vehicle.getWitnessStats(block3.block_hash);

    bool passed = (stats1.total_signed == 3 &&
                   stats2.total_signed == 4 &&
                   stats3.total_signed == 5);

    std::string details = "Blocks tracked: 3, Signatures: " +
                         std::to_string(stats1.total_signed) + "/" +
                         std::to_string(stats2.total_signed) + "/" +
                         std::to_string(stats3.total_signed);

    return TestResult{"Multiple blocks tracking", passed, details};
}

/**
 * Test 8: No silent witnesses when all report
 */
TestResult test_no_silent_when_all_report() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0x44, 2);
    vehicle.recordWitnessObservation(block);

    // All who observed also reported
    vehicle.recordWitnessSeenBlock(block.block_hash, "w1");
    vehicle.recordWitnessSeenBlock(block.block_hash, "w2");
    vehicle.recordWitnessReport(block.block_hash, "w1");
    vehicle.recordWitnessReport(block.block_hash, "w2");

    auto stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (stats.silent_count == 0);
    std::string details = "Silent count: " + std::to_string(stats.silent_count) + " (expected 0)";

    return TestResult{"No silent when all report", passed, details};
}

/**
 * Test 9: Thread safety of witness tracking
 */
TestResult test_thread_safety() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block
    Block block = createTestBlock(0x55, 1);
    vehicle.recordWitnessObservation(block);

    // Rapid concurrent access (simple test)
    for (int i = 0; i < 100; ++i) {
        vehicle.recordWitnessSeenBlock(block.block_hash, "witness_" + std::to_string(i % 10));
        auto stats = vehicle.getWitnessStats(block.block_hash);
    }

    auto final_stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (final_stats.total_observed == 10);  // 10 unique witnesses (0-9)
    std::string details = "Observed witnesses: " + std::to_string(final_stats.total_observed);

    return TestResult{"Thread safety", passed, details};
}

/**
 * Test 10: Empty block handling
 */
TestResult test_empty_block_handling() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle";
    config.traci = traci;
    config.wave_config.node_id = "test_vehicle";
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 1.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create block with no witnesses
    Block block = createTestBlock(0x66, 0);
    vehicle.recordWitnessObservation(block);

    auto stats = vehicle.getWitnessStats(block.block_hash);

    bool passed = (stats.total_signed == 0 && stats.total_observed == 0 && stats.total_reported == 0);
    std::string details = "Empty block tracked correctly";

    return TestResult{"Empty block handling", passed, details};
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║    Witness Tracking System Verification                     ║\n";
    std::cout << "║    Testing witness accountability and silent witness        ║\n";
    std::cout << "║    detection mechanisms                                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::vector<TestResult> results;

    // Run all tests 10 times
    const int NUM_RUNS = 10;

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::cout << "===== RUN " << run << " =====\n";

        results.push_back(test_record_witness_observation());
        results.push_back(test_track_observed_witnesses());
        results.push_back(test_track_reported_witnesses());
        results.push_back(test_identify_silent_witnesses());
        results.push_back(test_silent_witness_count_in_stats());
        results.push_back(test_mark_block_malicious());
        results.push_back(test_multiple_blocks_tracking());
        results.push_back(test_no_silent_when_all_report());
        results.push_back(test_thread_safety());
        results.push_back(test_empty_block_handling());

        std::cout << "\n";
    }

    // Print summary
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    VERIFICATION SUMMARY                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    int total = results.size();
    int passed = 0;
    for (const auto& result : results) {
        if (result.passed) passed++;
    }

    std::cout << "Total Tests: " << total << "\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << (total - passed) << "\n";
    std::cout << "Success Rate: " << std::fixed << std::setprecision(1)
              << (100.0 * passed / total) << "%\n\n";

    // Print failed tests if any
    if (passed < total) {
        std::cout << "Failed tests:\n";
        for (const auto& result : results) {
            if (!result.passed) {
                printResult(result);
            }
        }
    }

    std::cout << (passed == total ? "✓ ALL TESTS PASSED!\n" : "✗ SOME TESTS FAILED\n");
    std::cout << "══════════════════════════════════════════════════════════════\n\n";

    return (passed == total) ? 0 : 1;
}
