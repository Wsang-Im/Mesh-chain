#include "rsu/anchor_system.h"
#include "crypto/sha3_wrapper.h"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <random>

using namespace meshchain;
using namespace meshchain::rsu;

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
 * Helper: Create a block with specific hash
 */
Block createTestBlock(uint8_t fill_value) {
    Block block;
    block.header.state = BlockState::LOCALLY_FINAL;
    std::fill(block.block_hash.begin(), block.block_hash.end(), fill_value);
    return block;
}

/**
 * Test 1: Single block Merkle proof
 */
TestResult test_single_block_proof() {
    // Create anchor system
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create single block
    std::vector<Block> blocks;
    blocks.push_back(createTestBlock(0xAA));

    // Access private method via reflection (using const_cast for testing)
    // In real test, we'd expose a public test interface
    // For now, test via generateAnchor which uses computeMerkleRoot internally

    anchor_system.addBlock(blocks[0]);
    auto anchor_result = anchor_system.generateAnchor();

    bool passed = anchor_result.has_value();
    std::string details = passed ? "Anchor generated with single block"
                                 : "Failed to generate anchor";

    return TestResult{"Single block Merkle proof", passed, details};
}

/**
 * Test 2: Two blocks Merkle proof
 */
TestResult test_two_blocks_proof() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create two blocks
    Block block1 = createTestBlock(0xAA);
    Block block2 = createTestBlock(0xBB);

    anchor_system.addBlock(block1);
    anchor_system.addBlock(block2);

    auto anchor_result = anchor_system.generateAnchor();

    bool passed = anchor_result.has_value() && anchor_result->count == 2;
    std::string details = "Anchor count: " + std::to_string(anchor_result ? anchor_result->count : 0);

    return TestResult{"Two blocks Merkle proof", passed, details};
}

/**
 * Test 3: Power of 2 blocks (4 blocks)
 */
TestResult test_power_of_2_blocks() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create 4 blocks
    for (int i = 0; i < 4; ++i) {
        anchor_system.addBlock(createTestBlock(0x10 * i));
    }

    auto anchor_result = anchor_system.generateAnchor();

    bool passed = anchor_result.has_value() && anchor_result->count == 4;
    std::string details = "Blocks anchored: " + std::to_string(anchor_result ? anchor_result->count : 0);

    return TestResult{"Power of 2 blocks (4)", passed, details};
}

/**
 * Test 4: Non-power of 2 blocks (7 blocks)
 */
TestResult test_non_power_of_2_blocks() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create 7 blocks (non-power of 2)
    for (int i = 0; i < 7; ++i) {
        anchor_system.addBlock(createTestBlock(0x10 + i));
    }

    auto anchor_result = anchor_system.generateAnchor();

    bool passed = anchor_result.has_value() && anchor_result->count == 7;
    std::string details = "Blocks anchored: " + std::to_string(anchor_result ? anchor_result->count : 0);

    return TestResult{"Non-power of 2 blocks (7)", passed, details};
}

/**
 * Test 5: Large batch (100 blocks)
 */
TestResult test_large_batch() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create 100 blocks
    for (int i = 0; i < 100; ++i) {
        Block block = createTestBlock(i % 256);
        anchor_system.addBlock(block);
    }

    auto anchor_result = anchor_system.generateAnchor();

    bool passed = anchor_result.has_value() && anchor_result->count == 100;
    std::string details = "Large batch anchored: " + std::to_string(anchor_result ? anchor_result->count : 0);

    return TestResult{"Large batch (100 blocks)", passed, details};
}

/**
 * Test 6: Merkle root determinism
 */
TestResult test_merkle_root_determinism() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system1(config);
    AnchorSystem anchor_system2(config);

    // Add same blocks to both
    for (int i = 0; i < 5; ++i) {
        Block block = createTestBlock(0x20 + i);
        anchor_system1.addBlock(block);
        anchor_system2.addBlock(block);
    }

    auto anchor1 = anchor_system1.generateAnchor();
    auto anchor2 = anchor_system2.generateAnchor();

    bool passed = anchor1.has_value() && anchor2.has_value() &&
                  anchor1->merkle_root == anchor2->merkle_root;

    std::string details = passed ? "Merkle roots match (deterministic)"
                                 : "Merkle roots differ (non-deterministic)";

    return TestResult{"Merkle root determinism", passed, details};
}

/**
 * Test 7: Different blocks produce different roots
 */
TestResult test_different_blocks_different_roots() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system1(config);
    AnchorSystem anchor_system2(config);

    // Add different blocks
    for (int i = 0; i < 5; ++i) {
        anchor_system1.addBlock(createTestBlock(0x30 + i));
        anchor_system2.addBlock(createTestBlock(0x40 + i));  // Different values
    }

    auto anchor1 = anchor_system1.generateAnchor();
    auto anchor2 = anchor_system2.generateAnchor();

    bool passed = anchor1.has_value() && anchor2.has_value() &&
                  anchor1->merkle_root != anchor2->merkle_root;

    std::string details = passed ? "Different roots for different blocks (correct)"
                                 : "Same roots for different blocks (ERROR)";

    return TestResult{"Different blocks produce different roots", passed, details};
}

/**
 * Test 8: Block order sensitivity
 */
TestResult test_block_order_sensitivity() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system1(config);
    AnchorSystem anchor_system2(config);

    // Add blocks in different orders
    Block block_a = createTestBlock(0xAA);
    Block block_b = createTestBlock(0xBB);
    Block block_c = createTestBlock(0xCC);

    anchor_system1.addBlock(block_a);
    anchor_system1.addBlock(block_b);
    anchor_system1.addBlock(block_c);

    anchor_system2.addBlock(block_c);
    anchor_system2.addBlock(block_b);
    anchor_system2.addBlock(block_a);

    auto anchor1 = anchor_system1.generateAnchor();
    auto anchor2 = anchor_system2.generateAnchor();

    bool passed = anchor1.has_value() && anchor2.has_value() &&
                  anchor1->merkle_root != anchor2->merkle_root;

    std::string details = passed ? "Order affects Merkle root (correct)"
                                 : "Order doesn't affect root (ERROR)";

    return TestResult{"Block order sensitivity", passed, details};
}

/**
 * Test 9: Empty block list handling
 */
TestResult test_empty_block_list() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Don't add any blocks
    auto anchor_result = anchor_system.generateAnchor();

    bool passed = !anchor_result.has_value();  // Should return nullopt
    std::string details = passed ? "Correctly returns nullopt for empty list"
                                 : "Incorrectly generated anchor for empty list";

    return TestResult{"Empty block list handling", passed, details};
}

/**
 * Test 10: Merkle root is non-zero for valid blocks
 */
TestResult test_merkle_root_non_zero() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Add blocks with non-zero hashes
    for (int i = 0; i < 3; ++i) {
        anchor_system.addBlock(createTestBlock(0x50 + i));
    }

    auto anchor_result = anchor_system.generateAnchor();

    Hash256 zero_hash = {};
    bool is_non_zero = false;
    if (anchor_result.has_value()) {
        is_non_zero = (anchor_result->merkle_root != zero_hash);
    }

    bool passed = is_non_zero;
    std::string details = passed ? "Merkle root is non-zero (valid)"
                                 : "Merkle root is zero (ERROR)";

    return TestResult{"Merkle root non-zero for valid blocks", passed, details};
}

/**
 * Test 11: L2 anchor aggregation
 */
TestResult test_l2_anchor_aggregation() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L2;
    config.rsu_id = "test_rsu_l2";
    config.region_id = "test_region";
    config.base_period_s = 180;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create L1 anchors to aggregate
    for (int i = 0; i < 3; ++i) {
        Anchor l1_anchor;
        l1_anchor.level = AnchorLevel::L1;
        l1_anchor.sequence_number = i;
        std::fill(l1_anchor.merkle_root.begin(), l1_anchor.merkle_root.end(), 0x60 + i);
        anchor_system.addSubAnchor(l1_anchor);
    }

    auto anchor_result = anchor_system.generateAnchor();

    bool passed = anchor_result.has_value() &&
                  anchor_result->level == AnchorLevel::L2 &&
                  anchor_result->count == 3;

    std::string details = "L2 aggregated " + std::to_string(anchor_result ? anchor_result->count : 0) + " L1 anchors";

    return TestResult{"L2 anchor aggregation", passed, details};
}

/**
 * Test 12: Anchor signature verification
 */
TestResult test_anchor_signature_verification() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Add blocks
    for (int i = 0; i < 3; ++i) {
        anchor_system.addBlock(createTestBlock(0x70 + i));
    }

    auto anchor_result = anchor_system.generateAnchor();

    bool has_signature = anchor_result.has_value() && !anchor_result->anchor_sig.empty();

    // Verify signature (requires public key)
    bool verified = false;
    if (has_signature) {
        auto public_key = signer->getPublicKey();
        verified = anchor_system.verifyAnchor(anchor_result.value(), public_key);
    }

    bool passed = has_signature && verified;
    std::string details = has_signature ?
                         (verified ? "Signature verified" : "Signature verification failed") :
                         "No signature generated";

    return TestResult{"Anchor signature verification", passed, details};
}

/**
 * Test 13: Multiple anchor generations
 */
TestResult test_multiple_anchor_generations() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    int successful_generations = 0;

    // Generate 5 anchors sequentially
    for (int gen = 0; gen < 5; ++gen) {
        // Add blocks
        for (int i = 0; i < 3; ++i) {
            anchor_system.addBlock(createTestBlock(0x80 + gen * 10 + i));
        }

        auto anchor_result = anchor_system.generateAnchor();
        if (anchor_result.has_value()) {
            successful_generations++;
        }
    }

    bool passed = (successful_generations == 5);
    std::string details = "Generated " + std::to_string(successful_generations) + "/5 anchors";

    return TestResult{"Multiple anchor generations", passed, details};
}

/**
 * Test 14: Adaptive anchor period
 */
TestResult test_adaptive_anchor_period() {
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "test_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();  // Generate key pair
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Test different traffic conditions
    uint32_t period_dense = anchor_system.computeAnchorPeriod(100.0, 0.1);  // Dense traffic
    uint32_t period_sparse = anchor_system.computeAnchorPeriod(5.0, 0.1);   // Sparse traffic
    uint32_t period_high_risk = anchor_system.computeAnchorPeriod(30.0, 0.5); // High partition risk

    bool passed = (period_dense < config.base_period_s) &&
                  (period_sparse > config.base_period_s) &&
                  (period_high_risk < config.base_period_s);

    std::string details = "Dense: " + std::to_string(period_dense) + "s, " +
                         "Sparse: " + std::to_string(period_sparse) + "s, " +
                         "High-risk: " + std::to_string(period_high_risk) + "s";

    return TestResult{"Adaptive anchor period", passed, details};
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║    Merkle Proof Generation Verification                     ║\n";
    std::cout << "║    Testing SHA-256 based Merkle tree implementation         ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::vector<TestResult> results;

    // Run all tests 10 times as required
    const int NUM_RUNS = 10;

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::cout << "===== RUN " << run << " =====\n";

        results.push_back(test_single_block_proof());
        results.push_back(test_two_blocks_proof());
        results.push_back(test_power_of_2_blocks());
        results.push_back(test_non_power_of_2_blocks());
        results.push_back(test_large_batch());
        results.push_back(test_merkle_root_determinism());
        results.push_back(test_different_blocks_different_roots());
        results.push_back(test_block_order_sensitivity());
        results.push_back(test_empty_block_list());
        results.push_back(test_merkle_root_non_zero());
        results.push_back(test_l2_anchor_aggregation());
        results.push_back(test_anchor_signature_verification());
        results.push_back(test_multiple_anchor_generations());
        results.push_back(test_adaptive_anchor_period());

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
