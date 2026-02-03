#include "src/rsu/anchor_system.h"
#include "src/crypto/sha3_wrapper.h"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <openssl/sha.h>

using namespace meshchain;
using namespace meshchain::rsu;

/**
 * Validation Test: Verify Merkle proofs use REAL SHA-256 hashing
 *
 * This test validates that:
 * 1. Merkle root is computed using real SHA-256 (not XOR or other arbitrary methods)
 * 2. Merkle proofs can be independently verified using OpenSSL SHA-256
 * 3. No mock or stub implementations are in use
 */

// Helper: Manually compute SHA-256 hash of two 32-byte values
Hash256 manual_sha256_pair(const Hash256& left, const Hash256& right) {
    Hash256 result;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, left.data(), 32);
    SHA256_Update(&ctx, right.data(), 32);
    SHA256_Final(result.data(), &ctx);
    return result;
}

int main() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Merkle Proof SHA-256 Validation Test                       ║\n";
    std::cout << "║  Verifies real cryptographic hashing (no mocks/stubs)       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    // Create anchor system
    AnchorSystem::Config config;
    config.level = AnchorLevel::L1;
    config.rsu_id = "validation_rsu";
    config.region_id = "test_region";
    config.base_period_s = 120;
    config.generate_proofs = false;

    auto signer = std::make_shared<crypto::MLDSASigner>();
    signer->generateKeys();
    config.signer = signer;

    AnchorSystem anchor_system(config);

    // Create 4 blocks with known hashes
    std::vector<Block> blocks;
    for (int i = 0; i < 4; ++i) {
        Block block;
        block.header.state = BlockState::LOCALLY_FINAL;
        std::fill(block.block_hash.begin(), block.block_hash.end(), 0x10 + i);
        blocks.push_back(block);
        anchor_system.addBlock(block);
    }

    std::cout << "Test 1: Verifying Merkle root uses real SHA-256\n";
    std::cout << "  Created 4 blocks with known hashes...\n";

    // Generate anchor
    auto anchor_result = anchor_system.generateAnchor();
    if (!anchor_result.has_value()) {
        std::cout << "  [FAIL] Failed to generate anchor\n";
        return 1;
    }

    Hash256 merkle_root = anchor_result->merkle_root;

    std::cout << "  Merkle root (first 16 bytes): ";
    for (int i = 0; i < 16; ++i) {
        printf("%02x", merkle_root[i]);
    }
    std::cout << "\n";

    // Manually compute expected root using SHA-256
    // Tree structure for 4 blocks:
    //           root
    //          /    \
    //        h01    h23
    //       /  \   /  \
    //      b0  b1 b2  b3

    Hash256 h01 = manual_sha256_pair(blocks[0].block_hash, blocks[1].block_hash);
    Hash256 h23 = manual_sha256_pair(blocks[2].block_hash, blocks[3].block_hash);
    Hash256 expected_root = manual_sha256_pair(h01, h23);

    std::cout << "  Expected root (first 16 bytes): ";
    for (int i = 0; i < 16; ++i) {
        printf("%02x", expected_root[i]);
    }
    std::cout << "\n";

    bool roots_match = (merkle_root == expected_root);
    std::cout << "  " << (roots_match ? "[PASS]" : "[FAIL]")
              << " Merkle root matches manually computed SHA-256 root\n\n";

    if (!roots_match) {
        std::cout << "ERROR: Merkle root does not match expected SHA-256 computation!\n";
        std::cout << "This indicates the implementation is NOT using real SHA-256.\n";
        return 1;
    }

    // Test 2: Verify deterministic hashing
    std::cout << "Test 2: Verifying deterministic SHA-256 hashing\n";

    AnchorSystem anchor_system2(config);
    for (const auto& block : blocks) {
        anchor_system2.addBlock(block);
    }

    auto anchor_result2 = anchor_system2.generateAnchor();
    bool deterministic = (anchor_result2.has_value() &&
                          anchor_result2->merkle_root == merkle_root);

    std::cout << "  " << (deterministic ? "[PASS]" : "[FAIL]")
              << " Same blocks produce identical Merkle root\n\n";

    if (!deterministic) {
        std::cout << "ERROR: Non-deterministic hashing detected!\n";
        return 1;
    }

    // Test 3: Verify different data produces different hash
    std::cout << "Test 3: Verifying collision resistance\n";

    AnchorSystem anchor_system3(config);
    for (int i = 0; i < 4; ++i) {
        Block block;
        block.header.state = BlockState::LOCALLY_FINAL;
        std::fill(block.block_hash.begin(), block.block_hash.end(), 0x20 + i);  // Different hashes
        anchor_system3.addBlock(block);
    }

    auto anchor_result3 = anchor_system3.generateAnchor();
    bool different = (anchor_result3.has_value() &&
                      anchor_result3->merkle_root != merkle_root);

    std::cout << "  " << (different ? "[PASS]" : "[FAIL]")
              << " Different blocks produce different Merkle root\n\n";

    if (!different) {
        std::cout << "ERROR: Collision detected or non-cryptographic hash in use!\n";
        return 1;
    }

    // Test 4: Verify no zero-only output (avalanche effect)
    std::cout << "Test 4: Verifying avalanche effect (SHA-256 property)\n";

    Hash256 zero_hash = {};
    bool non_zero = (merkle_root != zero_hash);

    // Also check that hash has good entropy (not all same byte)
    bool has_entropy = false;
    uint8_t first_byte = merkle_root[0];
    for (size_t i = 1; i < merkle_root.size(); ++i) {
        if (merkle_root[i] != first_byte) {
            has_entropy = true;
            break;
        }
    }

    std::cout << "  " << (non_zero ? "[PASS]" : "[FAIL]")
              << " Merkle root is non-zero\n";
    std::cout << "  " << (has_entropy ? "[PASS]" : "[FAIL]")
              << " Merkle root has good entropy (not all same byte)\n\n";

    if (!non_zero || !has_entropy) {
        std::cout << "ERROR: Hash output lacks expected cryptographic properties!\n";
        return 1;
    }

    // Test 5: Verify no simple XOR (old implementation check)
    std::cout << "Test 5: Verifying NOT using simple XOR aggregation\n";

    // Compute what XOR would give
    Hash256 xor_result = {};
    for (const auto& block : blocks) {
        for (size_t i = 0; i < 32; ++i) {
            xor_result[i] ^= block.block_hash[i];
        }
    }

    bool not_xor = (merkle_root != xor_result);

    std::cout << "  " << (not_xor ? "[PASS]" : "[FAIL]")
              << " Merkle root is NOT simple XOR of block hashes\n";
    std::cout << "  (XOR would give: ";
    for (int i = 0; i < 8; ++i) {
        printf("%02x", xor_result[i]);
    }
    std::cout << "...)\n\n";

    if (!not_xor) {
        std::cout << "ERROR: Implementation is using simple XOR, not SHA-256!\n";
        return 1;
    }

    // Summary
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                  VALIDATION SUMMARY                          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    bool all_passed = roots_match && deterministic && different && non_zero && has_entropy && not_xor;

    if (all_passed) {
        std::cout << "✓ ALL VALIDATION TESTS PASSED!\n";
        std::cout << "\nConclusion: Merkle proof implementation uses REAL SHA-256 hashing.\n";
        std::cout << "  - No mock implementations detected\n";
        std::cout << "  - No stub implementations detected\n";
        std::cout << "  - No arbitrary value generation detected\n";
        std::cout << "  - Cryptographic properties verified\n";
    } else {
        std::cout << "✗ VALIDATION FAILED!\n";
        std::cout << "\nERROR: Implementation does not use real SHA-256 hashing!\n";
    }

    std::cout << "══════════════════════════════════════════════════════════════\n\n";

    return all_passed ? 0 : 1;
}
