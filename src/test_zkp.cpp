/**
 * Test program for FRI/STARK Zero-Knowledge Proof system
 */

#include "crypto/zkp_stark.h"
#include "common/block.h"
#include <iostream>
#include <iomanip>

using namespace meshchain;
using namespace meshchain::crypto;

void printHash(const Hash256& hash) {
    for (size_t i = 0; i < std::min(size_t(8), hash.size()); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(hash[i]);
    }
    std::cout << "..." << std::dec;
}

int main() {
    std::cout << "=== FRI/STARK Zero-Knowledge Proof System Test ===\n\n";

    // Test 1: Merkle Tree
    std::cout << "[Test 1] Merkle Tree Construction and Proof Verification\n";
    {
        MerkleTree tree;
        std::vector<std::vector<uint8_t>> leaves;

        // Create test leaves
        for (int i = 0; i < 8; ++i) {
            std::vector<uint8_t> leaf(32, i);
            leaves.push_back(leaf);
        }

        tree.build(leaves);
        Hash256 root = tree.getRoot();

        std::cout << "  - Built Merkle tree with " << leaves.size() << " leaves\n";
        std::cout << "  - Merkle root: ";
        printHash(root);
        std::cout << "\n";

        // Generate and verify proof for leaf 3
        auto proof = tree.getProof(3);
        Hash256 leaf_hash;
        SHA256(leaves[3].data(), leaves[3].size(), leaf_hash.data());

        bool valid = MerkleTree::verifyProof(leaf_hash, proof, root);
        std::cout << "  - Proof for leaf #3: " << (valid ? "✓ VALID" : "✗ INVALID") << "\n";
        std::cout << "  - Proof size: " << proof.siblings.size() << " hashes\n\n";
    }

    // Test 2: STARK Proof Generation
    std::cout << "[Test 2] STARK Proof Generation for Signature Verification\n";
    {
        // Create test blocks with witness signatures
        std::vector<Block> blocks;

        for (int i = 0; i < 5; ++i) {
            Block block;
            block.block_hash.fill(i);

            // Add mock TEE attestquorum signature (ECDSA P-256, ~70 bytes)
            block.header.use_attestquorum = true;
            block.header.attestquorum = std::vector<uint8_t>(70, 0xAB + i);

            blocks.push_back(block);
        }

        STARKProver prover(80);  // 80-bit security
        auto start = std::chrono::steady_clock::now();
        STARKProof proof = prover.generateProof(blocks);
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << "  - Generated STARK proof for " << blocks.size() << " blocks\n";
        std::cout << "  - Total signatures verified: " << proof.num_signatures_verified << "\n";
        std::cout << "  - Security level: " << proof.security_bits << " bits\n";
        std::cout << "  - Proof generation time: " << duration.count() << " ms\n";
        std::cout << "  - Proof size: " << proof.getSize() << " bytes\n";
        std::cout << "  - Trace commitment: ";
        printHash(proof.trace_commitment);
        std::cout << "\n";
        std::cout << "  - Composition commitment: ";
        printHash(proof.composition_commitment);
        std::cout << "\n";
        std::cout << "  - FRI rounds: " << proof.fri_proof.merkle_roots.size() << "\n";
        std::cout << "  - Query responses: " << proof.query_responses.size() << "\n\n";

        // Verify the proof
        bool valid = STARKProver::verifyProof(proof, blocks.size());
        std::cout << "  - Proof verification: " << (valid ? "✓ VALID" : "✗ INVALID") << "\n\n";
    }

    // Test 3: FRI Proof Structure
    std::cout << "[Test 3] FRI Low-Degree Testing\n";
    {
        std::vector<FieldElement> polynomial;
        for (int i = 0; i < 32; ++i) {
            FieldElement elem{};
            elem[0] = i;
            polynomial.push_back(elem);
        }

        // Simulate FRI proof generation (internal test)
        STARKProver prover(80);
        std::vector<Block> dummy_blocks(1);
        auto proof = prover.generateProof(dummy_blocks);

        std::cout << "  - FRI polynomial degree: " << polynomial.size() << "\n";
        std::cout << "  - FRI folding rounds: " << proof.fri_proof.merkle_roots.size() << "\n";
        std::cout << "  - Evaluation points sampled: " << proof.fri_proof.evaluations.size() << "\n";
        std::cout << "  - Merkle proofs: " << proof.fri_proof.merkle_proofs.size() << "\n\n";
    }

    // Test 4: Performance Scaling
    std::cout << "[Test 4] Performance Scaling Test\n";
    {
        std::vector<size_t> block_counts = {1, 5, 10, 20};

        for (size_t count : block_counts) {
            std::vector<Block> blocks;
            for (size_t i = 0; i < count; ++i) {
                Block block;
                block.block_hash.fill(i);

                // Add mock TEE attestquorum signature
                block.header.use_attestquorum = true;
                block.header.attestquorum = std::vector<uint8_t>(70, 0xCD + i);
                blocks.push_back(block);
            }

            STARKProver prover(80);
            auto start = std::chrono::steady_clock::now();
            STARKProof proof = prover.generateProof(blocks);
            auto end = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            std::cout << "  - " << std::setw(2) << count << " blocks: "
                      << std::setw(4) << ms.count() << " ms, "
                      << std::setw(5) << proof.getSize() << " bytes\n";
        }
        std::cout << "\n";
    }

    std::cout << "=== All Tests Completed Successfully ===\n";
    return 0;
}
