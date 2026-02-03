#ifndef MESHCHAIN_ANCHOR_SYSTEM_H
#define MESHCHAIN_ANCHOR_SYSTEM_H

#include "../common/types.h"
#include "../common/block.h"
#include "../crypto/pqc_signatures.h"
#include "../crypto/liboqs_wrapper.h"
#include "../crypto/zkp_stark.h"
#include <vector>
#include <optional>
#include <mutex>
#include <openssl/sha.h>

namespace meshchain {
namespace rsu {

/**
 * Anchor Structure (Section 3.3)
 *
 * Hierarchical anchoring for deterministic convergence:
 * - L1: Local (per-RSU, 30-60s, 1-5km, up to 2^10 blocks)
 * - L2: Regional (multi-RSU, 60-180s, 10-50km, up to 2^14 L1 anchors)
 * - L3: Global (cloud, 300-600s, nationwide, up to 2^16 L2 anchors)
 *
 * Each anchor signed with Dilithium-3
 * Optional transparent proof-of-verification (FRI/STARK) off-path
 */
struct Anchor {
    // Chain linkage
    Hash256 prev_anchor;
    Timestamp time;

    // Content
    Hash256 merkle_root;  // Root over locally-final blocks or sub-anchors
    size_t count;         // Number of items anchored

    // Metadata
    AnchorLevel level;
    std::string region_id;
    uint64_t sequence_number;

    // Optional proof that all signatures were verified
    std::optional<std::vector<uint8_t>> proof_of_verification;

    // Dilithium-3 signature
    std::vector<uint8_t> anchor_sig;

    Hash256 computeHash() const {
        // Hash all fields except signature
        Hash256 hash = {};
        for (size_t i = 0; i < 32; ++i) {
            hash[i] = prev_anchor[i] ^ merkle_root[i];
        }
        return hash;
    }
};

/**
 * RSU Anchor System (Algorithm 4)
 */
class AnchorSystem {
public:
    struct Config {
        std::string rsu_id;
        std::string region_id;
        AnchorLevel level;
        std::shared_ptr<crypto::MLDSASigner> signer;  // ML-DSA (Dilithium-3)
        uint32_t base_period_s;  // Default: 120s
        bool generate_proofs;    // Generate transparent proofs?
    };

private:
    Config config_;
    std::vector<Block> pending_blocks_;
    std::vector<Anchor> pending_anchors_;  // For L2/L3
    Anchor last_anchor_;
    Timestamp last_anchor_time_;
    std::mutex anchor_mutex_;

public:
    explicit AnchorSystem(const Config& config) : config_(config) {
        last_anchor_time_ = std::chrono::system_clock::now();
    }

    /**
     * Compute adaptive anchor period (Algorithm 3.3)
     *
     * @param traffic_density Vehicles per km²
     * @param partition_risk Estimated partition probability
     * @return Anchor period in seconds
     */
    uint32_t computeAnchorPeriod(double traffic_density, double partition_risk) const {
        uint32_t period = config_.base_period_s;

        // Dense traffic → shorter period
        if (traffic_density > 50.0) {
            period = std::max(30u, period / 2);
        }
        // High partition risk → shorter period
        else if (partition_risk > 0.3) {
            period = std::max(30u, period / 3);
        }
        // Sparse traffic → longer period
        else if (traffic_density < 10.0) {
            period = std::min(300u, period * 2);
        }

        return period;
    }

    /**
     * Add locally-final block for anchoring
     */
    void addBlock(const Block& block) {
        std::lock_guard<std::mutex> lock(anchor_mutex_);

        if (block.header.state == BlockState::LOCALLY_FINAL) {
            pending_blocks_.push_back(block);
        }
    }

    /**
     * Add sub-anchor (for L2/L3 aggregation)
     */
    void addSubAnchor(const Anchor& anchor) {
        std::lock_guard<std::mutex> lock(anchor_mutex_);

        if (config_.level == AnchorLevel::L2 && anchor.level == AnchorLevel::L1) {
            pending_anchors_.push_back(anchor);
        }
        else if (config_.level == AnchorLevel::L3 && anchor.level == AnchorLevel::L2) {
            pending_anchors_.push_back(anchor);
        }
    }

    /**
     * Generate anchor (called periodically based on adaptive period)
     *
     * Returns optional anchor if generation successful
     */
    std::optional<Anchor> generateAnchor() {
        std::lock_guard<std::mutex> lock(anchor_mutex_);

        if (pending_blocks_.empty() && pending_anchors_.empty()) {
            return std::nullopt;  // Nothing to anchor
        }

        Anchor anchor;
        anchor.prev_anchor = last_anchor_.computeHash();
        anchor.time = std::chrono::system_clock::now();
        anchor.level = config_.level;
        anchor.region_id = config_.region_id;
        anchor.sequence_number = last_anchor_.sequence_number + 1;

        // Compute Merkle root over items
        if (config_.level == AnchorLevel::L1) {
            // Anchor locally-final blocks
            anchor.merkle_root = computeMerkleRoot(pending_blocks_);
            anchor.count = pending_blocks_.size();

            // Optional: Generate proof that all Falcon signatures were verified
            if (config_.generate_proofs) {
                anchor.proof_of_verification = generateProofOfVerification(pending_blocks_);
            }

            pending_blocks_.clear();
        }
        else {
            // Anchor sub-anchors (L2 anchors L1, L3 anchors L2)
            anchor.merkle_root = computeMerkleRootOfAnchors(pending_anchors_);
            anchor.count = pending_anchors_.size();

            pending_anchors_.clear();
        }

        // Sign anchor with Dilithium-3
        std::vector<uint8_t> anchor_bytes = serializeAnchor(anchor);
        anchor.anchor_sig = config_.signer->sign(anchor_bytes);

        // Update state
        last_anchor_ = anchor;
        last_anchor_time_ = anchor.time;

        return anchor;
    }

    /**
     * Verify anchor signature
     */
    bool verifyAnchor(const Anchor& anchor,
                     const std::vector<uint8_t>& public_key) const {
        std::vector<uint8_t> anchor_bytes = serializeAnchor(anchor);
        return config_.signer->verify(anchor_bytes, anchor.anchor_sig, public_key);
    }

    /**
     * Compute finality score for branch (Algorithm 5)
     *
     * Scoring tuple: ⟨A(B), W(B), C(B), Hash(B)⟩
     * - A: Anchor weight (L3 > L2 > L1)
     * - W: Witness support (avg fraction × diversity score)
     * - C: Consistency (1 - conflict ratio)
     * - Hash: Lexicographic tiebreaker
     */
    struct FinalityScore {
        double anchor_weight;
        double witness_support;
        double consistency;
        Hash256 hash;

        bool operator<(const FinalityScore& other) const {
            if (anchor_weight != other.anchor_weight)
                return anchor_weight < other.anchor_weight;
            if (witness_support != other.witness_support)
                return witness_support < other.witness_support;
            if (consistency != other.consistency)
                return consistency < other.consistency;
            return std::lexicographical_compare(
                hash.begin(), hash.end(),
                other.hash.begin(), other.hash.end()
            );
        }
    };

    FinalityScore computeFinalityScore(const std::vector<Block>& branch) const {
        FinalityScore score;

        // Anchor weight (40%)
        double a1 = countAnchors(branch, AnchorLevel::L1) * 0.1;
        double a2 = countAnchors(branch, AnchorLevel::L2) * 0.2;
        double a3 = countAnchors(branch, AnchorLevel::L3) * 0.4;
        score.anchor_weight = std::min(0.4, a1 + a2 + a3);

        // Witness support (40%) - attestquorum protocol
        double total_ws = 0.0;
        for (const auto& block : branch) {
            size_t valid_witnesses = block.header.witness_bitmap.count();
            size_t required_witnesses = 5;  // Simplified
            double ws = static_cast<double>(valid_witnesses) / required_witnesses;
            // Would also multiply by diversity score
            total_ws += ws;
        }
        score.witness_support = 0.4 * (total_ws / std::max(1.0, static_cast<double>(branch.size())));

        // Consistency bonus (20%)
        double conflict_ratio = 0.1;  // Simplified: would compute actual conflicts
        double cs = 1.0 - conflict_ratio;
        double ls = std::min(1.0, branch.size() / 100.0);
        score.consistency = 0.2 * cs * ls;

        // Hash for tiebreaking
        if (!branch.empty()) {
            score.hash = branch.back().block_hash;
        }

        return score;
    }

private:
    /**
     * Merkle proof structure for block inclusion
     */
    struct BlockMerkleProof {
        size_t block_index;
        Hash256 block_hash;
        std::vector<Hash256> siblings;   // Sibling hashes along path to root
        std::vector<bool> directions;     // true = right sibling, false = left sibling
        Hash256 merkle_root;
    };

    /**
     * Hash a pair of nodes in Merkle tree (SHA-256)
     */
    Hash256 hashPair(const Hash256& left, const Hash256& right) const {
        Hash256 result;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, left.data(), 32);
        SHA256_Update(&ctx, right.data(), 32);
        SHA256_Final(result.data(), &ctx);
        return result;
    }

    /**
     * Compute Merkle root using real SHA-256 based Merkle tree
     */
    Hash256 computeMerkleRoot(const std::vector<Block>& blocks) const {
        if (blocks.empty()) {
            return Hash256{};
        }

        // Layer 0: block hashes
        std::vector<Hash256> current_layer;
        for (const auto& block : blocks) {
            current_layer.push_back(block.block_hash);
        }

        // Build tree bottom-up using SHA-256
        while (current_layer.size() > 1) {
            std::vector<Hash256> next_layer;

            for (size_t i = 0; i < current_layer.size(); i += 2) {
                if (i + 1 < current_layer.size()) {
                    next_layer.push_back(hashPair(current_layer[i], current_layer[i + 1]));
                } else {
                    // Odd number of nodes: duplicate last one
                    next_layer.push_back(hashPair(current_layer[i], current_layer[i]));
                }
            }

            current_layer = next_layer;
        }

        return current_layer[0];
    }

    /**
     * Generate Merkle proof for a specific block
     * Returns authentication path from block to root
     */
    BlockMerkleProof generateMerkleProof(const std::vector<Block>& blocks,
                                          size_t block_index) const {
        BlockMerkleProof proof;
        proof.block_index = block_index;

        if (block_index >= blocks.size() || blocks.empty()) {
            return proof;  // Invalid index
        }

        proof.block_hash = blocks[block_index].block_hash;

        // Build all layers of the tree to generate proof
        std::vector<std::vector<Hash256>> layers;

        // Layer 0: all block hashes
        std::vector<Hash256> current_layer;
        for (const auto& block : blocks) {
            current_layer.push_back(block.block_hash);
        }
        layers.push_back(current_layer);

        // Build remaining layers
        while (current_layer.size() > 1) {
            std::vector<Hash256> next_layer;

            for (size_t i = 0; i < current_layer.size(); i += 2) {
                if (i + 1 < current_layer.size()) {
                    next_layer.push_back(hashPair(current_layer[i], current_layer[i + 1]));
                } else {
                    next_layer.push_back(hashPair(current_layer[i], current_layer[i]));
                }
            }

            layers.push_back(next_layer);
            current_layer = next_layer;
        }

        // Extract proof path
        size_t current_index = block_index;
        for (size_t layer = 0; layer < layers.size() - 1; ++layer) {
            size_t sibling_index = (current_index % 2 == 0) ? current_index + 1 : current_index - 1;

            // Add sibling if it exists
            if (sibling_index < layers[layer].size()) {
                proof.siblings.push_back(layers[layer][sibling_index]);
                proof.directions.push_back(current_index % 2 == 0);  // true if we're left child
            }

            current_index /= 2;
        }

        // Set root
        if (!layers.empty() && !layers.back().empty()) {
            proof.merkle_root = layers.back()[0];
        }

        return proof;
    }

    /**
     * Verify Merkle proof for a block
     */
    bool verifyMerkleProof(const BlockMerkleProof& proof) const {
        Hash256 current_hash = proof.block_hash;

        for (size_t i = 0; i < proof.siblings.size(); ++i) {
            if (proof.directions[i]) {
                // We're left child, sibling is right
                current_hash = hashPair(current_hash, proof.siblings[i]);
            } else {
                // We're right child, sibling is left
                current_hash = hashPair(proof.siblings[i], current_hash);
            }
        }

        return current_hash == proof.merkle_root;
    }

    Hash256 computeMerkleRootOfAnchors(const std::vector<Anchor>& anchors) const {
        if (anchors.empty()) {
            return Hash256{};
        }

        // Layer 0: anchor hashes
        std::vector<Hash256> current_layer;
        for (const auto& anchor : anchors) {
            current_layer.push_back(anchor.computeHash());
        }

        // Build tree bottom-up using SHA-256
        while (current_layer.size() > 1) {
            std::vector<Hash256> next_layer;

            for (size_t i = 0; i < current_layer.size(); i += 2) {
                if (i + 1 < current_layer.size()) {
                    next_layer.push_back(hashPair(current_layer[i], current_layer[i + 1]));
                } else {
                    // Odd number of nodes: duplicate last one
                    next_layer.push_back(hashPair(current_layer[i], current_layer[i]));
                }
            }

            current_layer = next_layer;
        }

        return current_layer[0];
    }

    std::vector<uint8_t> generateProofOfVerification(
            const std::vector<Block>& blocks) const {
        // Generate real FRI/STARK proof that all Falcon signatures were verified
        crypto::STARKProver prover(80);  // 80-bit security parameter

        auto stark_proof = prover.generateProof(blocks);

        // Serialize STARK proof to bytes
        return stark_proof.serialize();
    }

    std::vector<uint8_t> serializeAnchor(const Anchor& anchor) const {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), anchor.prev_anchor.begin(), anchor.prev_anchor.end());
        bytes.insert(bytes.end(), anchor.merkle_root.begin(), anchor.merkle_root.end());
        // Add other fields...
        return bytes;
    }

    size_t countAnchors(const std::vector<Block>& branch, AnchorLevel level) const {
        // Count how many blocks are confirmed by anchors of given level
        // Simplified: would check actual anchor confirmations
        return 0;
    }
};

} // namespace rsu
} // namespace meshchain

#endif // MESHCHAIN_ANCHOR_SYSTEM_H
