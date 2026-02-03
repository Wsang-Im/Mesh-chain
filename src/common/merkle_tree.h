#ifndef MESHCHAIN_MERKLE_TREE_H
#define MESHCHAIN_MERKLE_TREE_H

#include "types.h"
#include "../crypto/sha3_wrapper.h"
#include <vector>
#include <string>
#include <optional>
#include <cmath>
#include <algorithm>

namespace meshchain {

/**
 * Merkle Path for witness membership verification
 *
 * Used in Algorithm 2 (witness-side validation) to verify:
 * 1. Witness is actually in the committed witness set
 * 2. Position in the set matches the claimed position
 *
 * From paper Section 3.1:
 * "The witness-set-commit is a Merkle root over the sorted witness IDs,
 *  allowing each witness to verify their membership with O(log w) proof size"
 */
struct MerklePath {
    size_t leaf_index;              // Position in sorted witness list
    std::vector<Hash256> siblings;  // Sibling hashes on path to root
    std::vector<bool> directions;   // true = sibling on right, false = sibling on left

    MerklePath() : leaf_index(0) {}

    // Verify the path has consistent structure
    bool isValid() const {
        return siblings.size() == directions.size();
    }

    // Get the depth of the tree (path length)
    size_t depth() const {
        return siblings.size();
    }
};

/**
 * Binary Merkle Tree for witness-set commitment
 *
 * Critical security property from paper:
 * "Each witness must be able to verify they are in the committed set
 *  using only their Merkle path and the root in the block header"
 *
 * Implementation details:
 * - Leaves are sorted witness IDs (lexicographic order)
 * - Internal nodes are SHA3-256(left || right)
 * - Padding for non-power-of-2 witness counts
 */
class MerkleTree {
private:
    std::vector<std::string> sorted_witness_ids_;
    std::vector<std::vector<Hash256>> tree_levels_;  // tree_levels_[0] = leaves, last = root
    Hash256 root_;

public:
    MerkleTree() = default;

    /**
     * Build Merkle tree from witness IDs
     *
     * @param witness_ids Witness IDs (will be sorted internally)
     * @return Constructed Merkle tree
     */
    static MerkleTree build(const std::vector<std::string>& witness_ids) {
        MerkleTree tree;

        if (witness_ids.empty()) {
            // Empty tree has zero root
            tree.root_ = Hash256{};
            return tree;
        }

        // Sort witness IDs lexicographically for deterministic ordering
        tree.sorted_witness_ids_ = witness_ids;
        std::sort(tree.sorted_witness_ids_.begin(), tree.sorted_witness_ids_.end());

        // Build leaf level
        std::vector<Hash256> leaves;
        for (const auto& id : tree.sorted_witness_ids_) {
            leaves.push_back(hashLeaf(id));
        }
        tree.tree_levels_.push_back(leaves);

        // Build internal levels bottom-up
        std::vector<Hash256> current_level = leaves;
        while (current_level.size() > 1) {
            std::vector<Hash256> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    // Pair exists
                    next_level.push_back(hashPair(current_level[i], current_level[i + 1]));
                } else {
                    // Odd node - duplicate it (standard Merkle tree padding)
                    next_level.push_back(hashPair(current_level[i], current_level[i]));
                }
            }

            tree.tree_levels_.push_back(next_level);
            current_level = next_level;
        }

        // Root is the last level
        tree.root_ = current_level[0];

        return tree;
    }

    /**
     * Get Merkle root (witness-set-commit)
     */
    Hash256 getRoot() const {
        return root_;
    }

    /**
     * Generate Merkle path for a specific witness
     *
     * This is what gets transmitted to the witness in sig_req message
     * (Algorithm 1, Phase E: witness signature collection)
     *
     * @param witness_id The witness ID to generate path for
     * @return Merkle path or nullopt if witness not in tree
     */
    std::optional<MerklePath> getPath(const std::string& witness_id) const {
        // Find witness index in sorted list
        auto it = std::find(sorted_witness_ids_.begin(), sorted_witness_ids_.end(), witness_id);
        if (it == sorted_witness_ids_.end()) {
            return std::nullopt;  // Witness not in tree
        }

        size_t leaf_index = std::distance(sorted_witness_ids_.begin(), it);

        MerklePath path;
        path.leaf_index = leaf_index;

        // Traverse from leaf to root, collecting siblings
        size_t current_index = leaf_index;
        for (size_t level = 0; level < tree_levels_.size() - 1; ++level) {
            const auto& level_nodes = tree_levels_[level];

            // Find sibling
            size_t sibling_index;
            bool sibling_on_right;

            if (current_index % 2 == 0) {
                // Current node is left child, sibling is right
                sibling_index = current_index + 1;
                sibling_on_right = true;
            } else {
                // Current node is right child, sibling is left
                sibling_index = current_index - 1;
                sibling_on_right = false;
            }

            // Handle case where sibling doesn't exist (odd number of nodes)
            Hash256 sibling_hash;
            if (sibling_index < level_nodes.size()) {
                sibling_hash = level_nodes[sibling_index];
            } else {
                // Duplicate current node (padding)
                sibling_hash = level_nodes[current_index];
            }

            path.siblings.push_back(sibling_hash);
            path.directions.push_back(sibling_on_right);

            // Move to parent in next level
            current_index = current_index / 2;
        }

        return path;
    }

    /**
     * Verify witness membership using Merkle path
     *
     * This is used by the witness in Algorithm 2 (line 10-11):
     * "Check membership in witness-set-commit using Merkle path"
     *
     * @param root Expected Merkle root (from block header)
     * @param witness_id Witness ID claiming membership
     * @param path Merkle path provided by creator
     * @return true if path proves witness is in the committed set
     */
    static bool verify(const Hash256& root, const std::string& witness_id, const MerklePath& path) {
        if (!path.isValid()) {
            return false;
        }

        // Start with leaf hash
        Hash256 current_hash = hashLeaf(witness_id);

        // Traverse path upward, computing parent hashes
        for (size_t i = 0; i < path.siblings.size(); ++i) {
            const Hash256& sibling = path.siblings[i];
            bool sibling_on_right = path.directions[i];

            if (sibling_on_right) {
                // Current is left, sibling is right
                current_hash = hashPair(current_hash, sibling);
            } else {
                // Current is right, sibling is left
                current_hash = hashPair(sibling, current_hash);
            }
        }

        // Final hash should match root
        return current_hash == root;
    }

    /**
     * Get the list of sorted witness IDs
     */
    const std::vector<std::string>& getWitnessIds() const {
        return sorted_witness_ids_;
    }

private:
    /**
     * Hash a leaf node (witness ID)
     * Uses SHA3-256 for cryptographic security
     */
    static Hash256 hashLeaf(const std::string& witness_id) {
        // Use real SHA3-256: hash("leaf" || witness_id)
        std::vector<uint8_t> data;
        data.push_back(0x01);  // Leaf prefix to differentiate from internal nodes
        data.insert(data.end(), witness_id.begin(), witness_id.end());

        return crypto::SHA3::hash(data);
    }

    /**
     * Hash an internal node (pair of children)
     * Uses SHA3-256 for cryptographic security
     */
    static Hash256 hashPair(const Hash256& left, const Hash256& right) {
        // Use real SHA3-256: hash("internal" || left || right)
        std::vector<uint8_t> data;
        data.push_back(0x02);  // Internal node prefix to differentiate from leaves
        data.insert(data.end(), left.begin(), left.end());
        data.insert(data.end(), right.begin(), right.end());

        return crypto::SHA3::hash(data);
    }
};

} // namespace meshchain

#endif // MESHCHAIN_MERKLE_TREE_H
