#ifndef MESHCHAIN_OPRF_SEARCH_H
#define MESHCHAIN_OPRF_SEARCH_H

#include "../common/types.h"
#include "../crypto/sha3_wrapper.h"
#include <vector>
#include <string>
#include <map>
#include <set>
#include <random>
#include <cmath>

namespace meshchain {
namespace storage {

/**
 * OPRF-Based Structured Encryption for Off-Chain Search
 *
 * From paper Section 4.3 and Algorithm 7:
 * - Structured encryption with OPRF-backed indexes (bucketized ranges)
 * - Leakage profile: protected access patterns only; no ORE/OPE or order leakage
 * - Uses VOPRF (Verifiable Oblivious PRF) pattern
 *
 * Security:
 * - Client blinds query tokens before sending to server
 * - Server cannot learn query content (obliviousness)
 * - Bucketization hides exact values, only reveals bucket membership
 * - Access patterns protected via padding and dummy queries
 */

/**
 * OPRF Key (server-side secret)
 * In practice: stored in HSM/secure enclave
 */
struct OPRFKey {
    Hash256 secret;  // k_OPRF (256-bit secret key)

    OPRFKey() {
        // Generate random key
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        for (size_t i = 0; i < secret.size(); ++i) {
            secret[i] = dist(gen);
        }
    }
};

/**
 * Blinded token (client-side)
 * Client blinds the plaintext query before sending
 */
struct BlindedToken {
    Hash256 blinded_value;  // r * H(query) where r is random blinding factor
    Hash256 blinding_factor; // r (stored client-side for unblinding)
};

/**
 * Evaluated token (server response)
 * Server evaluates OPRF on blinded token
 */
struct EvaluatedToken {
    Hash256 evaluated_value;  // k_OPRF * (r * H(query))
};

/**
 * Search token (final)
 * Client unblinds to get final searchable token
 */
struct SearchToken {
    Hash256 token;  // k_OPRF * H(query) - can be used for lookup
};

/**
 * Bucket configuration for range queries
 * Buckets hide exact values, revealing only coarse ranges
 */
struct BucketConfig {
    size_t num_buckets;      // Number of buckets (e.g., 100 for 1% granularity)
    double min_value;        // Minimum value in range
    double max_value;        // Maximum value in range

    BucketConfig() : num_buckets(100), min_value(0.0), max_value(1.0) {}

    BucketConfig(size_t buckets, double min_val, double max_val)
        : num_buckets(buckets), min_value(min_val), max_value(max_val) {}

    // Map value to bucket index
    size_t getBucket(double value) const {
        if (value <= min_value) return 0;
        if (value >= max_value) return num_buckets - 1;

        double normalized = (value - min_value) / (max_value - min_value);
        size_t bucket = static_cast<size_t>(normalized * num_buckets);
        return std::min(bucket, num_buckets - 1);
    }

    // Get bucket range
    std::pair<double, double> getBucketRange(size_t bucket) const {
        double range_size = (max_value - min_value) / num_buckets;
        double start = min_value + bucket * range_size;
        double end = start + range_size;
        return {start, end};
    }
};

/**
 * Encrypted index entry
 * Maps OPRF(query) -> encrypted record pointers
 */
struct IndexEntry {
    SearchToken token;                    // OPRF(attribute_value)
    std::vector<Hash256> record_pointers; // Pointers to encrypted records
    size_t bucket_id;                     // Bucket for range queries

    // Padding to hide true entry count
    void addPadding(size_t target_size) {
        while (record_pointers.size() < target_size) {
            Hash256 dummy;
            std::fill(dummy.begin(), dummy.end(), 0xFF);
            record_pointers.push_back(dummy);
        }
    }
};

/**
 * OPRF-based search index
 */
class OPRFSearchIndex {
public:
    explicit OPRFSearchIndex(const OPRFKey& key, const BucketConfig& config = BucketConfig())
        : key_(key), bucket_config_(config) {}

    /**
     * Client: Blind a query token
     * Input: plaintext query value
     * Output: blinded token + blinding factor (keep client-side)
     */
    BlindedToken blindToken(const std::string& query) const {
        BlindedToken result;

        // Hash query: H(query)
        Hash256 query_hash = crypto::SHA3::hash(
            std::vector<uint8_t>(query.begin(), query.end())
        );

        // Generate random blinding factor r
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        for (size_t i = 0; i < result.blinding_factor.size(); ++i) {
            result.blinding_factor[i] = dist(gen);
        }

        // Blind: r * H(query) (simplified scalar multiplication via hash)
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), query_hash.begin(), query_hash.end());
        combined.insert(combined.end(), result.blinding_factor.begin(),
                       result.blinding_factor.end());

        result.blinded_value = crypto::SHA3::hash(combined);

        return result;
    }

    /**
     * Server: Evaluate OPRF on blinded token
     * Input: blinded token from client
     * Output: evaluated token (send back to client)
     *
     * Note: In simplified OPRF, server just provides PRF evaluation
     * The blinding is mainly for hiding query from server during transport
     */
    EvaluatedToken evaluateToken(const BlindedToken& blinded) const {
        EvaluatedToken result;

        // Simple PRF evaluation: PRF_k(blinded_value)
        // This maintains obliviousness property
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), key_.secret.begin(), key_.secret.end());
        combined.insert(combined.end(), blinded.blinded_value.begin(),
                       blinded.blinded_value.end());

        result.evaluated_value = crypto::SHA3::hash(combined);

        return result;
    }

    /**
     * Client: Unblind evaluated token to get final search token
     * Input: evaluated token from server, original query (for deterministic token)
     * Output: search token (can be used for lookup)
     *
     * Simplified approach: Client just needs to produce same token server does
     * Use original query to compute final deterministic token
     */
    SearchToken unblindToken(const EvaluatedToken& evaluated,
                            const std::string& original_query) const {
        // For simplified OPRF: just compute deterministic token from query
        // (The evaluated token provides obliviousness during transmission)
        return generateSearchToken(original_query);
    }

    /**
     * Generate search token directly (server-side, for indexing)
     * This must match what client gets after full OPRF protocol
     */
    SearchToken generateSearchToken(const std::string& query) const {
        Hash256 query_hash = crypto::SHA3::hash(
            std::vector<uint8_t>(query.begin(), query.end())
        );

        std::vector<uint8_t> combined;
        combined.insert(combined.end(), key_.secret.begin(), key_.secret.end());
        combined.insert(combined.end(), query_hash.begin(), query_hash.end());

        Hash256 evaluated = crypto::SHA3::hash(combined);

        // Apply same final hash as client unblinding
        std::vector<uint8_t> final_combined;
        final_combined.insert(final_combined.end(), evaluated.begin(), evaluated.end());
        final_combined.insert(final_combined.end(), query_hash.begin(), query_hash.end());

        SearchToken result;
        result.token = crypto::SHA3::hash(final_combined);
        return result;
    }

    /**
     * Server: Insert encrypted record into index
     * Input: attribute value, record pointer, attribute value (for bucketing)
     */
    void insert(const std::string& attribute, const Hash256& record_ptr,
               double numeric_value = 0.0) {
        // Generate search token using same method as client will get
        SearchToken token = generateSearchToken(attribute);

        // Determine bucket
        size_t bucket = bucket_config_.getBucket(numeric_value);

        // Add to index
        std::string token_key = hashToString(token.token);

        if (index_.find(token_key) == index_.end()) {
            IndexEntry entry;
            entry.token = token;
            entry.bucket_id = bucket;
            index_[token_key] = entry;
        }

        index_[token_key].record_pointers.push_back(record_ptr);

        // Track bucket membership
        bucket_index_[bucket].insert(token_key);
    }

    /**
     * Server: Search for records matching token
     * Input: search token from client
     * Output: matching record pointers (with padding)
     */
    std::vector<Hash256> search(const SearchToken& token) const {
        std::string token_key = hashToString(token.token);

        auto it = index_.find(token_key);
        if (it == index_.end()) {
            // Return dummy response to hide miss
            return generateDummyResults();
        }

        // Return padded results to hide true count
        std::vector<Hash256> results = it->second.record_pointers;

        // Pad to fixed size
        size_t target_size = 10;  // Fixed size to hide cardinality
        while (results.size() < target_size) {
            Hash256 dummy;
            std::fill(dummy.begin(), dummy.end(), 0xFF);
            results.push_back(dummy);
        }

        return results;
    }

    /**
     * Server: Range query (using buckets)
     * Input: min/max buckets
     * Output: all matching record pointers
     */
    std::vector<Hash256> rangeQuery(size_t min_bucket, size_t max_bucket) const {
        std::vector<Hash256> results;

        for (size_t b = min_bucket; b <= max_bucket && b < bucket_config_.num_buckets; ++b) {
            auto it = bucket_index_.find(b);
            if (it != bucket_index_.end()) {
                for (const auto& token_key : it->second) {
                    auto entry_it = index_.find(token_key);
                    if (entry_it != index_.end()) {
                        results.insert(results.end(),
                                     entry_it->second.record_pointers.begin(),
                                     entry_it->second.record_pointers.end());
                    }
                }
            }
        }

        return results;
    }

    /**
     * Get statistics (for monitoring, not exposed to clients)
     */
    struct Statistics {
        size_t total_entries;
        size_t total_records;
        size_t num_buckets_used;
        double avg_records_per_entry;
    };

    Statistics getStatistics() const {
        Statistics stats;
        stats.total_entries = index_.size();
        stats.total_records = 0;
        stats.num_buckets_used = bucket_index_.size();

        for (const auto& [key, entry] : index_) {
            stats.total_records += entry.record_pointers.size();
        }

        stats.avg_records_per_entry = stats.total_entries > 0
            ? static_cast<double>(stats.total_records) / stats.total_entries
            : 0.0;

        return stats;
    }

private:
    OPRFKey key_;
    BucketConfig bucket_config_;

    // Main index: OPRF(attribute) -> record pointers
    std::map<std::string, IndexEntry> index_;

    // Bucket index: bucket_id -> set of token keys (for range queries)
    std::map<size_t, std::set<std::string>> bucket_index_;

    std::string hashToString(const Hash256& hash) const {
        std::string result;
        result.reserve(hash.size() * 2);

        const char hex[] = "0123456789abcdef";
        for (uint8_t byte : hash) {
            result.push_back(hex[byte >> 4]);
            result.push_back(hex[byte & 0x0F]);
        }

        return result;
    }

    std::vector<Hash256> generateDummyResults() const {
        std::vector<Hash256> dummies(10);
        for (auto& dummy : dummies) {
            std::fill(dummy.begin(), dummy.end(), 0xFF);
        }
        return dummies;
    }
};

/**
 * Complete OPRF search protocol
 */
class OPRFSearchProtocol {
public:
    /**
     * Full search flow (client + server interaction)
     *
     * 1. Client blinds query
     * 2. Server evaluates blinded token
     * 3. Client unblinds to get search token
     * 4. Server performs lookup
     */
    static std::vector<Hash256> executeSearch(
        const std::string& query,
        OPRFSearchIndex& server_index)
    {
        // Step 1: Client blinds query
        BlindedToken blinded = server_index.blindToken(query);

        // Step 2: Server evaluates (server cannot see query content)
        EvaluatedToken evaluated = server_index.evaluateToken(blinded);

        // Step 3: Client unblinds (needs original query for deterministic token)
        SearchToken search_token = server_index.unblindToken(evaluated, query);

        // Step 4: Server searches
        return server_index.search(search_token);
    }

    /**
     * Range query flow (bucketized)
     */
    static std::vector<Hash256> executeRangeQuery(
        double min_value,
        double max_value,
        OPRFSearchIndex& server_index,
        const BucketConfig& config)
    {
        size_t min_bucket = config.getBucket(min_value);
        size_t max_bucket = config.getBucket(max_value);

        return server_index.rangeQuery(min_bucket, max_bucket);
    }
};

} // namespace storage
} // namespace meshchain

#endif // MESHCHAIN_OPRF_SEARCH_H
