#ifndef MESHCHAIN_TEE_AGGREGATOR_H
#define MESHCHAIN_TEE_AGGREGATOR_H

/**
 * TEE (Trusted Execution Environment) Signature Aggregator
 *
 * Supports two protocols:
 *
 * 1. LEGACY: Signature aggregation (deprecated)
 *    - Collects individual FALCON-512 signatures from witnesses
 *    - Generates aggregated commit (SHA3-256 hash of all signatures)
 *
 * 2. NEW: Attestquorum protocol (Paper Section 3.2)
 *    - Witnesses vote via MAC over secure ML-KEM-768 TLS 1.3 channels
 *    - TEE aggregates MACs and produces attestquorum signature (~128 bytes)
 *    - Reduces block size from ~4.2KB to ~1.4KB (w=3 witnesses)
 *    - Eliminates packet fragmentation in WAVE networks
 *
 * Key features:
 * - Backward compatible with existing block structure
 * - Compatible with OMNet++ integration
 * - Verifiable proof of witness set participation
 */

#include "../common/types.h"
#include "../common/block.h"
#include "sha3_wrapper.h"
#include "pqc_signatures.h"
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace meshchain {
namespace crypto {

/**
 * TEE Aggregated Commit Structure
 *
 * Represents the aggregated commitment from all witness signatures
 */
struct TEECommit {
    Hash256 aggregate_hash;              // SHA3-256(all witness signatures)
    std::vector<Hash256> signature_hashes;  // Individual signature hashes for verification
    size_t witness_count;                // Number of witnesses
    Timestamp created_at;                // When commit was created

    // Metadata for verification
    Hash256 block_header_hash;           // Hash of the block header being signed
    std::bitset<MAX_WITNESS_COUNT> witness_bitmap;  // Which witnesses signed

    TEECommit() : witness_count(0) {
        aggregate_hash.fill(0);
        block_header_hash.fill(0);
        created_at = std::chrono::system_clock::now();
    }

    /**
     * Serialize TEE commit for storage/transmission
     */
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.reserve(1024);

        // Serialize aggregate hash
        data.insert(data.end(), aggregate_hash.begin(), aggregate_hash.end());

        // Serialize witness count
        uint64_t count = witness_count;
        for (size_t i = 0; i < 8; ++i) {
            data.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
        }

        // Serialize block header hash
        data.insert(data.end(), block_header_hash.begin(), block_header_hash.end());

        // Serialize individual signature hashes
        for (const auto& sig_hash : signature_hashes) {
            data.insert(data.end(), sig_hash.begin(), sig_hash.end());
        }

        return data;
    }
};

/**
 * TEE Signature Aggregator
 *
 * Simulates TEE-based secure aggregation of witness signatures
 * In production, this would run inside SGX/TrustZone enclave
 */
class TEEAggregator {
public:
    struct Config {
        bool enable_individual_verification;  // Verify each signature before aggregation
        double max_aggregation_time_ms;       // Maximum time for aggregation (default: 10ms)

        Config()
            : enable_individual_verification(true)
            , max_aggregation_time_ms(10.0) {}
    };

    struct AggregationResult {
        bool success;
        TEECommit commit;
        size_t verified_count;
        size_t failed_count;
        double aggregation_time_ms;
        std::string failure_reason;
    };

    // NEW: Attestdiv result structure (Paper Section 3.2 - Phase 2)
    // Phase 2: Witness Selection and Diversity Attestation
    // attestdiv ← SignTEE(Hash(W)||metrics) where W is selected witness set
    struct AttestdivResult {
        bool success;
        std::vector<uint8_t> attestdiv;  // TEE signature over diversity metrics (~658 bytes FALCON-512)
        size_t witness_count;            // Number of witnesses in the selected set
        double generation_time_ms;       // Time to generate attestdiv
        std::string failure_reason;      // Error message if failed

        // Diversity metrics (for debugging/logging)
        size_t oem_diversity_count;      // Number of unique OEMs
        double geographical_spread;      // Geographical diversity metric
        double avg_reputation;           // Average reputation of witnesses

        AttestdivResult() : success(false), witness_count(0), generation_time_ms(0.0),
                           oem_diversity_count(0), geographical_spread(0.0), avg_reputation(0.0) {}
    };

    // NEW: Attestquorum result structure (Paper Section 3.2)
    struct AttestquorumResult {
        bool success;
        std::vector<uint8_t> attestquorum;  // TEE signature over aggregated votes (~128 bytes)
        Hash256 witness_merkle_root;        // Merkle root of witness identities
        size_t witness_count;               // Number of witnesses who voted
        double generation_time_ms;          // Time to generate attestquorum
        std::string failure_reason;         // Error message if failed

        AttestquorumResult() : success(false), witness_count(0), generation_time_ms(0.0) {
            witness_merkle_root.fill(0);
        }
    };

private:
    Config config_;

public:
    explicit TEEAggregator(const Config& config = Config())
        : config_(config) {}

    /**
     * Aggregate witness signatures into TEE commit
     *
     * @param block_header Header of the block being signed
     * @param witness_signatures List of witness signatures
     * @param witness_public_keys List of witness public keys (for verification)
     * @return Aggregation result with TEE commit
     */
    AggregationResult aggregateSignatures(
            const BlockHeader& block_header,
            const std::vector<std::vector<uint8_t>>& witness_signatures,
            const std::vector<std::vector<uint8_t>>& witness_public_keys) {

        auto start_time = std::chrono::high_resolution_clock::now();

        AggregationResult result;
        result.success = false;
        result.verified_count = 0;
        result.failed_count = 0;

        std::cout << "[TEE Aggregator] Starting aggregation of "
                  << witness_signatures.size() << " witness signatures\n";

        // Validate input
        if (witness_signatures.empty()) {
            result.failure_reason = "No witness signatures provided";
            result.aggregation_time_ms = getElapsedMs(start_time);
            return result;
        }

        if (config_.enable_individual_verification &&
            witness_signatures.size() != witness_public_keys.size()) {
            result.failure_reason = "Signature and public key count mismatch";
            result.aggregation_time_ms = getElapsedMs(start_time);
            return result;
        }

        // Compute block header hash (what witnesses signed)
        Hash256 header_hash = block_header.computeHeaderHash();
        result.commit.block_header_hash = header_hash;

        // Step 1: Verify individual signatures (if enabled)
        std::vector<Hash256> verified_sig_hashes;
        std::bitset<MAX_WITNESS_COUNT> verified_bitmap;

        for (size_t i = 0; i < witness_signatures.size(); ++i) {
            const auto& signature = witness_signatures[i];

            if (config_.enable_individual_verification && i < witness_public_keys.size()) {
                const auto& pubkey = witness_public_keys[i];

                // Verify FALCON-512 signature
                bool valid = verifyFalconSignature(header_hash, signature, pubkey);

                if (!valid) {
                    std::cout << "[TEE Aggregator] ⚠ Signature #" << i
                              << " verification failed\n";
                    result.failed_count++;
                    continue;
                }
            }

            // Hash individual signature for commit
            Hash256 sig_hash = SHA3::hash(signature);
            verified_sig_hashes.push_back(sig_hash);
            verified_bitmap.set(i);
            result.verified_count++;
        }

        std::cout << "[TEE Aggregator] Verified " << result.verified_count
                  << " / " << witness_signatures.size() << " signatures\n";

        // Check if we have enough verified signatures
        if (verified_sig_hashes.empty()) {
            result.failure_reason = "No signatures passed verification";
            result.aggregation_time_ms = getElapsedMs(start_time);
            return result;
        }

        // Step 2: Create aggregated commit
        // Concatenate all verified signature hashes in deterministic order
        std::vector<uint8_t> aggregate_input;
        aggregate_input.reserve(verified_sig_hashes.size() * 32);

        for (const auto& sig_hash : verified_sig_hashes) {
            aggregate_input.insert(aggregate_input.end(),
                                  sig_hash.begin(), sig_hash.end());
        }

        // Compute aggregate hash (TEE commit)
        Hash256 aggregate_hash = SHA3::hash(aggregate_input);

        // Step 3: Build TEE commit structure
        result.commit.aggregate_hash = aggregate_hash;
        result.commit.signature_hashes = verified_sig_hashes;
        result.commit.witness_count = result.verified_count;
        result.commit.witness_bitmap = verified_bitmap;
        result.commit.created_at = std::chrono::system_clock::now();

        result.success = true;
        result.aggregation_time_ms = getElapsedMs(start_time);

        std::cout << "[TEE Aggregator] ✓ Aggregation complete in "
                  << result.aggregation_time_ms << "ms\n";
        std::cout << "[TEE Aggregator]   Aggregate hash: "
                  << hashToHexString(aggregate_hash).substr(0, 16) << "...\n";

        return result;
    }

    /**
     * Verify TEE commit against block and signatures
     *
     * This verifies that the TEE commit matches the provided signatures
     * Used by validators to check block integrity
     *
     * @param commit TEE commit to verify
     * @param block_header Block header that was signed
     * @param witness_signatures Original witness signatures
     * @return True if commit is valid
     */
    bool verifyTEECommit(
            const TEECommit& commit,
            const BlockHeader& block_header,
            const std::vector<std::vector<uint8_t>>& witness_signatures) {

        std::cout << "[TEE Aggregator] Verifying TEE commit...\n";

        // Check witness count matches
        if (commit.witness_count != witness_signatures.size()) {
            std::cout << "[TEE Aggregator] ✗ Witness count mismatch: commit="
                      << commit.witness_count << ", actual="
                      << witness_signatures.size() << "\n";
            return false;
        }

        // Verify block header hash
        Hash256 header_hash = block_header.computeHeaderHash();
        if (commit.block_header_hash != header_hash) {
            std::cout << "[TEE Aggregator] ✗ Block header hash mismatch\n";
            return false;
        }

        // Recompute signature hashes
        std::vector<Hash256> recomputed_hashes;
        for (const auto& signature : witness_signatures) {
            Hash256 sig_hash = SHA3::hash(signature);
            recomputed_hashes.push_back(sig_hash);
        }

        // Verify signature hashes match commit
        if (recomputed_hashes.size() != commit.signature_hashes.size()) {
            std::cout << "[TEE Aggregator] ✗ Signature hash count mismatch\n";
            return false;
        }

        for (size_t i = 0; i < recomputed_hashes.size(); ++i) {
            if (recomputed_hashes[i] != commit.signature_hashes[i]) {
                std::cout << "[TEE Aggregator] ✗ Signature hash #" << i
                          << " mismatch\n";
                return false;
            }
        }

        // Recompute aggregate hash
        std::vector<uint8_t> aggregate_input;
        aggregate_input.reserve(commit.signature_hashes.size() * 32);

        for (const auto& sig_hash : commit.signature_hashes) {
            aggregate_input.insert(aggregate_input.end(),
                                  sig_hash.begin(), sig_hash.end());
        }

        Hash256 recomputed_aggregate = SHA3::hash(aggregate_input);

        if (recomputed_aggregate != commit.aggregate_hash) {
            std::cout << "[TEE Aggregator] ✗ Aggregate hash mismatch\n";
            return false;
        }

        std::cout << "[TEE Aggregator] ✓ TEE commit verified successfully\n";
        return true;
    }

    /**
     * Generate attestdiv for witness selection (Phase 2 - Paper Section 3.2)
     *
     * This implements TEE-based diversity attestation that proves the selected
     * witness set satisfies diversity requirements (OEM diversity, geographical
     * spread, reputation thresholds, etc.)
     *
     * Protocol flow:
     * 1. Creator selects witness set W based on diversity criteria
     * 2. Creator computes diversity metrics (OEM count, geo spread, etc.)
     * 3. TEE generates attestdiv ← SignTEE(Hash(W)||metrics)
     * 4. Block includes attestdiv to prove witness diversity
     *
     * Fallback mechanism:
     * - If insufficient diverse witnesses, may use RSU super-witnessing
     *
     * @param witness_ids Vector of selected witness identities
     * @param oem_diversity_count Number of unique OEMs in witness set
     * @param geographical_spread Geographical diversity metric
     * @param avg_reputation Average reputation of selected witnesses
     * @param creator_signer Creator's FALCON signer (TEE uses it to sign attestdiv)
     * @return Attestdiv result with TEE signature
     */
    AttestdivResult generateAttestdiv(
            const std::vector<VehicleID>& witness_ids,
            size_t oem_diversity_count,
            double geographical_spread,
            double avg_reputation,
            const std::shared_ptr<FalconSigner>& creator_signer) {

        auto start_time = std::chrono::high_resolution_clock::now();

        AttestdivResult result;
        result.success = false;

        std::cout << "[TEE Attestdiv] Generating diversity attestation for "
                  << witness_ids.size() << " witnesses\n";

        // Validate input
        if (witness_ids.empty()) {
            result.failure_reason = "No witnesses provided";
            result.generation_time_ms = getElapsedMs(start_time);
            return result;
        }

        // Step 1: Compute Hash(W) - hash of witness identities (sorted for determinism)
        std::vector<std::string> sorted_witness_ids = witness_ids;
        std::sort(sorted_witness_ids.begin(), sorted_witness_ids.end());

        std::vector<uint8_t> witness_set_data;
        for (const auto& witness_id : sorted_witness_ids) {
            witness_set_data.insert(witness_set_data.end(),
                                   witness_id.begin(), witness_id.end());
        }
        Hash256 witness_set_hash = SHA3::hash(witness_set_data);

        // Step 2: Encode diversity metrics
        // Format: [oem_count(8B)] [geo_spread(8B)] [avg_rep(8B)]
        std::vector<uint8_t> metrics_data;
        metrics_data.reserve(24);

        // Encode OEM diversity count (8 bytes, little-endian)
        uint64_t oem_count = static_cast<uint64_t>(oem_diversity_count);
        for (size_t i = 0; i < 8; ++i) {
            metrics_data.push_back(static_cast<uint8_t>((oem_count >> (i * 8)) & 0xFF));
        }

        // Encode geographical spread (8 bytes, as uint64_t scaled by 1e6)
        uint64_t geo_scaled = static_cast<uint64_t>(geographical_spread * 1000000.0);
        for (size_t i = 0; i < 8; ++i) {
            metrics_data.push_back(static_cast<uint8_t>((geo_scaled >> (i * 8)) & 0xFF));
        }

        // Encode average reputation (8 bytes, as uint64_t scaled by 1e6)
        uint64_t rep_scaled = static_cast<uint64_t>(avg_reputation * 1000000.0);
        for (size_t i = 0; i < 8; ++i) {
            metrics_data.push_back(static_cast<uint8_t>((rep_scaled >> (i * 8)) & 0xFF));
        }

        // Step 3: Compute Hash(W)||metrics
        std::vector<uint8_t> attestdiv_input;
        attestdiv_input.reserve(32 + 24);
        attestdiv_input.insert(attestdiv_input.end(),
                              witness_set_hash.begin(), witness_set_hash.end());
        attestdiv_input.insert(attestdiv_input.end(),
                              metrics_data.begin(), metrics_data.end());

        Hash256 attestdiv_hash = SHA3::hash(attestdiv_input);

        // Step 4: TEE signs the diversity attestation with ECDSA
        // Uses secp256r1 (P-256) ECDSA signature (~70-72 bytes in DER format)
        // This simulates hardware TEE signatures (Intel SGX, ARM TrustZone)
        std::vector<uint8_t> hash_input(attestdiv_hash.begin(), attestdiv_hash.end());
        std::vector<uint8_t> attestdiv_sig = getTEESigner().sign(hash_input);

        if (attestdiv_sig.empty()) {
            result.failure_reason = "TEE ECDSA signing failed";
            result.generation_time_ms = getElapsedMs(start_time);
            std::cerr << "[TEE Attestdiv] ✗ ECDSA signing failed\n";
            return result;
        }

        // Store results
        result.attestdiv = attestdiv_sig;
        result.witness_count = witness_ids.size();
        result.oem_diversity_count = oem_diversity_count;
        result.geographical_spread = geographical_spread;
        result.avg_reputation = avg_reputation;
        result.success = true;
        result.generation_time_ms = getElapsedMs(start_time);

        std::cout << "[TEE Attestdiv] ✓ Diversity attestation generated in "
                  << result.generation_time_ms << "ms\n";
        std::cout << "[TEE Attestdiv]   Attestdiv size: "
                  << attestdiv_sig.size() << " bytes\n";
        std::cout << "[TEE Attestdiv]   Witness count: " << witness_ids.size() << "\n";
        std::cout << "[TEE Attestdiv]   OEM diversity: " << oem_diversity_count << "\n";
        std::cout << "[TEE Attestdiv]   Geo spread: " << geographical_spread << "\n";
        std::cout << "[TEE Attestdiv]   Avg reputation: " << avg_reputation << "\n";

        return result;
    }

    /**
     * Generate attestquorum from witness bitmap (NEW PROTOCOL - Paper Section 3.2)
     *
     * This implements the TEE-based attestquorum protocol that replaces individual
     * FALCON-512 signatures with temporary MAC voting, dramatically reducing block size.
     *
     * IMPORTANT: Vote (MAC) is NOT stored in block - only bitmap + attestquorum
     *
     * Protocol flow:
     * 1. Witnesses vote via MAC over secure ML-KEM-768 TLS 1.3 channels (Phase 4)
     * 2. Creator validates MACs and sets witness_bitmap for valid votes
     * 3. MACs are DISCARDED - only bitmap is kept
     * 4. TEE generates: attestquorum ← SignTEE_ECDSA(Hash(Header)||bitmap)
     * 5. Block includes: creator_sig + bitmap + attestquorum (NO MACs stored)
     *
     * Block size reduction (w=3 witnesses):
     * - Old: creator_sig (690B) + 3×witness_sigs (3×690B = 2070B) = 2760B
     * - New: creator_sig (690B) + bitmap (~1B) + attestquorum (~70B ECDSA) = ~761B
     * - Savings: ~2000B (72% reduction)
     *
     * @param block_header Header of the block being voted on
     * @param witness_bitmap Bitmap indicating which witnesses voted (MACs already validated)
     * @param witness_ids Vector of witness identities (for Merkle root)
     * @param creator_signer Creator's FALCON signer (not used - TEE has own ECDSA key)
     * @return Attestquorum result with TEE ECDSA signature
     */
    AttestquorumResult generateAttestquorum(
            const BlockHeader& block_header,
            const std::bitset<MAX_WITNESS_COUNT>& witness_bitmap,
            const std::vector<VehicleID>& witness_ids,
            const std::shared_ptr<FalconSigner>& creator_signer) {

        auto start_time = std::chrono::high_resolution_clock::now();

        AttestquorumResult result;
        result.success = false;

        size_t witness_count = witness_bitmap.count();
        std::cout << "[TEE Attestquorum] Generating attestquorum for "
                  << witness_count << " witnesses (bitmap-based)\n";

        // Validate input
        if (witness_count == 0) {
            result.failure_reason = "No witnesses in bitmap";
            result.generation_time_ms = getElapsedMs(start_time);
            return result;
        }

        if (witness_ids.size() < witness_count) {
            result.failure_reason = "Insufficient witness IDs for bitmap";
            result.generation_time_ms = getElapsedMs(start_time);
            return result;
        }

        // Step 1: Compute Merkle root of witness identities (deterministic ordering)
        // Use only witnesses that are set in bitmap
        std::vector<std::string> active_witness_ids;
        for (size_t i = 0; i < witness_ids.size() && i < MAX_WITNESS_COUNT; ++i) {
            if (witness_bitmap.test(i)) {
                active_witness_ids.push_back(witness_ids[i]);
            }
        }
        std::sort(active_witness_ids.begin(), active_witness_ids.end());

        std::vector<std::vector<uint8_t>> witness_id_hashes;
        for (const auto& witness_id : active_witness_ids) {
            std::vector<uint8_t> id_bytes(witness_id.begin(), witness_id.end());
            Hash256 id_hash = SHA3::hash(id_bytes);
            witness_id_hashes.push_back(std::vector<uint8_t>(id_hash.begin(), id_hash.end()));
        }

        // Compute Merkle root
        std::vector<uint8_t> merkle_input;
        for (const auto& id_hash : witness_id_hashes) {
            merkle_input.insert(merkle_input.end(), id_hash.begin(), id_hash.end());
        }
        Hash256 witness_merkle_root = SHA3::hash(merkle_input);
        result.witness_merkle_root = witness_merkle_root;

        std::cout << "[TEE Attestquorum] Witness Merkle root: "
                  << hashToHexString(witness_merkle_root).substr(0, 16) << "...\n";

        // Step 2: Serialize witness_bitmap for signing
        // Convert bitset to byte array (compact representation)
        std::vector<uint8_t> bitmap_bytes;
        size_t num_bytes = (MAX_WITNESS_COUNT + 7) / 8;  // Round up to nearest byte
        bitmap_bytes.resize(num_bytes, 0);

        for (size_t i = 0; i < MAX_WITNESS_COUNT; ++i) {
            if (witness_bitmap.test(i)) {
                bitmap_bytes[i / 8] |= (1 << (i % 8));
            }
        }

        std::cout << "[TEE Attestquorum] Witness bitmap: "
                  << witness_count << " bits set (" << bitmap_bytes.size() << " bytes)\n";

        // Step 3: Generate attestquorum signature
        // TEE signs: H(block_header || bitmap)
        // NOTE: We do NOT sign MACs - they are temporary and not stored
        Hash256 header_hash = block_header.computeHeaderHash();

        std::vector<uint8_t> attestquorum_input;
        attestquorum_input.reserve(32 + bitmap_bytes.size());
        attestquorum_input.insert(attestquorum_input.end(),
                                 header_hash.begin(), header_hash.end());
        attestquorum_input.insert(attestquorum_input.end(),
                                 bitmap_bytes.begin(), bitmap_bytes.end());

        // TEE signs with ECDSA (secp256r1 / P-256)
        // This produces ~70 bytes signature (much smaller than FALCON-512's 690 bytes)
        std::vector<uint8_t> attestquorum_sig = getTEESigner().sign(attestquorum_input);

        if (attestquorum_sig.empty()) {
            result.failure_reason = "TEE ECDSA signing failed";
            result.generation_time_ms = getElapsedMs(start_time);
            std::cerr << "[TEE Attestquorum] ✗ ECDSA signing failed\n";
            return result;
        }

        result.attestquorum = attestquorum_sig;
        result.witness_count = witness_count;
        result.success = true;
        result.generation_time_ms = getElapsedMs(start_time);

        size_t old_size = witness_count * 690;  // FALCON-512 signatures
        size_t new_size = attestquorum_sig.size();  // ECDSA signature
        size_t savings = old_size - new_size;

        std::cout << "[TEE Attestquorum] ✓ Attestquorum generated in "
                  << result.generation_time_ms << "ms\n";
        std::cout << "[TEE Attestquorum]   ECDSA signature size: "
                  << attestquorum_sig.size() << " bytes\n";
        std::cout << "[TEE Attestquorum]   Block size reduction: ~"
                  << savings << " bytes saved (vs " << witness_count
                  << " FALCON-512 sigs)\n";
        std::cout << "[TEE Attestquorum]   NOTE: Vote MACs NOT stored in block\n";

        return result;
    }

private:
    /**
     * TEE ECDSA Signer Helper Class
     * Simulates hardware TEE ECDSA signatures (e.g., Intel SGX, ARM TrustZone)
     * Uses secp256r1 (P-256) curve for ~70 byte signatures
     */
    class TEEECDSASigner {
    private:
        EVP_PKEY* pkey_;
        EVP_PKEY_CTX* pkey_ctx_;

    public:
        TEEECDSASigner() : pkey_(nullptr), pkey_ctx_(nullptr) {
            // Generate EC key pair (secp256r1 / P-256)
            pkey_ctx_ = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!pkey_ctx_) {
                std::cerr << "[TEE ECDSA] Failed to create PKEY context\n";
                return;
            }

            if (EVP_PKEY_keygen_init(pkey_ctx_) <= 0) {
                std::cerr << "[TEE ECDSA] Failed to init keygen\n";
                return;
            }

            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx_, NID_X9_62_prime256v1) <= 0) {
                std::cerr << "[TEE ECDSA] Failed to set curve\n";
                return;
            }

            if (EVP_PKEY_keygen(pkey_ctx_, &pkey_) <= 0) {
                std::cerr << "[TEE ECDSA] Failed to generate key\n";
                pkey_ = nullptr;
            }
        }

        ~TEEECDSASigner() {
            if (pkey_) EVP_PKEY_free(pkey_);
            if (pkey_ctx_) EVP_PKEY_CTX_free(pkey_ctx_);
        }

        /**
         * Sign data with TEE ECDSA key
         * Returns DER-encoded ECDSA signature (~70-72 bytes for P-256)
         */
        std::vector<uint8_t> sign(const std::vector<uint8_t>& data) {
            if (!pkey_) {
                std::cerr << "[TEE ECDSA] No key available for signing\n";
                return std::vector<uint8_t>();
            }

            // Hash data with SHA-256
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(data.data(), data.size(), hash);

            // Create signing context
            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            if (!md_ctx) {
                std::cerr << "[TEE ECDSA] Failed to create MD context\n";
                return std::vector<uint8_t>();
            }

            // Initialize signing
            if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey_) <= 0) {
                std::cerr << "[TEE ECDSA] Failed to init signing\n";
                EVP_MD_CTX_free(md_ctx);
                return std::vector<uint8_t>();
            }

            // Determine signature length
            size_t sig_len = 0;
            if (EVP_DigestSign(md_ctx, nullptr, &sig_len, hash, SHA256_DIGEST_LENGTH) <= 0) {
                std::cerr << "[TEE ECDSA] Failed to determine signature length\n";
                EVP_MD_CTX_free(md_ctx);
                return std::vector<uint8_t>();
            }

            // Allocate buffer and sign
            std::vector<uint8_t> signature(sig_len);
            if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, hash, SHA256_DIGEST_LENGTH) <= 0) {
                std::cerr << "[TEE ECDSA] Failed to sign\n";
                EVP_MD_CTX_free(md_ctx);
                return std::vector<uint8_t>();
            }

            signature.resize(sig_len);
            EVP_MD_CTX_free(md_ctx);

            return signature;
        }

        /**
         * Verify ECDSA signature
         */
        bool verify(const std::vector<uint8_t>& data,
                   const std::vector<uint8_t>& signature) {
            if (!pkey_) return false;

            // Hash data with SHA-256
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(data.data(), data.size(), hash);

            // Create verification context
            EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
            if (!md_ctx) return false;

            // Initialize verification
            if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey_) <= 0) {
                EVP_MD_CTX_free(md_ctx);
                return false;
            }

            // Verify signature
            int result = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                                         hash, SHA256_DIGEST_LENGTH);
            EVP_MD_CTX_free(md_ctx);

            return result == 1;
        }
    };

    // Singleton TEE ECDSA signer (simulates hardware TEE)
    static TEEECDSASigner& getTEESigner() {
        static TEEECDSASigner signer;
        return signer;
    }

    /**
     * Verify FALCON-512 signature
     * Wrapper for signature verification
     */
    bool verifyFalconSignature(
            const Hash256& header_hash,
            const std::vector<uint8_t>& signature,
            const std::vector<uint8_t>& public_key) {

        // Convert hash to vector for verification
        std::vector<uint8_t> hash_vec(header_hash.begin(), header_hash.end());

        // Create temporary signer for verification
        FalconSigner verifier;

        // Verify signature
        return verifier.verify(hash_vec, signature, public_key);
    }

    /**
     * Convert hash to hex string for logging
     */
    std::string hashToHexString(const Hash256& hash) const {
        std::string result;
        result.reserve(64);
        for (uint8_t byte : hash) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", byte);
            result += hex;
        }
        return result;
    }

    /**
     * Get elapsed time in milliseconds
     */
    double getElapsedMs(
            const std::chrono::high_resolution_clock::time_point& start) const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(now - start).count();
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_TEE_AGGREGATOR_H
