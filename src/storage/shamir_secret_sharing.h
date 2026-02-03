#ifndef MESHCHAIN_SHAMIR_SECRET_SHARING_H
#define MESHCHAIN_SHAMIR_SECRET_SHARING_H

#include "../common/types.h"
#include "../crypto/secure_channel.h"  // For AEAD
#include <vector>
#include <random>
#include <stdexcept>
#include <algorithm>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <thread>

namespace meshchain {
namespace storage {

/**
 * Shamir Secret Sharing Implementation
 *
 * Used for off-chain payload storage as per paper Section 2.3:
 * - Split encrypted payload into n shares
 * - Require t shares to reconstruct
 * - Distribute shares across storage tiers (hot/warm/cold)
 *
 * Mathematical background:
 * - Based on polynomial interpolation over GF(256)
 * - Secret s is the constant term of polynomial P(x)
 * - Shares are (x_i, P(x_i)) for different x_i
 * - Any t shares can reconstruct P(x) via Lagrange interpolation
 *
 * Security: As long as < t shares are compromised, secret is information-theoretically secure
 */

/**
 * Galois Field GF(256) arithmetic for Shamir's scheme
 */
class GF256 {
private:
    // Pre-computed logarithm and exponential tables for GF(256)
    // Generator polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
    static constexpr uint16_t POLY = 0x11B;
    inline static uint8_t exp_table[512] = {};
    inline static uint8_t log_table[256] = {};
    inline static bool tables_initialized = false;

public:
    static void initializeTables() {
        if (tables_initialized) return;

        // Use 0x03 as the generator (primitive element for polynomial 0x11B)
        uint16_t x = 1;

        for (int i = 0; i < 255; ++i) {
            exp_table[i] = static_cast<uint8_t>(x);
            log_table[x] = static_cast<uint8_t>(i);

            // Multiply by 3 in GF(256): x *= 3 = x * (2 + 1) = (x * 2) + x
            uint16_t x2 = x << 1;  // x * 2
            if (x2 & 0x100) {
                x2 ^= POLY;
            }
            x = (x2 ^ x) & 0xFF;  // (x * 2) + x = x * 3
        }

        // Extend exp table for easier implementation
        for (int i = 255; i < 512; ++i) {
            exp_table[i] = exp_table[i - 255];
        }

        tables_initialized = true;
    }

    // Multiply two elements in GF(256)
    static uint8_t multiply(uint8_t a, uint8_t b) {
        if (a == 0 || b == 0) return 0;
        return exp_table[log_table[a] + log_table[b]];
    }

    // Divide two elements in GF(256)
    static uint8_t divide(uint8_t a, uint8_t b) {
        if (a == 0) return 0;
        if (b == 0) throw std::invalid_argument("Division by zero in GF(256)");
        return exp_table[(log_table[a] + 255 - log_table[b]) % 255];
    }

    // Add (XOR in GF(2^8))
    static uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }

    // Subtract (same as add in GF(2^8))
    static uint8_t subtract(uint8_t a, uint8_t b) {
        return a ^ b;
    }
};

/**
 * Shamir Secret Share
 */
struct ShamirShare {
    uint8_t x;  // Share index (1-255)
    std::vector<uint8_t> y;  // Share data

    size_t size() const {
        return 1 + y.size();  // x + y data
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        bytes.push_back(x);
        bytes.insert(bytes.end(), y.begin(), y.end());
        return bytes;
    }

    static ShamirShare deserialize(const std::vector<uint8_t>& bytes) {
        if (bytes.empty()) {
            throw std::invalid_argument("Empty share data");
        }

        ShamirShare share;
        share.x = bytes[0];
        share.y.assign(bytes.begin() + 1, bytes.end());
        return share;
    }
};

/**
 * Shamir Secret Sharing Scheme
 */
class ShamirSecretSharing {
private:
    size_t threshold_;  // t
    size_t total_shares_;  // n
    std::mt19937 rng_;

public:
    ShamirSecretSharing(size_t threshold, size_t total_shares)
        : threshold_(threshold), total_shares_(total_shares) {

        if (threshold < 2 || threshold > 255) {
            throw std::invalid_argument("Threshold must be in [2, 255]");
        }
        if (total_shares < threshold || total_shares > 255) {
            throw std::invalid_argument("Total shares must be in [threshold, 255]");
        }

        GF256::initializeTables();

        std::random_device rd;
        rng_.seed(rd());
    }

    /**
     * Split secret into n shares where t are needed to reconstruct
     *
     * @param secret The secret data to split
     * @return Vector of n shares
     */
    std::vector<ShamirShare> split(const std::vector<uint8_t>& secret) {
        if (secret.empty()) {
            throw std::invalid_argument("Secret cannot be empty");
        }

        std::vector<ShamirShare> shares(total_shares_);

        // Initialize share indices
        for (size_t i = 0; i < total_shares_; ++i) {
            shares[i].x = static_cast<uint8_t>(i + 1);
            shares[i].y.resize(secret.size());
        }

        // For each byte of the secret, create a polynomial and evaluate
        // Use thread-local RNG for thread-safety
        thread_local std::mt19937 local_rng(
            std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
            std::chrono::steady_clock::now().time_since_epoch().count()
        );

        for (size_t byte_idx = 0; byte_idx < secret.size(); ++byte_idx) {
            // Create random polynomial of degree (threshold - 1)
            // P(x) = secret[byte_idx] + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
            std::vector<uint8_t> coefficients(threshold_);
            coefficients[0] = secret[byte_idx];  // Constant term = secret

            // Random coefficients for terms x^1 to x^{t-1}
            std::uniform_int_distribution<int> dist(0, 255);
            for (size_t i = 1; i < threshold_; ++i) {
                coefficients[i] = static_cast<uint8_t>(dist(local_rng));
            }

            // Evaluate polynomial at each share point
            for (size_t share_idx = 0; share_idx < total_shares_; ++share_idx) {
                uint8_t x = shares[share_idx].x;
                uint8_t y = evaluatePolynomial(coefficients, x);
                shares[share_idx].y[byte_idx] = y;
            }
        }

        return shares;
    }

    /**
     * Reconstruct secret from t or more shares
     *
     * @param shares Vector of at least t shares
     * @return Reconstructed secret
     */
    std::vector<uint8_t> reconstruct(const std::vector<ShamirShare>& shares) {
        if (shares.size() < threshold_) {
            throw std::invalid_argument("Insufficient shares for reconstruction");
        }

        // Verify all shares have the same length
        size_t secret_length = shares[0].y.size();
        for (const auto& share : shares) {
            if (share.y.size() != secret_length) {
                throw std::invalid_argument("Shares have inconsistent lengths");
            }
        }

        // Use only first t shares (extras are ignored)
        std::vector<ShamirShare> active_shares(shares.begin(),
                                               shares.begin() + threshold_);

        std::vector<uint8_t> secret(secret_length);

        // Reconstruct each byte using Lagrange interpolation
        for (size_t byte_idx = 0; byte_idx < secret_length; ++byte_idx) {
            secret[byte_idx] = lagrangeInterpolate(active_shares, byte_idx);
        }

        return secret;
    }

    size_t getThreshold() const { return threshold_; }
    size_t getTotalShares() const { return total_shares_; }

private:
    /**
     * Evaluate polynomial at point x using Horner's method
     */
    uint8_t evaluatePolynomial(const std::vector<uint8_t>& coefficients, uint8_t x) const {
        if (coefficients.empty()) return 0;

        // Horner's method: P(x) = a_0 + x(a_1 + x(a_2 + ... ))
        uint8_t result = coefficients.back();
        for (int i = static_cast<int>(coefficients.size()) - 2; i >= 0; --i) {
            result = GF256::add(
                GF256::multiply(result, x),
                coefficients[i]
            );
        }

        return result;
    }

    /**
     * Lagrange interpolation to find P(0)
     *
     * P(0) = sum_{i=0}^{t-1} y_i * product_{j!=i} (x_j / (x_j - x_i))
     */
    uint8_t lagrangeInterpolate(const std::vector<ShamirShare>& shares, size_t byte_idx) const {
        uint8_t secret = 0;

        for (size_t i = 0; i < shares.size(); ++i) {
            uint8_t y_i = shares[i].y[byte_idx];
            uint8_t x_i = shares[i].x;

            // Compute Lagrange basis polynomial L_i(0)
            uint8_t basis = 1;  // L_i(0)

            for (size_t j = 0; j < shares.size(); ++j) {
                if (i == j) continue;

                uint8_t x_j = shares[j].x;

                // basis *= x_j / (x_i - x_j)
                // Lagrange basis polynomial: L_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
                // In GF(256), 0 - x_j = x_j (characteristic 2)
                uint8_t numerator = x_j;
                uint8_t denominator = GF256::subtract(x_i, x_j);  // x_i - x_j

                basis = GF256::multiply(
                    basis,
                    GF256::divide(numerator, denominator)
                );
            }

            // secret += y_i * basis
            secret = GF256::add(
                secret,
                GF256::multiply(y_i, basis)
            );
        }

        return secret;
    }
};

/**
 * Off-chain storage manager using Shamir Secret Sharing
 *
 * Implements the tiered storage from paper:
 * - Hot tier (5 min): Keep all shares in memory
 * - Warm tier (5 min - 1 hour): Distribute to nearby RSUs
 * - Cold tier (> 1 hour): Archive to cloud/IPFS with reduced redundancy
 *
 * Security Architecture:
 * 1. Generate random AEAD key K
 * 2. Encrypt payload P with XChaCha20-Poly1305: E_K(P) → C
 * 3. Split K using Shamir (t,n): K → {S1, S2, ..., Sn}
 * 4. Store encrypted payload C (replicated across storage nodes)
 * 5. Distribute key shares {Si} to different nodes
 * 6. To retrieve: gather t shares → reconstruct K → decrypt C → verify hash
 *
 * This provides:
 * - Confidentiality: C is useless without K
 * - Availability: Any t shares can reconstruct K
 * - Integrity: Hash verification detects tampering
 */
class OffChainStorage {
private:
    size_t threshold_;
    size_t total_shares_;
    std::unique_ptr<ShamirSecretSharing> sss_;

    // Simulated storage for encrypted payloads (in production: distributed storage)
    std::unordered_map<std::string, std::vector<uint8_t>> encrypted_storage_;
    // Simulated storage for key shares (in production: separate storage tier)
    std::unordered_map<std::string, ShamirShare> key_share_storage_;

    std::mt19937 rng_;

public:
    struct StorageConfig {
        size_t threshold;      // t shares needed (default: 3)
        size_t total_shares;   // n shares created (default: 5)
        std::string tier;      // "hot", "warm", "cold"
    };

    explicit OffChainStorage(const StorageConfig& config)
        : threshold_(config.threshold), total_shares_(config.total_shares) {

        sss_ = std::make_unique<ShamirSecretSharing>(threshold_, total_shares_);

        std::random_device rd;
        rng_.seed(rd());
    }

    /**
     * Store payload off-chain with AEAD encryption and secret sharing
     *
     * @param payload Data to store (e.g., V2XRecord serialized)
     * @return DataPointer for on-chain reference
     */
    DataPointer store(const std::vector<uint8_t>& payload) {
        // 1. Generate random AEAD key (256-bit for XChaCha20-Poly1305)
        // Use thread-local RNG for thread-safety
        thread_local std::mt19937 local_rng(
            std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
            std::chrono::steady_clock::now().time_since_epoch().count()
        );

        std::vector<uint8_t> aead_key(crypto::AEAD::KEY_SIZE);
        std::uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < aead_key.size(); ++i) {
            aead_key[i] = static_cast<uint8_t>(dist(local_rng));
        }

        // 2. Encrypt payload with XChaCha20-Poly1305 AEAD
        auto encrypted = crypto::AEAD::encrypt(aead_key, payload);
        std::vector<uint8_t> encrypted_payload = encrypted.serialize();

        // 3. Split AEAD key (not payload!) using Shamir
        auto key_shares = sss_->split(aead_key);

        // 4. Generate unique storage ID from payload hash
        Hash256 payload_hash = computeHash(payload);
        std::string storage_id = hashToString(payload_hash);

        // 5. Store encrypted payload (in production: replicate across storage nodes)
        encrypted_storage_[storage_id] = encrypted_payload;

        // 6. Distribute key shares to different storage nodes
        DataPointer ptr;
        ptr.hash = payload_hash;
        ptr.tier = "hot";
        ptr.t = threshold_;
        ptr.n = total_shares_;

        for (size_t i = 0; i < key_shares.size(); ++i) {
            std::string share_location = "storage_node_" + std::to_string(i) +
                                        "/key_share_" + std::to_string(key_shares[i].x) +
                                        "/" + storage_id;
            ptr.share_locations.push_back(share_location);

            // Simulate storing key share (in production: send to storage node)
            key_share_storage_[share_location] = key_shares[i];
        }

        return ptr;
    }

    /**
     * Retrieve payload from off-chain storage
     *
     * @param ptr DataPointer from block
     * @return Reconstructed and decrypted payload
     */
    std::vector<uint8_t> retrieve(const DataPointer& ptr) {
        std::string storage_id = hashToString(ptr.hash);

        // 1. Retrieve encrypted payload
        auto it = encrypted_storage_.find(storage_id);
        if (it == encrypted_storage_.end()) {
            throw std::runtime_error("Encrypted payload not found in storage");
        }
        std::vector<uint8_t> encrypted_payload = it->second;

        // 2. Retrieve key shares (simulate fetching from t different nodes)
        std::vector<ShamirShare> available_shares;
        for (size_t i = 0; i < std::min(ptr.share_locations.size(), threshold_); ++i) {
            const std::string& location = ptr.share_locations[i];
            auto share_it = key_share_storage_.find(location);
            if (share_it != key_share_storage_.end()) {
                available_shares.push_back(share_it->second);
            }
        }

        // 3. Check if we have enough shares
        if (available_shares.size() < threshold_) {
            throw std::runtime_error(
                "Insufficient key shares: have " + std::to_string(available_shares.size()) +
                ", need " + std::to_string(threshold_)
            );
        }

        // 4. Reconstruct AEAD key from shares using Lagrange interpolation
        std::vector<uint8_t> aead_key = sss_->reconstruct(available_shares);

        // 5. Decrypt payload with reconstructed key
        auto encrypted = crypto::AEAD::EncryptedData::deserialize(encrypted_payload);
        std::vector<uint8_t> payload = crypto::AEAD::decrypt(aead_key, encrypted);

        // 6. Verify hash for integrity
        Hash256 computed_hash = computeHash(payload);
        if (computed_hash != ptr.hash) {
            throw std::runtime_error("Payload hash mismatch - data corrupted or tampered");
        }

        return payload;
    }

    /**
     * Retrieve with explicit shares (for testing/manual retrieval)
     */
    std::vector<uint8_t> retrieve(const DataPointer& ptr,
                                   const std::vector<ShamirShare>& available_shares) {
        std::string storage_id = hashToString(ptr.hash);

        if (available_shares.size() < threshold_) {
            throw std::runtime_error(
                "Insufficient shares: have " + std::to_string(available_shares.size()) +
                ", need " + std::to_string(threshold_)
            );
        }

        // Retrieve encrypted payload
        auto it = encrypted_storage_.find(storage_id);
        if (it == encrypted_storage_.end()) {
            throw std::runtime_error("Encrypted payload not found in storage");
        }

        // Reconstruct AEAD key from shares
        std::vector<uint8_t> aead_key = sss_->reconstruct(available_shares);

        // Decrypt
        auto encrypted = crypto::AEAD::EncryptedData::deserialize(it->second);
        std::vector<uint8_t> payload = crypto::AEAD::decrypt(aead_key, encrypted);

        // Verify hash
        Hash256 computed_hash = computeHash(payload);
        if (computed_hash != ptr.hash) {
            throw std::runtime_error("Payload hash mismatch - data corrupted");
        }

        return payload;
    }

private:
    Hash256 computeHash(const std::vector<uint8_t>& data) const {
        // Use real SHA3-256 for cryptographic integrity verification
        return crypto::SHA3::hash(data);
    }

    std::string hashToString(const Hash256& hash) const {
        std::stringstream ss;
        for (size_t i = 0; i < hash.size(); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(hash[i]);
        }
        return ss.str();
    }
};

} // namespace storage
} // namespace meshchain

#endif // MESHCHAIN_SHAMIR_SECRET_SHARING_H
