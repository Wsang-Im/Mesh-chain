#ifndef MESHCHAIN_SHA3_WRAPPER_H
#define MESHCHAIN_SHA3_WRAPPER_H

#include "../common/types.h"
#include <vector>
#include <cstring>
#include <stdexcept>

#ifdef USE_OPENSSL_SHA3
#include <openssl/evp.h>
#endif

namespace meshchain {
namespace crypto {

/**
 * SHA3-256 Wrapper
 * 
 * Uses OpenSSL 3.0+ for real SHA3-256 hashing
 * Falls back to simple XOR-based hashing in simulation mode
 */
class SHA3 {
public:
    static constexpr size_t HASH_SIZE = 32;  // 256 bits

    /**
     * Hash data with SHA3-256
     * 
     * @param data Input data to hash
     * @return 32-byte hash
     */
    static Hash256 hash(const std::vector<uint8_t>& data) {
        Hash256 result = {};

#ifdef USE_OPENSSL_SHA3
        // Use real SHA3-256 from OpenSSL
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        const EVP_MD* md = EVP_sha3_256();
        if (!md) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA3-256 not available");
        }

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA3-256 init failed");
        }

        if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA3-256 update failed");
        }

        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx, result.data(), &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA3-256 final failed");
        }

        EVP_MD_CTX_free(ctx);

        if (hash_len != HASH_SIZE) {
            throw std::runtime_error("Unexpected SHA3-256 hash size");
        }
#else
        // Simulation mode: Simple XOR-based hashing
        // NOT cryptographically secure, only for testing
        for (size_t i = 0; i < data.size(); ++i) {
            result[i % HASH_SIZE] ^= data[i];
        }
        
        // Add some mixing to make it slightly more robust
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            result[i] = static_cast<uint8_t>(
                (result[i] ^ (result[(i + 7) % HASH_SIZE])) + 
                (i * 13) % 256
            );
        }
#endif

        return result;
    }

    /**
     * Hash multiple data chunks (for streaming)
     */
    static Hash256 hash(const std::vector<std::vector<uint8_t>>& chunks) {
        std::vector<uint8_t> combined;
        for (const auto& chunk : chunks) {
            combined.insert(combined.end(), chunk.begin(), chunk.end());
        }
        return hash(combined);
    }

    /**
     * Hash a string
     */
    static Hash256 hash(const std::string& str) {
        std::vector<uint8_t> data(str.begin(), str.end());
        return hash(data);
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_SHA3_WRAPPER_H
