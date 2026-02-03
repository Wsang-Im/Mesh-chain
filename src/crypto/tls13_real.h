#ifndef MESHCHAIN_TLS13_REAL_H
#define MESHCHAIN_TLS13_REAL_H

/**
 * TLS 1.3 with Real OpenSSL Cryptography + ML-KEM
 *
 * Uses OpenSSL 3.0+ APIs for:
 * - HKDF (Key Derivation Function)
 * - HMAC (Message Authentication)
 * - AEAD (XChaCha20-Poly1305)
 *
 * Uses liboqs for:
 * - ML-KEM-768 (Post-Quantum Key Exchange)
 * - FALCON-512 (Post-Quantum Signatures)
 */

#include "../common/types.h"
#include "liboqs_wrapper.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <vector>
#include <memory>
#include <cstring>
#include <stdexcept>

namespace meshchain {
namespace crypto {

/**
 * Real TLS 1.3 Cryptographic Functions using OpenSSL
 *
 * Static utility class providing real HKDF, HMAC, and transcript hashing
 * for TLS 1.3 key schedule implementation.
 */
class TLS13RealCrypto {
public:
    /**
     * HKDF-Extract using OpenSSL
     */
    static std::vector<uint8_t> hkdfExtract(const std::vector<uint8_t>& salt,
                                            const std::vector<uint8_t>& ikm) {
        std::vector<uint8_t> prk(32);

        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!pctx) {
            throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        }

        if (EVP_PKEY_derive_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_derive_init failed");
        }

        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");
        }

        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed");
        }

        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");
        }

        if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_mode failed");
        }

        size_t outlen = prk.size();
        if (EVP_PKEY_derive(pctx, prk.data(), &outlen) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_derive (extract) failed");
        }

        EVP_PKEY_CTX_free(pctx);
        return prk;
    }

    /**
     * HKDF-Expand using OpenSSL
     */
    static std::vector<uint8_t> hkdfExpand(const std::vector<uint8_t>& prk,
                                           const std::vector<uint8_t>& info,
                                           size_t length) {
        std::vector<uint8_t> okm(length);

        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!pctx) {
            throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        }

        if (EVP_PKEY_derive_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_derive_init failed");
        }

        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");
        }

        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk.data(), prk.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");
        }

        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed");
        }

        if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_mode failed");
        }

        size_t outlen = okm.size();
        if (EVP_PKEY_derive(pctx, okm.data(), &outlen) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_derive (expand) failed");
        }

        EVP_PKEY_CTX_free(pctx);
        return okm;
    }

    /**
     * HKDF-Expand-Label (TLS 1.3 specific)
     */
    static std::vector<uint8_t> hkdfExpandLabel(const std::vector<uint8_t>& secret,
                                                const std::string& label,
                                                const std::vector<uint8_t>& context,
                                                size_t length) {
        // Build HkdfLabel structure
        std::vector<uint8_t> info;

        // Length (2 bytes)
        uint16_t len = static_cast<uint16_t>(length);
        info.push_back(static_cast<uint8_t>(len >> 8));
        info.push_back(static_cast<uint8_t>(len & 0xFF));

        // Label (prefixed with "tls13 ")
        std::string full_label = "tls13 " + label;
        info.push_back(static_cast<uint8_t>(full_label.size()));
        info.insert(info.end(), full_label.begin(), full_label.end());

        // Context
        info.push_back(static_cast<uint8_t>(context.size()));
        info.insert(info.end(), context.begin(), context.end());

        return hkdfExpand(secret, info, length);
    }

    /**
     * HMAC-SHA256 using OpenSSL
     */
    static std::vector<uint8_t> hmacSha256(const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result(32);
        unsigned int len = 0;

        if (!HMAC(EVP_sha256(), key.data(), key.size(),
                  data.data(), data.size(),
                  result.data(), &len)) {
            throw std::runtime_error("HMAC failed");
        }

        if (len != 32) {
            throw std::runtime_error("HMAC unexpected output size");
        }

        return result;
    }

    /**
     * Transcript Hash (SHA256)
     */
    static Hash256 transcriptHash(const std::vector<std::vector<uint8_t>>& messages) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }

        for (const auto& msg : messages) {
            if (EVP_DigestUpdate(ctx, msg.data(), msg.size()) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("EVP_DigestUpdate failed");
            }
        }

        Hash256 hash = {};
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestFinal_ex failed");
        }

        EVP_MD_CTX_free(ctx);

        if (hash_len != 32) {
            throw std::runtime_error("Unexpected hash size");
        }

        return hash;
    }

    /**
     * Compute Finished verify_data (RFC 8446 Section 4.4.4)
     *
     * finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
     * verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
     *
     * @param base_key Either client_handshake_traffic_secret or server_handshake_traffic_secret
     * @param handshake_context All handshake messages up to (but not including) this Finished
     * @return verify_data (32 bytes)
     */
    static std::vector<uint8_t> computeFinishedVerifyData(
            const std::vector<uint8_t>& base_key,
            const std::vector<std::vector<uint8_t>>& handshake_context) {

        // Step 1: finished_key = HKDF-Expand-Label(base_key, "finished", "", 32)
        std::vector<uint8_t> finished_key = hkdfExpandLabel(base_key, "finished", {}, 32);

        // Step 2: Transcript-Hash(handshake_context)
        Hash256 transcript_hash = transcriptHash(handshake_context);
        std::vector<uint8_t> transcript_vec(transcript_hash.begin(), transcript_hash.end());

        // Step 3: verify_data = HMAC(finished_key, transcript_hash)
        return hmacSha256(finished_key, transcript_vec);
    }

    /**
     * Generate cryptographically secure random bytes using OpenSSL
     */
    static std::vector<uint8_t> generateRandom(size_t length) {
        std::vector<uint8_t> random(length);
        if (RAND_bytes(random.data(), length) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        return random;
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_TLS13_REAL_H
