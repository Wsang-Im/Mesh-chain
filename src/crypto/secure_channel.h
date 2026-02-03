#ifndef MESHCHAIN_SECURE_CHANNEL_H
#define MESHCHAIN_SECURE_CHANNEL_H

#include "../common/types.h"
#include "../common/block.h"
#include "../common/merkle_tree.h"
#include "liboqs_wrapper.h"
#include <vector>
#include <memory>
#include <cstring>
#include <array>
#include <random>

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

namespace meshchain {
namespace crypto {

/**
 * Secure Channel using ML-KEM + AEAD
 *
 * Purpose: Protect signature request messages from eavesdropping
 *
 * Protocol flow:
 * 1. Each witness generates ML-KEM-768 keypair, publishes public key
 * 2. Creator encapsulates to witness's public key → (ciphertext, shared_secret)
 * 3. Creator sends: ciphertext || AEAD_encrypt(shared_secret, sig_req_data)
 * 4. Witness decapsulates ciphertext → shared_secret
 * 5. Witness decrypts: AEAD_decrypt(shared_secret, encrypted_data) → sig_req_data
 *
 * Security properties:
 * - Forward secrecy: New shared secret per message
 * - Authenticated encryption: Prevents tampering
 * - Post-quantum secure: Based on ML-KEM (Kyber)
 */

/**
 * AEAD (Authenticated Encryption with Associated Data)
 *
 * Using XChaCha20-Poly1305:
 * - 256-bit key
 * - 192-bit nonce (24 bytes)
 * - 128-bit authentication tag (16 bytes)
 *
 * In simulation: Simplified XOR-based encryption
 * In production: Use libsodium's crypto_aead_xchacha20poly1305_ietf_*
 */
class AEAD {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 24;
    static constexpr size_t TAG_SIZE = 16;

    struct EncryptedData {
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;

        std::vector<uint8_t> serialize() const {
            std::vector<uint8_t> bytes;
            bytes.reserve(NONCE_SIZE + ciphertext.size() + TAG_SIZE);

            bytes.insert(bytes.end(), nonce.begin(), nonce.end());
            bytes.insert(bytes.end(), ciphertext.begin(), ciphertext.end());
            bytes.insert(bytes.end(), tag.begin(), tag.end());

            return bytes;
        }

        static EncryptedData deserialize(const std::vector<uint8_t>& bytes) {
            if (bytes.size() < NONCE_SIZE + TAG_SIZE) {
                throw std::runtime_error("Invalid encrypted data size");
            }

            EncryptedData data;
            data.nonce.assign(bytes.begin(), bytes.begin() + NONCE_SIZE);

            size_t ciphertext_size = bytes.size() - NONCE_SIZE - TAG_SIZE;
            data.ciphertext.assign(bytes.begin() + NONCE_SIZE,
                                  bytes.begin() + NONCE_SIZE + ciphertext_size);

            data.tag.assign(bytes.end() - TAG_SIZE, bytes.end());

            return data;
        }
    };

    /**
     * Encrypt plaintext with AEAD
     *
     * @param key 32-byte encryption key (from ML-KEM shared secret)
     * @param plaintext Data to encrypt
     * @param associated_data Additional authenticated data (not encrypted)
     * @return Encrypted data with nonce and tag
     */
    static EncryptedData encrypt(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& associated_data = {}) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size");
        }

        EncryptedData data;
        data.nonce.resize(NONCE_SIZE);

#ifdef USE_LIBSODIUM
        // Initialize libsodium (safe to call multiple times)
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }

        // Generate random nonce
        randombytes_buf(data.nonce.data(), NONCE_SIZE);

        // Allocate space for ciphertext + tag
        data.ciphertext.resize(plaintext.size());
        data.tag.resize(TAG_SIZE);

        // Temporary buffer for ciphertext+tag (libsodium combines them)
        std::vector<uint8_t> ciphertext_and_tag(plaintext.size() + TAG_SIZE);
        unsigned long long ciphertext_len;

        // Encrypt with XChaCha20-Poly1305
        int ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext_and_tag.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            associated_data.empty() ? nullptr : associated_data.data(),
            associated_data.size(),
            nullptr,  // nsec (not used)
            data.nonce.data(),
            key.data()
        );

        if (ret != 0) {
            throw std::runtime_error("libsodium encryption failed");
        }

        // Split ciphertext and tag
        std::copy(ciphertext_and_tag.begin(),
                 ciphertext_and_tag.begin() + plaintext.size(),
                 data.ciphertext.begin());
        std::copy(ciphertext_and_tag.begin() + plaintext.size(),
                 ciphertext_and_tag.end(),
                 data.tag.begin());

#else
        // Simulation mode: Generate random nonce
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < NONCE_SIZE; ++i) {
            data.nonce[i] = static_cast<uint8_t>(dis(gen));
        }

        // Simplified encryption (XOR with keystream)
        data.ciphertext.resize(plaintext.size());
        for (size_t i = 0; i < plaintext.size(); ++i) {
            data.ciphertext[i] = plaintext[i] ^
                                key[i % KEY_SIZE] ^
                                data.nonce[i % NONCE_SIZE];
        }

        // Simplified MAC
        data.tag.resize(TAG_SIZE);
        Hash256 hash = {};
        for (size_t i = 0; i < plaintext.size(); ++i) {
            hash[i % 32] ^= plaintext[i];
        }
        for (size_t i = 0; i < associated_data.size(); ++i) {
            hash[i % 32] ^= associated_data[i];
        }
        for (size_t i = 0; i < KEY_SIZE; ++i) {
            hash[i % 32] ^= key[i];
        }
        std::copy(hash.begin(), hash.begin() + TAG_SIZE, data.tag.begin());
#endif

        return data;
    }

    /**
     * Decrypt ciphertext with AEAD
     *
     * @param key 32-byte decryption key
     * @param encrypted Encrypted data
     * @param associated_data Additional authenticated data
     * @return Decrypted plaintext
     * @throws std::runtime_error if authentication fails
     */
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key,
                                        const EncryptedData& encrypted,
                                        const std::vector<uint8_t>& associated_data = {}) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size");
        }

        std::vector<uint8_t> plaintext;

#ifdef USE_LIBSODIUM
        // Initialize libsodium (safe to call multiple times)
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }

        // Combine ciphertext and tag for libsodium
        std::vector<uint8_t> ciphertext_and_tag;
        ciphertext_and_tag.reserve(encrypted.ciphertext.size() + encrypted.tag.size());
        ciphertext_and_tag.insert(ciphertext_and_tag.end(),
                                  encrypted.ciphertext.begin(),
                                  encrypted.ciphertext.end());
        ciphertext_and_tag.insert(ciphertext_and_tag.end(),
                                  encrypted.tag.begin(),
                                  encrypted.tag.end());

        // Allocate space for plaintext
        plaintext.resize(encrypted.ciphertext.size());
        unsigned long long plaintext_len;

        // Decrypt with XChaCha20-Poly1305
        int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // nsec (not used)
            ciphertext_and_tag.data(), ciphertext_and_tag.size(),
            associated_data.empty() ? nullptr : associated_data.data(),
            associated_data.size(),
            encrypted.nonce.data(),
            key.data()
        );

        if (ret != 0) {
            throw std::runtime_error("AEAD authentication failed - message tampered");
        }

        plaintext.resize(plaintext_len);

#else
        // Simulation mode: Decrypt
        plaintext.resize(encrypted.ciphertext.size());
        for (size_t i = 0; i < encrypted.ciphertext.size(); ++i) {
            plaintext[i] = encrypted.ciphertext[i] ^
                          key[i % KEY_SIZE] ^
                          encrypted.nonce[i % NONCE_SIZE];
        }

        // Verify MAC
        Hash256 hash = {};
        for (size_t i = 0; i < plaintext.size(); ++i) {
            hash[i % 32] ^= plaintext[i];
        }
        for (size_t i = 0; i < associated_data.size(); ++i) {
            hash[i % 32] ^= associated_data[i];
        }
        for (size_t i = 0; i < KEY_SIZE; ++i) {
            hash[i % 32] ^= key[i];
        }

        // Compare tag
        for (size_t i = 0; i < TAG_SIZE; ++i) {
            if (encrypted.tag[i] != hash[i]) {
                throw std::runtime_error("AEAD authentication failed - message tampered");
            }
        }
#endif

        return plaintext;
    }
};

/**
 * Signature Request Message (transmitted over secure channel)
 *
 * Contains everything witness needs to verify and sign:
 * - Block header
 * - Diversity certificate
 * - ToF transcript
 * - Merkle path proving witness membership
 */
struct SignatureRequest {
    BlockHeader header;
    DiversityCert diversity_cert;
    DiversityMetrics diversity_metrics;  // Added: full metrics for witness verification
    ToFTranscript tof_transcript;
    MerklePath merkle_path;
    std::string witness_id;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        bytes.reserve(8192);  // Typical size

        // Serialize header (simplified)
        bytes.insert(bytes.end(), header.prev_hash.begin(), header.prev_hash.end());
        bytes.insert(bytes.end(), header.witness_set_commit.begin(), header.witness_set_commit.end());
        bytes.insert(bytes.end(), header.diversity_cert.begin(), header.diversity_cert.end());

        // Serialize creator signature
        uint16_t sig_len = static_cast<uint16_t>(header.creator_sig.size());
        const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&sig_len);
        bytes.insert(bytes.end(), len_ptr, len_ptr + sizeof(uint16_t));
        bytes.insert(bytes.end(), header.creator_sig.begin(), header.creator_sig.end());

        // Serialize ToF transcript
        uint64_t nonce = header.nonce;
        const uint8_t* nonce_ptr = reinterpret_cast<const uint8_t*>(&nonce);
        bytes.insert(bytes.end(), nonce_ptr, nonce_ptr + sizeof(uint64_t));

        // Serialize DiversityMetrics
        const uint8_t* hm_ptr = reinterpret_cast<const uint8_t*>(&diversity_metrics.H_m);
        bytes.insert(bytes.end(), hm_ptr, hm_ptr + sizeof(double));

        const uint8_t* dmin_ptr = reinterpret_cast<const uint8_t*>(&diversity_metrics.d_min);
        bytes.insert(bytes.end(), dmin_ptr, dmin_ptr + sizeof(double));

        const uint8_t* mad_ptr = reinterpret_cast<const uint8_t*>(&diversity_metrics.MAD_t);
        bytes.insert(bytes.end(), mad_ptr, mad_ptr + sizeof(double));

        const uint8_t* minr_ptr = reinterpret_cast<const uint8_t*>(&diversity_metrics.min_R);
        bytes.insert(bytes.end(), minr_ptr, minr_ptr + sizeof(double));

        // R_profile size and values
        uint16_t r_profile_size = static_cast<uint16_t>(diversity_metrics.R_profile.size());
        const uint8_t* rsize_ptr = reinterpret_cast<const uint8_t*>(&r_profile_size);
        bytes.insert(bytes.end(), rsize_ptr, rsize_ptr + sizeof(uint16_t));

        for (double r : diversity_metrics.R_profile) {
            const uint8_t* r_ptr = reinterpret_cast<const uint8_t*>(&r);
            bytes.insert(bytes.end(), r_ptr, r_ptr + sizeof(double));
        }

        // Serialize Merkle path
        bytes.push_back(static_cast<uint8_t>(merkle_path.siblings.size()));
        for (const auto& sibling : merkle_path.siblings) {
            bytes.insert(bytes.end(), sibling.begin(), sibling.end());
        }
        for (bool dir : merkle_path.directions) {
            bytes.push_back(dir ? 1 : 0);
        }

        // Witness ID
        bytes.insert(bytes.end(), witness_id.begin(), witness_id.end());
        bytes.push_back(0);  // null terminator

        return bytes;
    }

    // Simplified deserialization (full implementation needed for production)
    static SignatureRequest deserialize(const std::vector<uint8_t>& bytes) {
        SignatureRequest req;
        // ... deserialization logic ...
        // (Omitted for brevity - would parse all fields)
        return req;
    }
};

/**
 * Secure Channel Manager
 *
 * Manages ML-KEM key exchange and AEAD encryption for sig_req messages
 */
class SecureChannel {
private:
    std::unique_ptr<MLKEM> kem_;
    std::string node_id_;

public:
    explicit SecureChannel(const std::string& node_id) : node_id_(node_id) {
        kem_ = std::make_unique<MLKEM>();
        kem_->generateKeys();
    }

    /**
     * Get this node's public key for key exchange
     */
    std::vector<uint8_t> getPublicKey() const {
        return kem_->getPublicKey();
    }

    /**
     * Encrypt signature request to witness (creator side)
     *
     * @param sig_req Signature request message
     * @param witness_public_key Witness's ML-KEM public key
     * @return (kem_ciphertext, encrypted_message)
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptSigRequest(
            const SignatureRequest& sig_req,
            const std::vector<uint8_t>& witness_public_key) {

        // 1. Encapsulate to witness's public key
        auto [kem_ciphertext, shared_secret] = kem_->encapsulate(witness_public_key);

        // 2. Derive AEAD key from shared secret (KDF)
        // In production: use HKDF-SHA256
        std::vector<uint8_t> aead_key = deriveKey(shared_secret);

        // 3. Serialize signature request
        std::vector<uint8_t> plaintext = sig_req.serialize();

        // 4. Encrypt with AEAD
        // Associated data: witness_id to prevent replay attacks
        std::vector<uint8_t> associated_data(sig_req.witness_id.begin(),
                                            sig_req.witness_id.end());
        auto encrypted = AEAD::encrypt(aead_key, plaintext, associated_data);

        // 5. Return (kem_ciphertext, encrypted_message)
        return {kem_ciphertext, encrypted.serialize()};
    }

    /**
     * Decrypt signature request (witness side)
     *
     * @param kem_ciphertext ML-KEM ciphertext from creator
     * @param encrypted_message AEAD-encrypted signature request
     * @param expected_witness_id This witness's ID (for replay protection)
     * @return Decrypted signature request
     */
    SignatureRequest decryptSigRequest(
            const std::vector<uint8_t>& kem_ciphertext,
            const std::vector<uint8_t>& encrypted_message,
            const std::string& expected_witness_id) {

        // 1. Decapsulate to get shared secret
        std::vector<uint8_t> shared_secret = kem_->decapsulate(kem_ciphertext);

        // 2. Derive AEAD key
        std::vector<uint8_t> aead_key = deriveKey(shared_secret);

        // 3. Parse encrypted data
        auto encrypted = AEAD::EncryptedData::deserialize(encrypted_message);

        // 4. Decrypt with AEAD
        std::vector<uint8_t> associated_data(expected_witness_id.begin(),
                                            expected_witness_id.end());
        std::vector<uint8_t> plaintext = AEAD::decrypt(aead_key, encrypted, associated_data);

        // 5. Deserialize signature request
        SignatureRequest sig_req = SignatureRequest::deserialize(plaintext);

        // 6. Verify witness ID matches
        if (sig_req.witness_id != expected_witness_id) {
            throw std::runtime_error("Witness ID mismatch - possible replay attack");
        }

        return sig_req;
    }

private:
    /**
     * Derive AEAD key from ML-KEM shared secret
     *
     * In production: use HKDF-SHA256
     * Here: simplified hash expansion
     */
    std::vector<uint8_t> deriveKey(const std::vector<uint8_t>& shared_secret) const {
        std::vector<uint8_t> key(AEAD::KEY_SIZE);

        // Simplified KDF - in production use HKDF
        Hash256 hash = {};
        for (size_t i = 0; i < shared_secret.size(); ++i) {
            hash[i % 32] ^= shared_secret[i];
        }

        std::copy(hash.begin(), hash.begin() + AEAD::KEY_SIZE, key.begin());
        return key;
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_SECURE_CHANNEL_H
