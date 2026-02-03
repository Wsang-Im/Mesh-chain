#ifndef MESHCHAIN_LIBOQS_WRAPPER_H
#define MESHCHAIN_LIBOQS_WRAPPER_H

#include "../common/types.h"
#include <memory>
#include <vector>
#include <string>
#include <stdexcept>

// Forward declarations for liboqs
#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#else
// Dummy definitions when liboqs is not available
struct OQS_SIG { char dummy; };
struct OQS_KEM { char dummy; };
#endif

namespace meshchain {
namespace crypto {

/**
 * liboqs Wrapper for PQC Cryptography
 *
 * Implements the paper's crypto requirements:
 * - FALCON-512: Vehicle signatures (fast path)
 * - ML-DSA-65 (Dilithium3): RSU/Anchor signatures
 * - ML-KEM-768: Key encapsulation for TLS-like secure channels
 *
 * All using NIST-standardized post-quantum algorithms
 */

/**
 * FALCON-512 Signature Wrapper
 *
 * Properties:
 * - Signature size: ~690 bytes
 * - Public key: ~897 bytes
 * - Fast signing: <1ms on embedded processors
 * - Used for: Vehicle block signatures, witness signatures
 */
class FalconSigner {
private:
#ifdef USE_LIBOQS
    OQS_SIG *sig_;
#endif
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> secret_key_;
    bool keys_generated_;

public:
    FalconSigner() : keys_generated_(false) {
#ifdef USE_LIBOQS
        sig_ = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        if (sig_ == nullptr) {
            throw std::runtime_error("Failed to initialize FALCON-512");
        }
#endif
    }

    ~FalconSigner() {
#ifdef USE_LIBOQS
        if (sig_) {
            OQS_SIG_free(sig_);
        }
#endif
    }

    // Generate keypair
    void generateKeys() {
#ifdef USE_LIBOQS
        public_key_.resize(sig_->length_public_key);
        secret_key_.resize(sig_->length_secret_key);

        if (OQS_SIG_keypair(sig_, public_key_.data(), secret_key_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("FALCON-512 key generation failed");
        }
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        keys_generated_ = true;
    }

    // Sign message
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) {
        if (!keys_generated_) {
            throw std::runtime_error("Keys not generated");
        }

#ifdef USE_LIBOQS
        std::vector<uint8_t> signature(sig_->length_signature);
        size_t sig_len = 0;

        if (OQS_SIG_sign(sig_, signature.data(), &sig_len,
                        message.data(), message.size(),
                        secret_key_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("FALCON-512 signing failed");
        }

        signature.resize(sig_len);
        return signature;
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
    }

    // Verify signature
    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key) {
#ifdef USE_LIBOQS
        if (OQS_SIG_verify(sig_, message.data(), message.size(),
                          signature.data(), signature.size(),
                          public_key.data()) == OQS_SUCCESS) {
            return true;
        }
        return false;
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
    }

    std::vector<uint8_t> getPublicKey() const {
        return public_key_;
    }

    size_t getSignatureSize() const {
        return FALCON512_SIG_SIZE;
    }

private:
    Hash256 hashMessage(const std::vector<uint8_t>& message) const {
        Hash256 hash = {};
        for (size_t i = 0; i < message.size(); ++i) {
            hash[i % 32] ^= message[i];
        }
        return hash;
    }
};

/**
 * ML-DSA-65 (Dilithium3) Signature Wrapper
 *
 * Properties:
 * - Signature size: ~3293 bytes
 * - Public key: ~1952 bytes
 * - Used for: RSU anchors, L1/L2/L3 anchor signatures
 */
class MLDSASigner {
private:
#ifdef USE_LIBOQS
    OQS_SIG *sig_;
#endif
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> secret_key_;
    bool keys_generated_;

public:
    MLDSASigner() : keys_generated_(false) {
#ifdef USE_LIBOQS
        // Try newer ML-DSA name first, fallback to dilithium_3
        #if defined(OQS_SIG_alg_ml_dsa_65)
            sig_ = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
        #elif defined(OQS_SIG_alg_dilithium_3)
            sig_ = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
        #else
            sig_ = OQS_SIG_new("Dilithium3");
        #endif

        if (sig_ == nullptr) {
            throw std::runtime_error("Failed to initialize ML-DSA-65 (Dilithium3)");
        }
#endif
    }

    ~MLDSASigner() {
#ifdef USE_LIBOQS
        if (sig_) {
            OQS_SIG_free(sig_);
        }
#endif
    }

    void generateKeys() {
#ifdef USE_LIBOQS
        public_key_.resize(sig_->length_public_key);
        secret_key_.resize(sig_->length_secret_key);

        if (OQS_SIG_keypair(sig_, public_key_.data(), secret_key_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("ML-DSA key generation failed");
        }
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        keys_generated_ = true;
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) {
        if (!keys_generated_) {
            throw std::runtime_error("Keys not generated");
        }

#ifdef USE_LIBOQS
        std::vector<uint8_t> signature(sig_->length_signature);
        size_t sig_len = 0;

        if (OQS_SIG_sign(sig_, signature.data(), &sig_len,
                        message.data(), message.size(),
                        secret_key_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("ML-DSA signing failed");
        }

        signature.resize(sig_len);
        return signature;
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
    }

    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key) {
#ifdef USE_LIBOQS
        if (OQS_SIG_verify(sig_, message.data(), message.size(),
                          signature.data(), signature.size(),
                          public_key.data()) == OQS_SUCCESS) {
            return true;
        }
        return false;
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
    }

    std::vector<uint8_t> getPublicKey() const {
        return public_key_;
    }

private:
    Hash256 hashMessage(const std::vector<uint8_t>& message) const {
        Hash256 hash = {};
        for (size_t i = 0; i < message.size(); ++i) {
            hash[i % 32] ^= message[i];
        }
        return hash;
    }
};

/**
 * ML-KEM-768 Key Encapsulation Mechanism
 *
 * Properties:
 * - Public key: 1184 bytes
 * - Ciphertext: 1088 bytes
 * - Shared secret: 32 bytes
 * - Used for: Establishing secure channels for sig_req messages
 *
 * Usage pattern:
 * 1. Receiver generates keypair, publishes public key
 * 2. Sender encapsulates to get (ciphertext, shared_secret)
 * 3. Sender sends ciphertext to receiver
 * 4. Receiver decapsulates ciphertext to get same shared_secret
 * 5. Both derive symmetric keys from shared_secret for AEAD encryption
 */
class MLKEM {
private:
#ifdef USE_LIBOQS
    OQS_KEM *kem_;
#endif
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> secret_key_;
    bool keys_generated_;

public:
    static constexpr size_t PUBLIC_KEY_SIZE = 1184;
    static constexpr size_t SECRET_KEY_SIZE = 2400;
    static constexpr size_t CIPHERTEXT_SIZE = 1088;
    static constexpr size_t SHARED_SECRET_SIZE = 32;

    MLKEM() : keys_generated_(false) {
#ifdef USE_LIBOQS
        kem_ = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if (kem_ == nullptr) {
            throw std::runtime_error("Failed to initialize ML-KEM-768");
        }
#endif
    }

    ~MLKEM() {
#ifdef USE_LIBOQS
        if (kem_) {
            OQS_KEM_free(kem_);
        }
#endif
    }

    // Generate keypair (done by receiver)
    void generateKeys() {
#ifdef USE_LIBOQS
        public_key_.resize(kem_->length_public_key);
        secret_key_.resize(kem_->length_secret_key);

        if (OQS_KEM_keypair(kem_, public_key_.data(), secret_key_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("ML-KEM key generation failed");
        }
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        keys_generated_ = true;
    }

    // Encapsulate (done by sender)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(
            const std::vector<uint8_t>& peer_public_key) {

#ifdef USE_LIBOQS
        std::vector<uint8_t> ciphertext(kem_->length_ciphertext);
        std::vector<uint8_t> shared_secret(kem_->length_shared_secret);

        if (OQS_KEM_encaps(kem_, ciphertext.data(), shared_secret.data(),
                          peer_public_key.data()) != OQS_SUCCESS) {
            throw std::runtime_error("ML-KEM encapsulation failed");
        }

        return {ciphertext, shared_secret};
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
    }

    // Decapsulate (done by receiver)
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext) {
        if (!keys_generated_) {
            throw std::runtime_error("Keys not generated");
        }

#ifdef USE_LIBOQS
        std::vector<uint8_t> shared_secret(kem_->length_shared_secret);

        if (OQS_KEM_decaps(kem_, shared_secret.data(),
                          ciphertext.data(), secret_key_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("ML-KEM decapsulation failed");
        }

        return shared_secret;
#else
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
    }

    std::vector<uint8_t> getPublicKey() const {
        return public_key_;
    }

    bool isKeyGenerated() const {
        return keys_generated_;
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_LIBOQS_WRAPPER_H
