#ifndef MESHCHAIN_PQC_SIGNATURES_H
#define MESHCHAIN_PQC_SIGNATURES_H

#include "../common/types.h"
#include <memory>
#include <vector>
#include <string>
#include <stdexcept>

namespace meshchain {
namespace crypto {

/**
 * PQC Signature Interface
 *
 * Critical requirements from paper:
 * - Fast path is PQC-ONLY (no BLS or other non-PQC aggregation)
 * - Vehicles: Falcon-512 (~690B signature, ~897B pubkey)
 * - RSU/Cloud: Dilithium-3 (~3293B signature)
 * - Constant-time operations, no secret-dependent branching
 */

// Signature scheme types
enum class SignatureScheme {
    FALCON_512,     // For vehicles (fast path)
    DILITHIUM_3     // For RSU/cloud anchors
};

class PQCSignature {
public:
    virtual ~PQCSignature() = default;

    // Key generation
    virtual void generateKeys() = 0;

    // Sign message
    virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& message) = 0;

    // Verify signature
    virtual bool verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key) = 0;

    // Get public key
    virtual std::vector<uint8_t> getPublicKey() const = 0;

    // Get signature size
    virtual size_t getSignatureSize() const = 0;

    // Get public key size
    virtual size_t getPublicKeySize() const = 0;

    // Get scheme type
    virtual SignatureScheme getScheme() const = 0;
};

/**
 * Falcon-512 Implementation (for vehicles)
 *
 * Properties:
 * - Compact signature: ~690 bytes
 * - Public key: ~897 bytes
 * - Sub-ms signing on Cortex-A72
 * - Lattice-based (NTRU lattices)
 */
class Falcon512 : public PQCSignature {
private:
    std::vector<uint8_t> secret_key_;
    std::vector<uint8_t> public_key_;
    bool keys_generated_;

public:
    Falcon512() : keys_generated_(false) {}

    void generateKeys() override {
#ifndef USE_LIBOQS
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        // This class is deprecated - use liboqs_wrapper.h FalconSigner instead
        throw std::runtime_error("Falcon512 class is deprecated - use FalconSigner from liboqs_wrapper.h");
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override {
#ifndef USE_LIBOQS
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        throw std::runtime_error("Falcon512 class is deprecated - use FalconSigner from liboqs_wrapper.h");
    }

    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key) override {
#ifndef USE_LIBOQS
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        throw std::runtime_error("Falcon512 class is deprecated - use FalconSigner from liboqs_wrapper.h");
    }

    std::vector<uint8_t> getPublicKey() const override {
        return public_key_;
    }

    size_t getSignatureSize() const override {
        return FALCON512_SIG_SIZE;
    }

    size_t getPublicKeySize() const override {
        return FALCON512_PK_SIZE;
    }

    SignatureScheme getScheme() const override {
        return SignatureScheme::FALCON_512;
    }

private:
    Hash256 hashMessage(const std::vector<uint8_t>& message) const {
        // Simplified hash for simulation
        // In production: use SHA3-256
        Hash256 hash = {};
        for (size_t i = 0; i < message.size(); ++i) {
            hash[i % 32] ^= message[i];
        }
        return hash;
    }
};

/**
 * Dilithium-3 Implementation (for RSU/cloud anchors)
 *
 * Properties:
 * - Signature: ~3293 bytes
 * - Public key: ~1952 bytes
 * - Robust verification, deployment maturity
 * - Module-LWE lattices
 */
class Dilithium3 : public PQCSignature {
private:
    std::vector<uint8_t> secret_key_;
    std::vector<uint8_t> public_key_;
    bool keys_generated_;

public:
    Dilithium3() : keys_generated_(false) {}

    void generateKeys() override {
#ifndef USE_LIBOQS
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        throw std::runtime_error("Dilithium3 class is deprecated - use MLDSASigner from liboqs_wrapper.h");
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override {
#ifndef USE_LIBOQS
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        throw std::runtime_error("Dilithium3 class is deprecated - use MLDSASigner from liboqs_wrapper.h");
    }

    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key) override {
#ifndef USE_LIBOQS
        #error "liboqs is REQUIRED for production builds. Simulation mode is NOT allowed for security evaluation and benchmarking. Install liboqs: sudo apt-get install liboqs-dev"
#endif
        throw std::runtime_error("Dilithium3 class is deprecated - use MLDSASigner from liboqs_wrapper.h");
    }

    std::vector<uint8_t> getPublicKey() const override {
        return public_key_;
    }

    size_t getSignatureSize() const override {
        return DILITHIUM3_SIG_SIZE;
    }

    size_t getPublicKeySize() const override {
        return 1952;
    }

    SignatureScheme getScheme() const override {
        return SignatureScheme::DILITHIUM_3;
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

// Factory function
inline std::unique_ptr<PQCSignature> createSignature(SignatureScheme scheme) {
    switch (scheme) {
        case SignatureScheme::FALCON_512:
            return std::make_unique<Falcon512>();
        case SignatureScheme::DILITHIUM_3:
            return std::make_unique<Dilithium3>();
        default:
            throw std::invalid_argument("Unknown signature scheme");
    }
}

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_PQC_SIGNATURES_H
