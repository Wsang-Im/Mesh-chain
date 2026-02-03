#ifndef MESHCHAIN_BLOCK_H
#define MESHCHAIN_BLOCK_H

#include "types.h"
#include "../crypto/sha3_wrapper.h"
#include <vector>
#include <bitset>
#include <functional>

namespace meshchain {

// Block header structure (Section 3.1)
// Total size target: 6-7 KB for w=7
struct BlockHeader {
    // Chain linkage
    Hash256 prev_hash;
    Timestamp time;
    Nonce nonce;

    // Creator information
    std::vector<uint8_t> creator_pk;  // Falcon-512 public key (~897 bytes)
    double creator_rep;  // Reputation R ∈ [0,1]

    // Off-chain data reference (async, NOT in 100ms path)
    DataPointer data_pointer;
    Hash256 data_hash;  // H(payload) for integrity

    // Witness set commitment (Merkle root of sorted witness IDs)
    Hash256 witness_set_commit;

    // Witness bitmap (which committed witnesses actually signed)
    std::bitset<MAX_WITNESS_COUNT> witness_bitmap;

    // Diversity certificate (commitment to metrics)
    // NOTE: Used for witness verification during Phase D, but NOT stored in final block
    // Witnesses verify diversity_cert before voting, then it's DISCARDED
    // Final block stores only attestdiv + attestquorum as proof
    DiversityCert diversity_cert;

    // ToF transcripts (one per witness, for proximity proof)
    std::vector<ToFTranscript> proximity_transcripts;

    // Phase 2: TEE Diversity Attestation (Paper Section 3.2)
    // attestdiv ← SignTEE_ECDSA(Hash(W)||metrics) where W is selected witness set
    // Proves that witness selection satisfies diversity requirements
    std::vector<uint8_t> attestdiv;  // TEE ECDSA signature over diversity metrics (~70 bytes P-256)

    // Signatures (PQC-only fast path)
    std::vector<uint8_t> creator_sig;  // Falcon-512 signature (~690 bytes)

    // REMOVED: Legacy fields no longer used (saved ~2,199 bytes per block!)
    // Previously these fields added significant overhead:
    // - witness_sigs: ~2,070 bytes (3 × 690 FALCON-512 signatures for w=3)
    // - has_tee_commit + tee_aggregate_hash + tee_signature_hashes: ~97 bytes
    // NOW: Use attestquorum protocol instead (70 bytes ECDSA signature)

    // NEW: TEE-based witness attestation (Paper Section 3.2 - attestquorum protocol)
    // Phase 4: Witnesses submit Vote (MAC) but NOT stored in block
    // TEE generates: attestquorum ← SignTEE_ECDSA(Hash(Header)||bitmap)
    // Only bitmap and attestquorum are stored in block
    // Block size reduction: ~4.2KB → ~1.4KB (w=3 witnesses)
    bool use_attestquorum;  // true if using TEE attestquorum (new protocol)
    std::vector<uint8_t> attestquorum;  // TEE ECDSA signature over (header||bitmap) (~70 bytes P-256)
    Hash256 witness_merkle_root;  // Merkle root of witness identities for attestquorum

    // State tracking
    BlockState state;

    // Fallback flags (Section 4.2: Witness Unavailability)
    bool reduced_threshold_flag;  // true if τ was reduced due to witness unavailability
    bool rsu_super_witness_flag;  // true if RSU was used as super-witness

    // Compute header hash for signing
    // IMPORTANT: This hash excludes ALL signature fields (attestdiv, attestquorum, creator_sig, witness_sigs)
    // Per paper specification, attestquorum = SignTEE(Hash(Header)||...) where Header is BEFORE attestquorum is added
    Hash256 computeHeaderHash() const {
        // Use real SHA3-256 over canonical encoding
        std::vector<uint8_t> data;
        data.reserve(1024);  // Pre-allocate reasonable size

        // Serialize all header fields in canonical order (excluding signature fields)
        data.insert(data.end(), prev_hash.begin(), prev_hash.end());
        data.insert(data.end(), data_hash.begin(), data_hash.end());
        data.insert(data.end(), witness_set_commit.begin(), witness_set_commit.end());
        // NOTE: diversity_cert is NOT serialized - it's temporary, used only during witness verification

        // Serialize creator public key
        data.insert(data.end(), creator_pk.begin(), creator_pk.end());

        // Serialize nonce (8 bytes, little-endian)
        uint64_t nonce_val = static_cast<uint64_t>(nonce);
        for (size_t i = 0; i < 8; ++i) {
            data.push_back(static_cast<uint8_t>((nonce_val >> (i * 8)) & 0xFF));
        }

        // Serialize timestamp (8 bytes)
        auto time_val = std::chrono::system_clock::to_time_t(time);
        for (size_t i = 0; i < 8; ++i) {
            data.push_back(static_cast<uint8_t>((time_val >> (i * 8)) & 0xFF));
        }

        // Hash with SHA3-256
        return crypto::SHA3::hash(data);
    }

    // Get header size estimate
    size_t estimateSize() const {
        size_t base = sizeof(prev_hash) + sizeof(time) + sizeof(nonce);
        base += creator_pk.size() + sizeof(creator_rep);
        base += sizeof(data_pointer.hash) + sizeof(data_hash);
        base += sizeof(witness_set_commit);  // Merkle root of witness IDs (32 bytes)
        // NOTE: diversity_cert NOT counted - used for witness verification but NOT stored in final block
        base += proximity_transcripts.size() * 64;  // Rough estimate (~64 bytes per ToF)
        base += attestdiv.size();  // Phase 2: TEE diversity attestation (~70 bytes ECDSA P-256)
        base += creator_sig.size();  // ~690 bytes (FALCON-512)

        // NEW: TEE attestquorum protocol (Paper Section 3.2)
        // NO witness_vote_macs in block (votes are temporary, not stored)
        // Only bitmap + attestquorum signature are stored
        base += attestquorum.size();  // TEE ECDSA signature (~70 bytes)
        base += sizeof(witness_merkle_root);  // 32 bytes
        base += sizeof(witness_bitmap) / 8;  // Bitmap (MAX_WITNESS_COUNT bits)
        return base;
    }

    // Validate basic header structure (attestquorum protocol only)
    bool validateStructure() const {
        // TEE attestquorum protocol validation
        size_t witness_count = witness_bitmap.count();
        if (witness_count == 0 || witness_count > MAX_WITNESS_COUNT) return false;
        if (proximity_transcripts.size() != witness_count) return false;
        if (attestquorum.empty()) return false;  // Must have TEE ECDSA signature
        // Attestquorum should be ~70 bytes (ECDSA P-256 signature: 64-72 bytes typical)
        if (attestquorum.size() < 64 || attestquorum.size() > 256) return false;
        return true;
    }

    // Get witness count from bitmap
    size_t getWitnessCount() const {
        return witness_bitmap.count();
    }
};

// Full block (header + metadata)
struct Block {
    BlockHeader header;
    Hash256 block_hash;

    // Validation metadata (not serialized)
    Timestamp received_at;
    std::string received_from;
    std::string creator_id;  // Vehicle ID who created this block (for anchoring)
    bool fully_validated;

    Block() : fully_validated(false) {
        received_at = std::chrono::system_clock::now();
    }

    // Compute block hash
    Hash256 computeHash() const {
        return header.computeHeaderHash();
    }
};

// Witness selection candidate
struct WitnessCandidate {
    VehicleID id;
    std::vector<uint8_t> public_key;  // FALCON-512 signature public key
    std::vector<uint8_t> kem_public_key;  // ML-KEM-768 key exchange public key
    Reputation reputation;
    double distance_m;  // From ToF measurement
    std::string oem;
    Timestamp first_contact;
    std::vector<VehicleID> neighbors;  // For witness-set-commit verification

    // LEGACY: Function to call witness's actual signer (FALCON-512)
    // Used in old protocol - each witness uses their own independent FALCON signer
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> sign_function;

    // NEW: TEE attestquorum protocol - MAC-based voting over secure TLS 1.3
    // Paper Section 3.2: Witnesses vote via MAC instead of expensive FALCON signatures
    // Parameters: (block_hash, witness_id) -> MAC (HMAC-SHA256, 32 bytes)
    // MAC is computed over secure ML-KEM-768 TLS 1.3 channel
    std::function<std::vector<uint8_t>(const Hash256&, const VehicleID&)> compute_vote_mac;

    // TLS 1.3 handshake function (witness side)
    // Parameters: (client_key_share, client_hello_data) -> server_hello_data
    // Returns ServerHello with certificate and encrypted handshake
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> tls_server_handshake;

    // TLS 1.3 application data decryption (witness side)
    // Takes encrypted request, returns decrypted data
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> tls_decrypt_app_data;

    bool isEligible(double min_rep = 0.3) const {
        return reputation.R >= min_rep;
    }
};

} // namespace meshchain

#endif // MESHCHAIN_BLOCK_H
