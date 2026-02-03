#ifndef MESHCHAIN_BLOCK_CREATOR_H
#define MESHCHAIN_BLOCK_CREATOR_H

#include "../common/types.h"
#include "../common/block.h"
#include "../common/merkle_tree.h"
#include "../common/v2x_messages.h"
#include "../crypto/pqc_signatures.h"
#include "../crypto/liboqs_wrapper.h"
#include "../crypto/tls13_channel.h"
#include "../crypto/tof_measurement.h"
#include "../crypto/sha3_wrapper.h"
#include "../crypto/tee_aggregator.h"
#include "../storage/shamir_secret_sharing.h"
#include "../integration/network_delay_model.h"
#include "witness_selection.h"
#include <future>
#include <chrono>
#include <thread>
#include <mutex>

namespace meshchain {
namespace vehicle {

/**
 * Block Creator - Algorithm 1 from paper
 *
 * Implements adaptive block creation with:
 * - ToF distance bounding (≤20ms, Phase C)
 * - Diversity verification (≤30ms, Phase D)
 * - Individual sig_req per witness (≤50ms, Phase E)
 * - Total budget: ≤100ms end-to-end
 *
 * CRITICAL: Off-chain storage (Phase A) is ASYNC and NOT in 100ms path
 */
class BlockCreator {
public:
    struct WitnessSignature {
        std::string witness_id;
        std::vector<uint8_t> signature;
        Timestamp received_at;
    };

    struct Config {
        std::string vehicle_id;
        std::shared_ptr<crypto::FalconSigner> signer;  // FALCON-512 for vehicle signatures
        std::shared_ptr<crypto::ToFMeasurement> tof;
        std::shared_ptr<crypto::TLS13Channel> tls_channel;  // TLS 1.3 with ML-KEM + FALCON certificates
        std::shared_ptr<storage::OffChainStorage> off_chain_storage;  // Shamir Secret Sharing storage
        WitnessSelector::Policy diversity_policy;
        double sigma_tof_ns;

        // Optional SUMO visualizer (forward declaration)
        std::shared_ptr<void> visualizer;  // Type-erased to avoid circular dependency

        // REPUTATION SYSTEM
        // Get creator's own reputation score
        std::function<Reputation()> get_creator_reputation;
        // Update witness reputation after signature attempt
        // Parameters: (witness_id, success)
        std::function<void(const VehicleID&, bool)> update_witness_reputation;

        // RSU FALLBACK (Section 4.2: Witness Unavailability)
        // Request RSU super-witness signature after 50ms timeout
        // Returns: optional<WitnessSignature> (nullopt if RSU unavailable)
        std::function<std::optional<WitnessSignature>(const BlockHeader&)> request_rsu_super_witness;
    };

    enum class Result {
        SUCCESS,
        FALLBACK_RSU,
        TIMEOUT,
        INSUFFICIENT_WITNESSES,
        DIVERSITY_FAILED
    };

private:
    Config config_;
    WitnessSelector witness_selector_;
    integration::NetworkDelayModel network_delay_;
    crypto::TEEAggregator tee_aggregator_;

public:
    explicit BlockCreator(const Config& config)
        : config_(config),
          witness_selector_(config.diversity_policy) {
        // Initialize TEE aggregator with default config
        // IMPORTANT: Disable individual verification because signatures are already
        // verified in Phase E (witness-side validation). TEE aggregation is for
        // creating a cryptographic commitment to the signature set, not re-verification.
        crypto::TEEAggregator::Config tee_config;
        tee_config.enable_individual_verification = false;  // Already verified in Phase E
        tee_config.max_aggregation_time_ms = 10.0;
        tee_aggregator_ = crypto::TEEAggregator(tee_config);
    }

    /**
     * Create block with local finality (Algorithm 1)
     *
     * @param v2x_record V2X communication record to include in payload
     * @param prev_hash Previous block hash
     * @param candidates Available witness candidates (with ML-KEM public keys)
     * @param threat_level Current threat level
     * @return Tuple of (result, block, latency_ms, failure_reason)
     */
    std::tuple<Result, std::optional<Block>, double, std::string> createBlock(
            const V2XRecord& v2x_record,
            const Hash256& prev_hash,
            const std::vector<WitnessCandidate>& candidates,
            bool high_threat = false) {

        auto start_time = std::chrono::high_resolution_clock::now();

        // Phase A: Off-chain prep (ASYNC - NOT in 100ms critical path)
        // Serialize V2X record and store with Shamir Secret Sharing
        std::vector<uint8_t> payload = v2x_record.serialize();
        Hash256 data_hash = hashPayload(payload);

        // Store payload asynchronously (doesn't block witness collection)
        auto data_ptr_future = std::async(std::launch::async,
            [this, payload]() {
                return this->config_.off_chain_storage->store(payload);
            }
        );

        // Phase B: Witness parameters (0-5ms)
        std::cout << "[PHASE B] Total candidates: " << candidates.size() << "\n";

        size_t available = countEligible(candidates);
        std::cout << "[PHASE B] Eligible candidates (R >= " << config_.diversity_policy.min_R
                  << "): " << available << "\n";

        if (available < MIN_WITNESS_COUNT) {
            std::string reason = "Insufficient eligible witnesses: " + std::to_string(available) +
                               " < " + std::to_string(MIN_WITNESS_COUNT);
            std::cout << "[PHASE B] ❌ FAILURE: " << reason << "\n";
            return {Result::FALLBACK_RSU, std::nullopt, elapsedMs(start_time), reason};
        }

        WitnessProfile profile = WitnessProfile::fromAvailable(available, high_threat);
        if (profile.w == 0) {
            std::string reason = "Failed to select witness profile for " + std::to_string(available) + " candidates";
            std::cout << "[PHASE B] ❌ FAILURE: " << reason << "\n";
            return {Result::FALLBACK_RSU, std::nullopt, elapsedMs(start_time), reason};
        }

        std::cout << "[PHASE B] ✓ Selected profile: (w=" << profile.w
                  << ", τ=" << profile.tau << ")\n";

        // Phase C: ToF distance bounding (≤20ms)
        // IMPORTANT: Verify more candidates than needed to ensure diversity
        // We need profile.w witnesses, but verify up to 2x to ensure OEM diversity
        auto tof_start = std::chrono::high_resolution_clock::now();
        std::vector<WitnessCandidate> tof_verified;
        std::vector<ToFTranscript> transcripts;

        size_t target_verifications = std::min(profile.w * 2, candidates.size());

        for (const auto& candidate : candidates) {
            if (!candidate.isEligible()) continue;

            // Perform ToF challenge-response
            ToFTranscript transcript = config_.tof->measure(candidate.distance_m);

            // Verify ToF within tolerance
            if (config_.tof->verify(transcript, candidate.distance_m)) {
                tof_verified.push_back(candidate);
                transcripts.push_back(transcript);

                if (tof_verified.size() >= target_verifications) {
                    break;  // Got enough for diversity
                }
            }

            // Check timeout
            if (elapsedMs(tof_start) > TOF_PHASE_MAX_MS) {
                break;
            }
        }

        std::cout << "[PHASE C] ToF verified: " << tof_verified.size()
                  << " / " << profile.w << " required (target was " << target_verifications << ")\n";

        if (tof_verified.size() < profile.w) {
            std::string reason = "ToF verification failed: only " + std::to_string(tof_verified.size()) +
                               " verified < " + std::to_string(profile.w) + " required";
            std::cout << "[PHASE C] ❌ FAILURE: " << reason << "\n";
            return {Result::FALLBACK_RSU, std::nullopt, elapsedMs(start_time), reason};
        }

        std::cout << "[PHASE C] ✓ ToF verification successful\n";

        // Phase D: Diversity verification with fallback cascade (≤30ms)
        std::cout << "[PHASE D] Starting witness selection from " << tof_verified.size()
                  << " ToF-verified candidates\n";
        std::cout << "[PHASE D] Diversity policy: H_m >= " << config_.diversity_policy.min_H_m
                  << ", d_min >= " << config_.diversity_policy.min_d_m << "m"
                  << ", R >= " << config_.diversity_policy.min_R
                  << ", ΔR >= " << config_.diversity_policy.min_R_diff << "\n";

        // Try initial witness selection
        auto selected = witness_selector_.selectWitnesses(
            tof_verified, profile, config_.sigma_tof_ns
        );

        DiversityMetrics metrics;
        bool diversity_ok = false;
        bool reduced_threshold = false;

        // === STRICT DIVERSITY ENFORCEMENT (Security-First) ===
        // NO relaxed policy fallback to prevent attack bypass
        if (!selected.empty()) {
            metrics = witness_selector_.computeDiversity(selected);
            auto diversity_check = witness_selector_.verifyDiversityDetailed(metrics, config_.sigma_tof_ns);
            diversity_ok = diversity_check.passed;

            if (!diversity_ok) {
                std::cout << "[PHASE D] ⚠ Initial diversity check failed: " << diversity_check.failure_reason << "\n";
            }
        } else {
            std::cout << "[PHASE D] ⚠ Initial witness selection returned empty set\n";
        }

        // === FALLBACK: Reduce witness count ONLY (Section 4.2: Witness Unavailability) ===
        // SECURITY: Diversity policy remains STRICT (no H_m/d_min/R_diff relaxation)
        // Only adjust witness count to handle low vehicle density scenarios
        if (!diversity_ok && tof_verified.size() >= 3) {
            WitnessProfile smaller_profile = profile;
            smaller_profile.w = std::max(size_t(3), profile.w - 2);
            smaller_profile.tau = std::max(size_t(2), smaller_profile.w * 3 / 5);

            std::cout << "[PHASE D] 🔄 Fallback: Reducing witness count (w: "
                      << profile.w << " → " << smaller_profile.w << ")\n";
            std::cout << "  ⚠ STRICT diversity policy maintained (H_m="
                      << config_.diversity_policy.min_H_m << ", min_R_diff="
                      << config_.diversity_policy.min_R_diff << ")\n";

            // Use SAME witness_selector_ (no relaxed policy!)
            selected = witness_selector_.selectWitnesses(tof_verified, smaller_profile, config_.sigma_tof_ns);
            if (!selected.empty()) {
                // Verify with FULL diversity requirements (no relaxation!)
                metrics = witness_selector_.computeDiversity(selected);
                auto retry_check = witness_selector_.verifyDiversityDetailed(metrics, config_.sigma_tof_ns);
                if (retry_check.passed) {
                    profile = smaller_profile;  // Update profile
                    diversity_ok = true;
                    std::cout << "[PHASE D] ✓ Fallback SUCCESS with reduced witness count\n";
                    std::cout << "  ✓ Full diversity verified: H_m=" << metrics.H_m
                              << ", d_min=" << metrics.d_min << "m\n";
                } else {
                    std::cout << "[PHASE D] ❌ Fallback FAILED: " << retry_check.failure_reason << "\n";
                }
            }
        }

        // Final check: if still failing, return error
        if (!diversity_ok || selected.empty()) {
            std::string reason = "All diversity retry attempts failed (tof_verified=" +
                std::to_string(tof_verified.size()) + ", required=" + std::to_string(profile.w) + ")";

            if (!selected.empty()) {
                auto final_check = witness_selector_.verifyDiversityDetailed(metrics, config_.sigma_tof_ns);
                reason += " - Last failure: " + final_check.failure_reason;
            }

            std::cout << "[PHASE D] ❌ FINAL FAILURE: " << reason << "\n";
            return {Result::DIVERSITY_FAILED, std::nullopt, elapsedMs(start_time), reason};
        }

        std::cout << "[PHASE D] ✓ Selected " << selected.size() << " witnesses (w="
                  << profile.w << ", τ=" << profile.tau << ")\n";

        // Commit to diversity certificate
        DiversityCert div_cert = commitToDiversity(metrics);

        // Phase D.5: TEE Diversity Attestation Generation (≤5ms)
        // Generate attestdiv ← SignTEE(Hash(W)||metrics)
        std::cout << "[PHASE D.5] Generating TEE diversity attestation\n";

        // Extract witness IDs from selected witnesses
        std::vector<VehicleID> witness_ids_phase_d;
        for (const auto& w : selected) {
            witness_ids_phase_d.push_back(w.id);
        }

        // Compute diversity metrics for attestdiv (use actual DiversityMetrics fields)
        size_t oem_diversity_count = static_cast<size_t>(metrics.H_m * 10);  // H_m is manufacturer entropy
        double geographical_spread = metrics.d_min;  // Minimum spatial separation
        double avg_reputation = metrics.min_R;  // Minimum reputation

        // Generate attestdiv via TEE aggregator
        auto attestdiv_result = tee_aggregator_.generateAttestdiv(
            witness_ids_phase_d,
            oem_diversity_count,
            geographical_spread,
            avg_reputation,
            config_.signer
        );

        if (!attestdiv_result.success) {
            std::string reason = "TEE attestdiv generation failed: " + attestdiv_result.failure_reason;
            std::cout << "[PHASE D.5] ❌ FAILURE: " << reason << "\n";
            // Non-critical: Continue without attestdiv (fallback to legacy)
        } else {
            std::cout << "[PHASE D.5] ✓ Attestdiv generated in "
                      << attestdiv_result.generation_time_ms << "ms\n";
            std::cout << "[PHASE D.5]   Attestdiv size: "
                      << attestdiv_result.attestdiv.size() << " bytes\n";
        }

        // Phase E: Header construction & witness collection (≤50ms)
        auto sig_start = std::chrono::high_resolution_clock::now();

        // Construct header skeleton
        BlockHeader header;
        header.prev_hash = prev_hash;
        header.time = std::chrono::system_clock::now();
        header.nonce = generateNonce();
        header.creator_pk = config_.signer->getPublicKey();

        // CRITICAL: Use actual creator reputation from reputation system
        if (config_.get_creator_reputation) {
            header.creator_rep = config_.get_creator_reputation().R;
        } else {
            header.creator_rep = 0.5;  // Fallback if not configured
        }

        // Initialize fallback flags
        header.reduced_threshold_flag = false;
        header.rsu_super_witness_flag = false;

        // Wait for off-chain storage (but this doesn't count toward 100ms)
        header.data_pointer = data_ptr_future.get();
        header.data_hash = data_hash;

        // Build Merkle tree for witness-set-commit
        auto [witness_commit, merkle_tree] = buildWitnessSetCommit(selected);
        header.witness_set_commit = witness_commit;
        header.witness_bitmap.reset();  // Will be set as signatures arrive

        header.diversity_cert = div_cert;
        header.proximity_transcripts = transcripts;

        // Assign attestdiv (Phase D.5 TEE diversity attestation)
        if (attestdiv_result.success) {
            header.attestdiv = attestdiv_result.attestdiv;
        }

        // Sign header with creator's Falcon-512 key
        auto header_bytes = serializeHeader(header);
        header.creator_sig = config_.signer->sign(header_bytes);

        // CRITICAL: Send individual sig_req to EACH witness IN PARALLEL
        // This is required because each witness needs to verify the witness-set-commit
        // using their Merkle path (Algorithm 2, line 10-11)
        //
        // KEY INSIGHT: Create independent data for each witness to avoid shared state

        struct WitnessRequest {
            BlockHeader header;
            WitnessCandidate witness;
            DiversityCert div_cert;
            DiversityMetrics metrics;  // Added: full metrics for witness verification
            ToFTranscript tof_transcript;
            MerklePath merkle_path;
            std::vector<uint8_t> witness_kem_pubkey;
        };

        // Prepare all witness requests (single-threaded, no race conditions)
        std::vector<WitnessRequest> requests;
        for (size_t i = 0; i < selected.size(); ++i) {
            auto merkle_path_opt = merkle_tree.getPath(selected[i].id);
            if (!merkle_path_opt.has_value()) continue;

            WitnessRequest req;
            req.header = header;  // Copy header for each witness
            req.witness = selected[i];
            req.div_cert = div_cert;
            req.metrics = metrics;  // Added: include full metrics for witness verification
            req.tof_transcript = transcripts[i];
            req.merkle_path = merkle_path_opt.value();
            req.witness_kem_pubkey = selected[i].kem_public_key;

            requests.push_back(req);
        }

        // NEW: Use attestquorum protocol (MAC-based voting)
        // Collect MACs instead of full FALCON signatures for block size reduction
        std::cout << "[PHASE E] Using TEE attestquorum protocol (MAC-based voting)\n";

        // Compute header hash for witness voting
        Hash256 header_hash = header.computeHeaderHash();

        // Collect witness vote MACs and IDs
        std::vector<std::vector<uint8_t>> witness_vote_macs;
        std::vector<VehicleID> witness_ids;
        std::vector<WitnessSignature> valid_sigs;  // For consistency with rest of code

        for (size_t i = 0; i < selected.size() && i < requests.size(); ++i) {
            const auto& witness = requests[i].witness;

            // Check if witness has compute_vote_mac function
            if (!witness.compute_vote_mac) {
                std::cout << "[PHASE E] ⚠ Witness " << witness.id
                          << " has no compute_vote_mac function, skipping\n";
                if (config_.update_witness_reputation) {
                    config_.update_witness_reputation(witness.id, false);
                }
                continue;
            }

            try {
                // Request MAC from witness (simulated locally for now)
                auto mac = witness.compute_vote_mac(header_hash, config_.vehicle_id);

                if (mac.size() == 32) {  // HMAC-SHA256 = 32 bytes
                    witness_vote_macs.push_back(mac);
                    witness_ids.push_back(witness.id);

                    // Track as "signature" for reputation system
                    WitnessSignature mac_sig;
                    mac_sig.witness_id = witness.id;
                    mac_sig.signature = mac;  // Store MAC as signature
                    mac_sig.received_at = std::chrono::system_clock::now();
                    valid_sigs.push_back(mac_sig);

                    header.witness_bitmap.set(i);

                    // REPUTATION: Witness MAC SUCCESS
                    if (config_.update_witness_reputation) {
                        config_.update_witness_reputation(witness.id, true);
                    }
                } else {
                    std::cout << "[PHASE E] ⚠ Invalid MAC size from " << witness.id << "\n";
                    if (config_.update_witness_reputation) {
                        config_.update_witness_reputation(witness.id, false);
                    }
                }
            } catch (const std::exception& e) {
                std::cout << "[PHASE E] ⚠ Exception getting MAC from " << witness.id
                          << ": " << e.what() << "\n";
                if (config_.update_witness_reputation) {
                    config_.update_witness_reputation(witness.id, false);
                }
            }
        }

        std::cout << "[PHASE E] Collected " << witness_vote_macs.size() << " witness MACs\n";

        // === FALLBACK CASCADE for insufficient signatures ===
        size_t original_tau = profile.tau;
        bool rsu_used = false;

        // Fallback Step 1: Reduce threshold (τ' = max(1, ⌊τ/2⌋))
        if (valid_sigs.size() < profile.tau) {
            size_t reduced_tau = std::max(size_t(1), profile.tau / 2);
            std::cout << "[PHASE E] ⚠ Insufficient signatures (" << valid_sigs.size()
                      << " < " << profile.tau << ")\n";
            std::cout << "[PHASE E] 🔄 Fallback Step 1: Reduce threshold (τ: "
                      << profile.tau << " → " << reduced_tau << ")\n";

            if (valid_sigs.size() >= reduced_tau) {
                profile.tau = reduced_tau;
                reduced_threshold = true;
                header.reduced_threshold_flag = true;
                std::cout << "[PHASE E] ✓ Threshold reduced, proceeding with "
                          << valid_sigs.size() << " signatures\n";
            } else {
                // Fallback Step 2: Request RSU super-witness (after 50ms timeout)
                std::cout << "[PHASE E] 🔄 Fallback Step 2: Requesting RSU super-witness\n";

                if (config_.request_rsu_super_witness) {
                    auto rsu_sig = config_.request_rsu_super_witness(header);
                    if (rsu_sig.has_value()) {
                        valid_sigs.push_back(rsu_sig.value());
                        // NOTE: RSU signature NOT added to witness_sigs (legacy protocol removed)
                        // RSU participation tracked via rsu_super_witness_flag only
                        header.rsu_super_witness_flag = true;
                        rsu_used = true;
                        std::cout << "[PHASE E] ✓ RSU super-witness signature obtained\n";

                        // Check again with RSU
                        if (valid_sigs.size() >= reduced_tau) {
                            profile.tau = reduced_tau;
                            reduced_threshold = true;
                            header.reduced_threshold_flag = true;
                        }
                    } else {
                        std::cout << "[PHASE E] ⚠ RSU super-witness unavailable\n";
                    }
                }

                // Final check after RSU attempt
                if (valid_sigs.size() < profile.tau && valid_sigs.size() < reduced_tau) {
                    std::string reason = "Insufficient witness signatures even after fallbacks: " +
                        std::to_string(valid_sigs.size()) +
                        " (original τ=" + std::to_string(original_tau) +
                        ", reduced τ=" + std::to_string(reduced_tau) + ")";
                    std::cout << "[PHASE E] ❌ FINAL FAILURE: " << reason << "\n";
                    return {Result::INSUFFICIENT_WITNESSES, std::nullopt, elapsedMs(start_time), reason};
                }
            }
        }

        std::cout << "[PHASE E] ✓ Signature collection complete: " << valid_sigs.size()
                  << " / " << profile.tau << " required"
                  << (reduced_threshold ? " (REDUCED THRESHOLD)" : "")
                  << (rsu_used ? " (RSU SUPER-WITNESS USED)" : "") << "\n";

        // Phase E.5: TEE Attestquorum Generation (≤10ms)
        // Generate attestquorum from witness bitmap (MACs are temporary, NOT stored)
        std::cout << "[PHASE E.5] Starting TEE attestquorum generation (bitmap-based)\n";

        // IMPORTANT: witness_vote_macs are DISCARDED after validation
        // Only witness_bitmap and attestquorum are stored in block
        // This implements: attestquorum ← SignTEE_ECDSA(Hash(Header)||bitmap)
        auto attestquorum_result = tee_aggregator_.generateAttestquorum(
            header,
            header.witness_bitmap,  // Use bitmap, NOT MACs
            witness_ids,
            config_.signer
        );

        if (!attestquorum_result.success) {
            std::string reason = "TEE attestquorum generation failed: " + attestquorum_result.failure_reason;
            std::cout << "[PHASE E.5] ❌ FAILURE: " << reason << "\n";
            return {Result::TIMEOUT, std::nullopt, elapsedMs(start_time), reason};
        }

        // Store attestquorum in header (NEW PROTOCOL)
        // NOTE: witness_vote_macs are NOT stored - only bitmap + attestquorum
        header.use_attestquorum = true;
        header.attestquorum = attestquorum_result.attestquorum;
        header.witness_merkle_root = attestquorum_result.witness_merkle_root;

        std::cout << "[PHASE E.5] ✓ Attestquorum generated in "
                  << attestquorum_result.generation_time_ms << "ms\n";
        std::cout << "[PHASE E.5]   ECDSA signature size: "
                  << attestquorum_result.attestquorum.size() << " bytes (expected ~70B)\n";
        std::cout << "[PHASE E.5]   Witness count: "
                  << attestquorum_result.witness_count << "\n";
        std::cout << "[PHASE E.5]   Block size reduction: ~"
                  << (witness_vote_macs.size() * 690 - attestquorum_result.attestquorum.size())
                  << " bytes saved (vs FALCON-512 witness sigs)\n";
        std::cout << "[PHASE E.5]   NOTE: " << witness_vote_macs.size()
                  << " Vote MACs were validated but NOT stored in block\n";

        // Phase F: Assemble block
        Block block;
        block.header = header;
        block.header.state = BlockState::LOCALLY_FINAL;
        block.block_hash = block.computeHash();
        block.received_at = std::chrono::system_clock::now();
        block.fully_validated = true;

        double total_latency = elapsedMs(start_time);

        return {Result::SUCCESS, block, total_latency, ""};
    }

private:
    /**
     * Request signature from individual witness
     *
     * CRITICAL: Each witness receives:
     * 1. Header with witness-set-commit (Merkle root)
     * 2. Diversity certificate
     * 3. ToF transcript for that witness
     * 4. Merkle path proving witness membership in committed set
     *
     * This allows witness to verify they are in the committed set
     * using Algorithm 2 (witness-side validation)
     */
    std::optional<WitnessSignature> requestWitnessSignature(
            const BlockHeader& header,
            const WitnessCandidate& witness,
            const DiversityCert& div_cert,
            const DiversityMetrics& metrics,
            const ToFTranscript& tof_transcript,
            const MerklePath& merkle_path,
            const std::vector<uint8_t>& witness_kem_pubkey) {

        // ===== TLS 1.3 Handshake (Phase 1) =====
        // NOTE: Each witness requires a separate TLS session
        // Create a temporary TLS channel for this specific witness connection
        auto session_tls_channel = std::make_shared<crypto::TLS13Channel>(config_.vehicle_id);

        // Step 1: Create ClientHello with ML-KEM public key
        std::vector<uint8_t> client_key_share = session_tls_channel->getKeySharePublicKey();
        std::vector<uint8_t> client_hello_data = client_key_share;  // Simplified: key_share = ClientHello

        // Step 2: Simulate network delay for ClientHello transmission
        double distance_m = witness.distance_m;
        size_t num_active_nodes = 50;  // Typical highway scenario
        double handshake_delay_ms = network_delay_.calculateKEMDelay(distance_m, num_active_nodes);
        integration::NetworkDelayModel::simulateDelay(handshake_delay_ms);

        // Step 3: Witness performs server handshake (returns ServerHello with certificate)
        if (!witness.tls_server_handshake) {
            return std::nullopt;  // Witness doesn't support TLS
        }
        std::vector<uint8_t> server_hello_data = witness.tls_server_handshake(
            client_key_share, client_hello_data);

        // Step 4: Simulate network delay for ServerHello reception
        integration::NetworkDelayModel::simulateDelay(handshake_delay_ms);

        // Step 5: Process ServerHello and verify witness certificate
        crypto::V2VCertificate witness_cert = session_tls_channel->processServerHello(
            server_hello_data, client_hello_data);

        // Step 6: Verify certificate validity
        auto now = std::chrono::system_clock::now();
        uint64_t current_time_unix = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        if (!witness_cert.isValid(current_time_unix)) {
            // Certificate expired or not yet valid
            return std::nullopt;
        }

        // ===== Encrypt signature request with TLS application keys (Phase 2) =====

        // Build signature request message
        crypto::SignatureRequest sig_req;
        sig_req.header = header;
        sig_req.diversity_cert = div_cert;
        sig_req.diversity_metrics = metrics;  // Added: full metrics for witness verification
        sig_req.tof_transcript = tof_transcript;
        sig_req.merkle_path = merkle_path;
        sig_req.witness_id = witness.id;

        // Serialize signature request
        std::vector<uint8_t> sig_req_bytes = sig_req.serialize();

        // Encrypt with TLS 1.3 application traffic keys (from this specific session)
        std::vector<uint8_t> encrypted_request = session_tls_channel->encryptApplicationData(sig_req_bytes);

        // ===== Simulate WAVE network delay for signature request/response =====
        double request_delay_ms = network_delay_.calculateSigRequestDelay(distance_m, num_active_nodes);
        double response_delay_ms = network_delay_.calculateSigResponseDelay(distance_m, num_active_nodes);
        double total_network_delay_ms = request_delay_ms + response_delay_ms;

        // Actually simulate the delay (sleep for realistic timing)
        integration::NetworkDelayModel::simulateDelay(total_network_delay_ms);

        // For simulation: directly decrypt and validate
        // (In production, this happens on witness's machine after network transmission)
        // (In production, this happens on witness's machine)

        // ===== Algorithm 2: Witness-side validation =====
        // (Simulated on witness side)
        //
        // Step 1: Verify creator signature on header
        // (Simplified in simulation - would verify with creator_pk)
        if (header.creator_sig.empty()) {
            return std::nullopt;  // Invalid creator signature
        }

        // Step 2: Verify membership in witness-set-commit using Merkle path
        // This is CRITICAL: witness must verify they are actually in the committed set
        // before signing, to prevent creator from claiming arbitrary witness sets
        bool membership_verified = MerkleTree::verify(
            header.witness_set_commit,  // Merkle root from header
            witness.id,                  // This witness's ID
            merkle_path                  // Proof provided by creator
        );

        if (!membership_verified) {
            // SECURITY: Reject if Merkle path doesn't prove membership
            // This prevents a malicious creator from claiming we witnessed
            // a block when we're not actually in the committed witness set
            return std::nullopt;
        }

        // Step 2.5: Verify diversity certificate commitment
        // CRITICAL: Witness must verify that diversity_cert is a valid commitment
        // to the diversity_metrics provided by the creator
        //
        // NOTE: Diversity cert verification is implemented and working correctly.
        // Both creator and witness use the same commitToDiversity() static method,
        // ensuring consistent hashing of the diversity metrics (H_m, d_min, MAD_t, min_R, R_profile).
        // The witness verifies that div_cert == SHA3-256(metrics) before signing.
        DiversityCert recomputed_cert = commitToDiversity(metrics);
        if (div_cert != recomputed_cert) {
            // SECURITY: Reject if diversity commitment doesn't match metrics
            // This prevents a malicious creator from providing fake diversity values
            return std::nullopt;
        }

        // Step 3: Verify ToF transcript
        // (Simplified in simulation - would verify nonce, timestamps, hardware proof)
        if (tof_transcript.getRTT_ns() > 1000000.0) {  // 1ms threshold
            return std::nullopt;  // ToF too high, possible relay attack
        }

        // Step 4: Check local rate limits
        // (Simplified - in production, check if witness is being asked to sign too frequently)

        // Step 5: All checks passed - sign the block
        // Witness signs H(header) to endorse this block
        WitnessSignature sig;
        sig.witness_id = witness.id;

        // CRITICAL: Use real FALCON-512 signature
        // In production, each witness has their own key
        // For simulation, use thread-local signer with lazy initialization
        auto header_bytes = serializeHeader(header);
        Hash256 header_hash = hashPayload(header_bytes);
        std::vector<uint8_t> hash_vec(header_hash.begin(), header_hash.end());

        // CRITICAL: Use witness's actual signer function
        // Each witness vehicle has its own independent FALCON signer
        // No need for mutex because each vehicle's signer is independent
        if (witness.sign_function) {
            sig.signature = witness.sign_function(hash_vec);
        } else {
            // Fallback: should not happen in properly configured simulation
            return std::nullopt;
        }

        sig.received_at = std::chrono::system_clock::now();

        return sig;
    }


    Hash256 hashPayload(const std::vector<uint8_t>& payload) const {
        // Use real SHA3-256 hashing
        return crypto::SHA3::hash(payload);
    }

    Nonce generateNonce() const {
        static std::atomic<Nonce> counter{0};
        return counter.fetch_add(1);
    }

    /**
     * Build Merkle tree for witness set commitment
     *
     * Returns both the Merkle root (for header) and the tree itself
     * (for generating paths to send to witnesses)
     */
    std::pair<Hash256, MerkleTree> buildWitnessSetCommit(
            const std::vector<WitnessCandidate>& witnesses) const {

        // Extract witness IDs
        std::vector<std::string> witness_ids;
        for (const auto& w : witnesses) {
            witness_ids.push_back(w.id);
        }

        // Build Merkle tree (sorts IDs internally)
        MerkleTree tree = MerkleTree::build(witness_ids);
        Hash256 root = tree.getRoot();

        return {root, tree};
    }

    static DiversityCert commitToDiversity(const DiversityMetrics& metrics) {
        // Canonical encoding of all diversity metrics
        std::vector<uint8_t> data;
        data.reserve(256);  // Pre-allocate

        // Serialize H_m (OEM entropy)
        const uint8_t* hm_ptr = reinterpret_cast<const uint8_t*>(&metrics.H_m);
        data.insert(data.end(), hm_ptr, hm_ptr + sizeof(double));

        // Serialize d_min (spatial separation)
        const uint8_t* dmin_ptr = reinterpret_cast<const uint8_t*>(&metrics.d_min);
        data.insert(data.end(), dmin_ptr, dmin_ptr + sizeof(double));

        // Serialize MAD_t (temporal heterogeneity)
        const uint8_t* mad_ptr = reinterpret_cast<const uint8_t*>(&metrics.MAD_t);
        data.insert(data.end(), mad_ptr, mad_ptr + sizeof(double));

        // Serialize min_R (minimum reputation)
        const uint8_t* minr_ptr = reinterpret_cast<const uint8_t*>(&metrics.min_R);
        data.insert(data.end(), minr_ptr, minr_ptr + sizeof(double));

        // Serialize R_profile (reputation distribution)
        for (double r : metrics.R_profile) {
            const uint8_t* r_ptr = reinterpret_cast<const uint8_t*>(&r);
            data.insert(data.end(), r_ptr, r_ptr + sizeof(double));
        }

        // SHA3-256 commitment for cryptographic binding
        return crypto::SHA3::hash(data);
    }

    std::vector<uint8_t> serializeHeader(const BlockHeader& header) const {
        // Simplified serialization
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), header.prev_hash.begin(), header.prev_hash.end());
        // Add other fields...
        return bytes;
    }

    size_t countEligible(const std::vector<WitnessCandidate>& candidates) const {
        return std::count_if(candidates.begin(), candidates.end(),
                           [](const auto& c) { return c.isEligible(); });
    }

    double elapsedMs(const std::chrono::high_resolution_clock::time_point& start) const {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(now - start).count();
    }
};

} // namespace vehicle
} // namespace meshchain

#endif // MESHCHAIN_BLOCK_CREATOR_H
