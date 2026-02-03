#ifndef MESHCHAIN_ATTACKER_MODELS_H
#define MESHCHAIN_ATTACKER_MODELS_H

#include "../common/types.h"
#include "../common/block.h"
#include "../crypto/pqc_signatures.h"
#include <vector>
#include <string>
#include <map>
#include <random>
#include <chrono>
#include <thread>
#include <iostream>
#include <iomanip>

namespace meshchain {
namespace security {

/**
 * Attacker Model Framework for Mesh-Chain V2X Blockchain
 *
 * Based on Section 2.3 "Threats" from Mesh-chain.pdf:
 * - T1: Solo tampering (forged signatures)
 * - T2: Regional majority / encirclement attack
 * - T3: Sybil/Eclipse attack
 * - T6: Spam/DoS attack
 *
 * Design Principles:
 * 1. Non-intrusive: Attackers are separate modules, minimal code changes
 * 2. Configurable: Attack parameters can be adjusted (β, βr, pmax, etc.)
 * 3. Observable: Statistics and logs for evaluation
 * 4. Defensive validation: Verify mitigation mechanisms work correctly
 */

// ==================== Attack Statistics ====================

struct AttackStatistics {
    // General stats
    size_t total_attempts = 0;
    size_t successful_attacks = 0;
    size_t detected_by_system = 0;
    size_t mitigated_by_policy = 0;

    // Timing stats
    std::chrono::system_clock::time_point first_attack;
    std::chrono::system_clock::time_point last_attack;

    // Per-attack type breakdown
    std::map<std::string, size_t> attempts_by_type;
    std::map<std::string, size_t> success_by_type;

    // Detection mechanism effectiveness
    std::map<std::string, size_t> detected_by_mechanism;

    void recordAttempt(const std::string& attack_type) {
        total_attempts++;
        attempts_by_type[attack_type]++;

        auto now = std::chrono::system_clock::now();
        if (total_attempts == 1) {
            first_attack = now;
        }
        last_attack = now;
    }

    void recordSuccess(const std::string& attack_type) {
        successful_attacks++;
        success_by_type[attack_type]++;
    }

    void recordDetection(const std::string& mechanism) {
        detected_by_system++;
        detected_by_mechanism[mechanism]++;
    }

    void recordMitigation() {
        mitigated_by_policy++;
    }

    double getSuccessRate() const {
        return total_attempts > 0 ?
            static_cast<double>(successful_attacks) / total_attempts : 0.0;
    }

    double getDetectionRate() const {
        return total_attempts > 0 ?
            static_cast<double>(detected_by_system) / total_attempts : 0.0;
    }

    void printSummary() const {
        std::cout << "  Total attempts:    " << total_attempts << "\n";
        std::cout << "  Successful:        " << successful_attacks << "\n";
        std::cout << "  Detected:          " << detected_by_system << "\n";
        std::cout << "  Mitigated:         " << mitigated_by_policy << "\n";
        std::cout << "  Success rate:      "
                  << std::fixed << std::setprecision(2)
                  << getSuccessRate() * 100.0 << "%\n";
        std::cout << "  Detection rate:    "
                  << std::fixed << std::setprecision(2)
                  << getDetectionRate() * 100.0 << "%\n";

        if (!attempts_by_type.empty()) {
            std::cout << "\n  Breakdown by type:\n";
            for (const auto& [type, attempts] : attempts_by_type) {
                auto success_it = success_by_type.find(type);
                size_t successes = (success_it != success_by_type.end()) ?
                                  success_it->second : 0;
                std::cout << "    " << std::left << std::setw(20) << type
                          << ": " << successes << "/" << attempts << " succeeded\n";
            }
        }
    }
};

// ==================== Base Attacker Interface ====================

/**
 * Base class for all attacker models
 */
class BaseAttacker {
protected:
    std::string attacker_id_;
    bool enabled_;
    AttackStatistics stats_;
    std::mt19937 rng_;

public:
    explicit BaseAttacker(const std::string& id)
        : attacker_id_(id), enabled_(false) {
        auto seed = std::chrono::system_clock::now().time_since_epoch().count();
        rng_.seed(static_cast<unsigned int>(seed));
    }

    virtual ~BaseAttacker() = default;

    // Enable/disable attacker
    void setEnabled(bool enabled) { enabled_ = enabled; }
    bool isEnabled() const { return enabled_; }

    // Get attacker identity
    std::string getId() const { return attacker_id_; }

    // Get attack statistics
    const AttackStatistics& getStatistics() const { return stats_; }

    // Reset statistics
    void resetStatistics() { stats_ = AttackStatistics(); }

    // Pure virtual: attack interface
    virtual std::string getAttackType() const = 0;
    virtual bool shouldAttackNow() = 0;
};

// ==================== T1: Solo Tampering Attack ====================

/**
 * T1: Solo tampering - Forged creator/witness signatures
 *
 * Attack model:
 * - Attacker tries to inject blocks with forged PQC signatures
 * - May attempt to forge creator signature or witness signatures
 *
 * Mitigation (from paper):
 * - PQC signatures (Falcon-512, Dilithium-3) are computationally infeasible to forge
 * - Anomaly screening with reputation threshold R ≥ 0.5
 * - Digital signature verification at every block reception
 *
 * Parameters:
 * - forge_attempt_rate: Rate of forged signature injection (attacks/sec)
 * - target_creator: Whether to forge creator signatures
 * - target_witnesses: Whether to forge witness signatures
 */
class SoloTamperingAttacker : public BaseAttacker {
private:
    double forge_attempt_rate_;  // attacks per second
    bool target_creator_;
    bool target_witnesses_;
    std::chrono::system_clock::time_point last_attempt_;

public:
    explicit SoloTamperingAttacker(const std::string& id,
                                   double forge_rate = 0.1,
                                   bool target_creator = true,
                                   bool target_witnesses = false)
        : BaseAttacker(id),
          forge_attempt_rate_(forge_rate),
          target_creator_(target_creator),
          target_witnesses_(target_witnesses),
          last_attempt_(std::chrono::system_clock::now()) {}

    std::string getAttackType() const override { return "T1-SoloTampering"; }

    bool shouldAttackNow() override {
        if (!enabled_) return false;

        auto now = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_attempt_).count();

        // Poisson arrival process
        double threshold = 1.0 - std::exp(-forge_attempt_rate_ * elapsed);
        std::uniform_real_distribution<double> dist(0.0, 1.0);

        if (dist(rng_) < threshold) {
            last_attempt_ = now;
            return true;
        }
        return false;
    }

    /**
     * Attempt to forge a block signature
     * This will ALWAYS fail in real implementation due to PQC security
     *
     * @return ForgedBlock structure (will be rejected by verifier)
     */
    Block attemptForgeBlock(const Block& legitimate_block) {
        stats_.recordAttempt(getAttackType());

        Block forged = legitimate_block;

        if (target_creator_) {
            // Attempt to forge creator signature (will fail verification)
            std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
            forged.header.creator_sig.clear();
            for (size_t i = 0; i < 690; ++i) {  // FALCON-512 signature size
                forged.header.creator_sig.push_back(byte_dist(rng_));
            }
        }

        if (target_witnesses_) {
            // NOTE: Legacy witness signature forging removed
            // New attestquorum protocol uses witness_bitmap + TEE attestquorum signature
            // Attacker would need to compromise TEE enclave to forge attestquorum
            // For simulation: Mark witness bitmap but cannot generate valid attestquorum
            forged.header.witness_bitmap.set();  // Set all bits (fake)
            forged.header.attestquorum.clear();  // Cannot forge valid attestquorum
            // This will be detected during attestquorum verification
        }

        // This forged block will be detected by signature verification
        // Detection happens in block validation phase
        return forged;
    }

    void setForgeRate(double rate) { forge_attempt_rate_ = rate; }
    double getForgeRate() const { return forge_attempt_rate_; }
};

// ==================== T2: Regional Majority Attack ====================

/**
 * T2: Regional majority (encirclement) attack
 *
 * Attack model:
 * - Adversary controls β fraction of all vehicles
 * - In a region, βr ≥ β due to spatial clustering
 * - Goal: Dominate witness selection to approve malicious blocks
 *
 * Mitigation (from paper):
 * - OEM cap: pmax = 0.25 (max 25% from any manufacturer)
 * - Manufacturer diversity: Hm ≥ 1.5 bits (Shannon entropy)
 * - Spatial diversity: dmin ≥ 3σtof
 * - Temporal diversity: MADt ≥ δt
 * - Reputation diversity: mini Ri ≥ 0.3, ∃i≠j: |Ri - Rj| ≥ 0.3
 *
 * Parameters:
 * - beta_global: Global adversary fraction (0.0 - 1.0)
 * - beta_regional: Regional adversary fraction (≥ beta_global)
 * - target_oem: OEM identity used by adversary vehicles
 * - clustering_radius: Spatial clustering range (meters)
 */
class RegionalMajorityAttacker : public BaseAttacker {
private:
    double beta_global_;       // β: global adversary fraction
    double beta_regional_;     // βr: regional adversary fraction
    std::string target_oem_;   // OEM identity for adversary vehicles
    double clustering_radius_; // Spatial clustering range (m)

    // Adversary vehicle IDs
    std::vector<std::string> adversary_vehicles_;

public:
    explicit RegionalMajorityAttacker(const std::string& id,
                                     double beta_global = 0.2,
                                     double beta_regional = 0.4,
                                     const std::string& oem = "Adversary-OEM",
                                     double cluster_radius = 100.0)
        : BaseAttacker(id),
          beta_global_(beta_global),
          beta_regional_(beta_regional),
          target_oem_(oem),
          clustering_radius_(cluster_radius) {}

    std::string getAttackType() const override { return "T2-RegionalMajority"; }

    bool shouldAttackNow() override {
        // Regional majority attack is passive (positioning-based)
        // Attack "happens" when adversary vehicles are selected as witnesses
        return enabled_ && !adversary_vehicles_.empty();
    }

    /**
     * Register an adversary vehicle
     */
    void registerAdversaryVehicle(const std::string& vehicle_id) {
        adversary_vehicles_.push_back(vehicle_id);
    }

    /**
     * Check if a vehicle is adversarial
     */
    bool isAdversaryVehicle(const std::string& vehicle_id) const {
        return std::find(adversary_vehicles_.begin(),
                        adversary_vehicles_.end(),
                        vehicle_id) != adversary_vehicles_.end();
    }

    /**
     * Attempt to dominate witness selection in a region
     *
     * @param candidates All witness candidates in region
     * @return Number of adversary vehicles in candidate set
     */
    size_t countAdversaryWitnesses(const std::vector<WitnessCandidate>& candidates) const {
        size_t count = 0;
        for (const auto& c : candidates) {
            if (isAdversaryVehicle(c.id) || c.oem == target_oem_) {
                count++;
            }
        }
        return count;
    }

    /**
     * Check if adversary achieved regional majority
     * (Will be blocked by diversity policy if βr pmax exceeds threshold)
     */
    bool checkRegionalMajority(const std::vector<WitnessCandidate>& selected) {
        stats_.recordAttempt(getAttackType());

        size_t adv_count = countAdversaryWitnesses(selected);
        double adv_fraction = static_cast<double>(adv_count) / selected.size();

        if (adv_fraction >= beta_regional_) {
            stats_.recordSuccess(getAttackType());
            return true;
        }
        return false;
    }

    double getBetaGlobal() const { return beta_global_; }
    double getBetaRegional() const { return beta_regional_; }
    std::string getTargetOEM() const { return target_oem_; }
    size_t getAdversaryCount() const { return adversary_vehicles_.size(); }
};

// ==================== T3: Sybil/Eclipse Attack ====================

/**
 * T3: Sybil/Eclipse attack - Identity inflation or isolation
 *
 * Attack model:
 * - Sybil: Adversary creates multiple fake identities
 * - Eclipse: Adversary isolates victim by surrounding with adversary nodes
 *
 * Mitigation (from paper):
 * - Onboarding cap: ≤ 1 identity per 30 seconds per neighborhood
 * - ToF-bound witnessing: Physical distance verification
 * - RSU cross-checks: Independent validation of vehicle presence
 *
 * Parameters:
 * - sybil_rate: Rate of fake identity creation (identities/sec)
 * - max_sybils: Maximum number of Sybil identities
 * - eclipse_target: Vehicle ID to isolate (optional)
 */
class SybilEclipseAttacker : public BaseAttacker {
private:
    double sybil_rate_;           // Sybil identity creation rate
    size_t max_sybils_;           // Maximum Sybil identities
    std::string eclipse_target_;  // Target vehicle for eclipse attack

    // Sybil identities created
    std::vector<std::string> sybil_identities_;
    std::chrono::system_clock::time_point last_sybil_creation_;

    // Onboarding rate limiter
    static constexpr double ONBOARDING_WINDOW_SEC = 30.0;
    std::map<std::string, std::chrono::system_clock::time_point> onboarding_times_;

public:
    explicit SybilEclipseAttacker(const std::string& id,
                                 double sybil_rate = 0.05,
                                 size_t max_sybils = 10,
                                 const std::string& eclipse_target = "")
        : BaseAttacker(id),
          sybil_rate_(sybil_rate),
          max_sybils_(max_sybils),
          eclipse_target_(eclipse_target),
          last_sybil_creation_(std::chrono::system_clock::now()) {}

    std::string getAttackType() const override { return "T3-SybilEclipse"; }

    bool shouldAttackNow() override {
        if (!enabled_) return false;

        // Check if we can create more Sybils
        if (sybil_identities_.size() >= max_sybils_) {
            return false;
        }

        auto now = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_sybil_creation_).count();

        // Poisson arrival for Sybil creation
        double threshold = 1.0 - std::exp(-sybil_rate_ * elapsed);
        std::uniform_real_distribution<double> dist(0.0, 1.0);

        return dist(rng_) < threshold;
    }

    /**
     * Attempt to create a new Sybil identity
     * (Will be rate-limited by onboarding cap)
     */
    std::string attemptCreateSybil(const std::string& neighborhood_id) {
        stats_.recordAttempt(getAttackType());

        auto now = std::chrono::system_clock::now();

        // Check onboarding rate limit for this neighborhood
        if (onboarding_times_.count(neighborhood_id) > 0) {
            auto last_onboard = onboarding_times_[neighborhood_id];
            auto elapsed = std::chrono::duration<double>(now - last_onboard).count();

            if (elapsed < ONBOARDING_WINDOW_SEC) {
                // Rate limited! Mitigation successful
                stats_.recordMitigation();
                return "";  // Failed to create Sybil
            }
        }

        // Create new Sybil identity
        std::string sybil_id = attacker_id_ + "_sybil_" +
                              std::to_string(sybil_identities_.size());
        sybil_identities_.push_back(sybil_id);
        onboarding_times_[neighborhood_id] = now;
        last_sybil_creation_ = now;

        stats_.recordSuccess(getAttackType());
        return sybil_id;
    }

    /**
     * Check if an identity is a Sybil
     */
    bool isSybilIdentity(const std::string& vehicle_id) const {
        return std::find(sybil_identities_.begin(),
                        sybil_identities_.end(),
                        vehicle_id) != sybil_identities_.end();
    }

    /**
     * Attempt Eclipse attack (surround target with Sybils)
     * Detection: ToF verification will fail for non-physical Sybils
     */
    bool attemptEclipse(const std::string& target_id,
                       const std::vector<std::string>& neighbors) {
        if (eclipse_target_.empty()) {
            eclipse_target_ = target_id;
        }

        stats_.recordAttempt("T3-Eclipse");

        size_t sybil_neighbors = 0;
        for (const auto& n : neighbors) {
            if (isSybilIdentity(n)) {
                sybil_neighbors++;
            }
        }

        // Eclipse successful if majority of neighbors are Sybils
        double sybil_fraction = static_cast<double>(sybil_neighbors) / neighbors.size();
        if (sybil_fraction > 0.5) {
            stats_.recordSuccess("T3-Eclipse");
            return true;
        }
        return false;
    }

    size_t getSybilCount() const { return sybil_identities_.size(); }
    std::string getEclipseTarget() const { return eclipse_target_; }
};

// ==================== T6: Spam/DoS Attack ====================

/**
 * T6: Spam/DoS attack - Resource exhaustion
 *
 * Attack model:
 * - Adversary floods network with high-rate messages
 * - Goal: Exhaust bandwidth, CPU, or memory resources
 *
 * Mitigation (from paper):
 * - Reputation-weighted token buckets
 * - Per-message computational costs
 * - Backpressure mechanisms
 *
 * Parameters:
 * - spam_rate: Message injection rate (msgs/sec)
 * - burst_size: Maximum burst size
 * - target_type: Type of messages to spam (CAM/DENM/CPM/Block)
 */
class SpamDoSAttacker : public BaseAttacker {
private:
    double spam_rate_;        // Messages per second
    size_t burst_size_;       // Maximum burst size
    std::string target_type_; // Message type to spam

    // Rate tracking
    std::chrono::system_clock::time_point last_spam_;
    size_t messages_sent_;

public:
    explicit SpamDoSAttacker(const std::string& id,
                            double spam_rate = 10.0,
                            size_t burst_size = 100,
                            const std::string& target_type = "CAM")
        : BaseAttacker(id),
          spam_rate_(spam_rate),
          burst_size_(burst_size),
          target_type_(target_type),
          last_spam_(std::chrono::system_clock::now()),
          messages_sent_(0) {}

    std::string getAttackType() const override { return "T6-SpamDoS"; }

    bool shouldAttackNow() override {
        if (!enabled_) return false;

        auto now = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_spam_).count();

        // Check if we can send based on spam rate
        double threshold = 1.0 - std::exp(-spam_rate_ * elapsed);
        std::uniform_real_distribution<double> dist(0.0, 1.0);

        return dist(rng_) < threshold;
    }

    /**
     * Attempt to send spam messages
     * (Will be rate-limited by token bucket)
     *
     * @param current_reputation Attacker's current reputation score
     * @return Number of messages actually sent (after rate limiting)
     */
    size_t attemptSpam(double current_reputation) {
        stats_.recordAttempt(getAttackType());

        auto now = std::chrono::system_clock::now();

        // Reputation-weighted token bucket
        // Lower reputation = lower allowed rate
        double effective_rate = spam_rate_ * std::max(0.1, current_reputation);

        auto elapsed = std::chrono::duration<double>(now - last_spam_).count();
        size_t tokens_available = static_cast<size_t>(effective_rate * elapsed);
        tokens_available = std::min(tokens_available, burst_size_);

        if (tokens_available == 0) {
            // Rate limited! Mitigation successful
            stats_.recordMitigation();
            return 0;
        }

        // Send messages (limited by token bucket)
        messages_sent_ += tokens_available;
        last_spam_ = now;

        if (tokens_available < burst_size_) {
            // Partially mitigated
            stats_.recordMitigation();
        } else {
            // Full burst successful
            stats_.recordSuccess(getAttackType());
        }

        return tokens_available;
    }

    void setSpamRate(double rate) { spam_rate_ = rate; }
    double getSpamRate() const { return spam_rate_; }
    size_t getMessagesSent() const { return messages_sent_; }
    std::string getTargetType() const { return target_type_; }
};

// ==================== Attack Coordinator ====================

/**
 * Coordinates multiple concurrent attacks and collects statistics
 */
class AttackCoordinator {
private:
    std::vector<std::unique_ptr<BaseAttacker>> attackers_;
    bool global_enable_;

public:
    AttackCoordinator() : global_enable_(false) {}

    // Add attackers
    void addAttacker(std::unique_ptr<BaseAttacker> attacker) {
        attackers_.push_back(std::move(attacker));
    }

    // Global enable/disable
    void enableAllAttacks(bool enable) {
        global_enable_ = enable;
        for (auto& attacker : attackers_) {
            attacker->setEnabled(enable);
        }
    }

    // Get specific attacker by type
    template<typename T>
    T* getAttacker(const std::string& id) {
        for (auto& attacker : attackers_) {
            if (attacker->getId() == id) {
                return dynamic_cast<T*>(attacker.get());
            }
        }
        return nullptr;
    }

    // Collect all statistics
    std::map<std::string, AttackStatistics> collectStatistics() const {
        std::map<std::string, AttackStatistics> all_stats;
        for (const auto& attacker : attackers_) {
            all_stats[attacker->getId()] = attacker->getStatistics();
        }
        return all_stats;
    }

    // Print summary report
    void printReport() const {
        std::cout << "\n========== ATTACK EVALUATION REPORT ==========\n";
        for (const auto& attacker : attackers_) {
            std::cout << "\n[" << attacker->getAttackType() << "] "
                     << attacker->getId() << ":\n";
            attacker->getStatistics().printSummary();
        }
        std::cout << "==============================================\n";
    }
};

} // namespace security
} // namespace meshchain

#endif // MESHCHAIN_ATTACKER_MODELS_H
