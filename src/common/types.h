#ifndef MESHCHAIN_TYPES_H
#define MESHCHAIN_TYPES_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <optional>
#include <chrono>

namespace meshchain {

// Type aliases
using Hash256 = std::array<uint8_t, 32>;
using VehicleID = std::string;
using Timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>;
using Nonce = uint64_t;

// Constants from paper
constexpr double TOF_TOLERANCE_NS = 10.0;  // εtof ≤ 10ns
constexpr size_t MAX_WITNESS_COUNT = 7;
constexpr size_t MIN_WITNESS_COUNT = 3;
constexpr double WITNESS_THRESHOLD_RATIO = 0.6;  // τ = ⌈0.6w⌉
constexpr uint64_t LOCAL_FINALITY_TARGET_MS = 100;  // ≤100ms p99
constexpr uint64_t TOF_PHASE_MAX_MS = 20;  // Paper specification: Phase C ≤20ms
constexpr uint64_t SIG_COLLECTION_MAX_MS = 200;  // Increased for MAC layer delays (was 50ms)
constexpr size_t FALCON512_SIG_SIZE = 690;
constexpr size_t FALCON512_PK_SIZE = 897;
constexpr size_t DILITHIUM3_SIG_SIZE = 3293;
constexpr double MIN_REPUTATION = 0.3;  // Paper specification: min_R ≥ 0.3
constexpr double MAX_REPUTATION = 1.0;
constexpr double MIN_OEM_ENTROPY = 1.5;  // Hm ≥ 1.5 bits
constexpr double SPEED_OF_LIGHT_M_PER_NS = 0.299792458;  // Speed of light in m/ns

// Malicious block detection parameters
constexpr double MALICIOUS_PENALTY_BASE = 0.15;  // P (>> learning_rate)
constexpr double MALICIOUS_PENALTY_MAX = 0.5;
constexpr double ACCURATE_REPORT_REWARD = 0.05;  // Q
constexpr double INCONSISTENCY_THRESHOLD = 0.5;  // 50% of witnesses
constexpr double WITNESS_CONFIDENCE_MIN = 0.3;
constexpr double BLACKLIST_THRESHOLD = 0.2;
constexpr int BLACKLIST_DURATION_SECONDS = 3600;  // 1 hour

// Witness profile configurations
struct WitnessProfile {
    size_t w;  // witness count
    size_t tau;  // threshold τ = ⌈0.6w⌉

    static WitnessProfile fromAvailable(size_t available, bool high_threat = false) {
        if (available < 3) return {0, 0};  // FALLBACK_RSU
        else if (available <= 5) return {3, 2};
        else if (available <= 10) return {5, 3};
        else {
            size_t t = high_threat ? 5 : 5;  // Can increase to 6 for high threat if w=7
            return {7, t};
        }
    }
};

// ToF (Time of Flight) measurement
struct ToFTranscript {
    Nonce nonce;
    Timestamp t0;  // Challenge sent
    Timestamp t1;  // Response received
    std::vector<uint8_t> pi_hw;  // Hardware proof (optional)

    // Calculate round-trip time in nanoseconds
    double getRTT_ns() const {
        auto duration = t1 - t0;
        return std::chrono::duration<double, std::nano>(duration).count();
    }

    // Check if ToF is within tolerance
    bool isValid(double max_rtt_ns, double jitter_ns) const {
        double rtt = getRTT_ns();
        return rtt <= max_rtt_ns && jitter_ns <= TOF_TOLERANCE_NS;
    }
};

// Diversity metrics (Section 3.2)
struct DiversityMetrics {
    double H_m;  // Manufacturer entropy (Shannon)
    double d_min;  // Minimum spatial separation
    double MAD_t;  // Temporal heterogeneity (Median Absolute Deviation)
    double min_R;  // Minimum reputation
    std::vector<double> R_profile;  // Reputation distribution

    // Check if metrics meet policy requirements
    bool meetsPolicy(double required_Hm = MIN_OEM_ENTROPY,
                     double required_dmin = 0.0,  // Will be set to 3*σ_tof
                     double required_MADt = 0.0,
                     double required_minR = 0.3) const {
        return H_m >= required_Hm &&
               d_min >= required_dmin &&
               MAD_t >= required_MADt &&
               min_R >= required_minR;
    }
};

// Commitment to diversity certificate
using DiversityCert = Hash256;

// Block states
enum class BlockState {
    TENTATIVE,      // 0-2 witnesses
    LOCALLY_FINAL,  // τ valid diverse witness signatures
    ANCHORED        // Included in RSU/cloud anchor
};

// Anchor levels
enum class AnchorLevel {
    L1,  // Local (per-RSU, 30-60s)
    L2,  // Regional (multi-RSU, 60-180s)
    L3   // Global (cloud, 300-600s)
};

// Reputation score
struct Reputation {
    double R;  // [0, 1]
    Timestamp last_updated;
    uint64_t total_interactions;
    uint64_t valid_interactions;

    // Malicious behavior tracking
    uint64_t malicious_reports_count;     // How many times reported as malicious
    uint64_t accurate_reports_count;      // How many accurate inconsistency reports
    double malicious_penalty_accumulated; // Cumulative penalty from malicious behavior

    Reputation() : R(0.5), total_interactions(0), valid_interactions(0),
                   malicious_reports_count(0), accurate_reports_count(0),
                   malicious_penalty_accumulated(0.0) {
        last_updated = std::chrono::system_clock::now();
    }

    void update(bool valid, double learning_rate = 0.01) {  // Slower learning rate
        total_interactions++;
        if (valid) valid_interactions++;

        // Exponential moving average with slow decay
        R = (1.0 - learning_rate) * R + learning_rate * (valid ? 1.0 : 0.0);
        R = std::max(MIN_REPUTATION, std::min(MAX_REPUTATION, R));
        last_updated = std::chrono::system_clock::now();
    }

    // Apply malicious behavior penalty (P >> M)
    void applyMaliciousPenalty(double penalty) {
        malicious_reports_count++;
        malicious_penalty_accumulated += penalty;

        R = std::max(0.0, R - penalty);
        R = std::max(MIN_REPUTATION, std::min(MAX_REPUTATION, R));
        last_updated = std::chrono::system_clock::now();
    }

    // Apply reward for accurate inconsistency reporting
    void applyReportReward(double reward) {
        accurate_reports_count++;

        R = std::min(MAX_REPUTATION, R + reward);
        last_updated = std::chrono::system_clock::now();
    }
};

// Blacklist entry for malicious vehicles
struct BlacklistEntry {
    VehicleID vehicle_id;
    Timestamp blacklisted_at;
    Timestamp expires_at;
    std::string reason;
    double severity;  // 0.0 ~ 1.0

    BlacklistEntry() : severity(0.0) {}

    BlacklistEntry(const VehicleID& vid, const std::string& rsn, double sev, int duration_sec)
        : vehicle_id(vid), reason(rsn), severity(sev) {
        blacklisted_at = std::chrono::system_clock::now();
        expires_at = blacklisted_at + std::chrono::seconds(duration_sec);
    }

    bool isActive() const {
        return std::chrono::system_clock::now() < expires_at;
    }

    int64_t remainingSeconds() const {
        auto now = std::chrono::system_clock::now();
        if (now >= expires_at) return 0;
        return std::chrono::duration_cast<std::chrono::seconds>(expires_at - now).count();
    }
};

// Off-chain data pointer
struct DataPointer {
    Hash256 hash;
    std::string tier;  // "hot", "warm", "cold"
    size_t t;  // Shamir threshold
    size_t n;  // Shamir total shares
    std::vector<std::string> share_locations;
};

} // namespace meshchain

#endif // MESHCHAIN_TYPES_H
