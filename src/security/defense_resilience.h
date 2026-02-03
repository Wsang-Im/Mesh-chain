#ifndef MESHCHAIN_DEFENSE_RESILIENCE_H
#define MESHCHAIN_DEFENSE_RESILIENCE_H

/**
 * Defense Resilience Measurement Framework
 *
 * Framework for systematically measuring and analyzing attack response capabilities
 *
 * Key Features:
 * 1. Measure effectiveness of each defense mechanism
 * 2. Calculate attack detection and blocking rates
 * 3. Analyze False Positives/Negatives
 * 4. Measure performance overhead
 * 5. Monitor system stability
 */

#include "../common/types.h"
#include "../common/block.h"
#include "attacker_models.h"
#include <vector>
#include <map>
#include <chrono>
#include <mutex>
#include <fstream>
#include <iomanip>
#include <cmath>

namespace meshchain {
namespace security {

// ==================== Defense Mechanisms ====================

/**
 * Defense Mechanism Types
 */
enum class DefenseMechanism {
    SIGNATURE_VERIFICATION,   // PQC signature verification
    REPUTATION_SCREENING,     // Reputation-based screening
    DIVERSITY_VALIDATION,     // Witness diversity validation
    TOF_PROXIMITY_CHECK,      // ToF distance measurement verification
    RATE_LIMITING,            // Rate limiting
    WITNESS_CONSENSUS,        // Witness consensus verification
    TEE_ATTESTATION,          // TEE attestation verification
    MERKLE_PROOF,             // Merkle proof verification
};

/**
 * Statistics per Defense Mechanism
 */
struct DefenseStats {
    std::string mechanism_name;
    size_t blocks_checked = 0;
    size_t attacks_detected = 0;
    size_t false_positives = 0;    // Legitimate mistaken as attack
    size_t false_negatives = 0;    // Attack mistaken as legitimate
    double avg_check_time_us = 0.0;
    double max_check_time_us = 0.0;
    std::chrono::system_clock::time_point last_detection;

    // Detection rate (True Positive Rate)
    double getDetectionRate() const {
        size_t total_attacks = attacks_detected + false_negatives;
        return total_attacks > 0 ?
            static_cast<double>(attacks_detected) / total_attacks : 0.0;
    }

    // False Positive Rate
    double getFalsePositiveRate() const {
        size_t total_legitimate = blocks_checked - (attacks_detected + false_negatives);
        return total_legitimate > 0 ?
            static_cast<double>(false_positives) / total_legitimate : 0.0;
    }

    // Precision (Positive Predictive Value)
    double getPrecision() const {
        size_t total_flagged = attacks_detected + false_positives;
        return total_flagged > 0 ?
            static_cast<double>(attacks_detected) / total_flagged : 0.0;
    }

    // F1 Score (harmonic mean of precision and recall)
    double getF1Score() const {
        double precision = getPrecision();
        double recall = getDetectionRate();
        return (precision + recall) > 0 ?
            2.0 * (precision * recall) / (precision + recall) : 0.0;
    }
};

// ==================== Attack Impact Metrics ====================

/**
 * Attack Impact Metrics
 */
struct AttackImpactMetrics {
    // System integrity
    size_t total_blocks_created = 0;
    size_t malicious_blocks_rejected = 0;
    size_t malicious_blocks_accepted = 0;  // False negatives!

    // Network health
    double network_throughput_degradation = 0.0;  // %
    double avg_block_latency_increase_ms = 0.0;
    size_t honest_vehicles_affected = 0;

    // Security metrics
    double chain_integrity_score = 1.0;  // [0,1], 1 = perfect
    double consensus_reliability = 1.0;   // [0,1]
    double witness_diversity_score = 1.0; // [0,1]

    // Economic impact (optional)
    size_t gas_wasted_on_spam = 0;
    size_t valid_transactions_delayed = 0;

    void updateChainIntegrity() {
        if (total_blocks_created > 0) {
            chain_integrity_score = 1.0 -
                static_cast<double>(malicious_blocks_accepted) / total_blocks_created;
        }
    }
};

// ==================== Defense Resilience Tracker ====================

/**
 * Defense Capability Tracking System
 */
class DefenseResilienceTracker {
private:
    std::map<DefenseMechanism, DefenseStats> defense_stats_;
    AttackImpactMetrics impact_metrics_;

    // Timing
    std::chrono::system_clock::time_point test_start_time_;
    std::chrono::system_clock::time_point test_end_time_;

    // Thread safety
    mutable std::mutex stats_mutex_;

    // Configuration
    bool verbose_logging_ = false;
    std::string log_file_path_;

public:
    DefenseResilienceTracker() {
        // Initialize defense mechanisms
        initializeDefenseStats();
        test_start_time_ = std::chrono::system_clock::now();
    }

    void setVerbose(bool verbose) { verbose_logging_ = verbose; }
    void setLogFile(const std::string& path) { log_file_path_ = path; }

    /**
     * Record defense mechanism check
     */
    void recordDefenseCheck(DefenseMechanism mechanism,
                           bool is_attack,
                           bool detected,
                           double check_time_us) {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        auto& stats = defense_stats_[mechanism];
        stats.blocks_checked++;

        if (is_attack) {
            if (detected) {
                stats.attacks_detected++;
                stats.last_detection = std::chrono::system_clock::now();
            } else {
                stats.false_negatives++;
                impact_metrics_.malicious_blocks_accepted++;
            }
        } else {
            if (detected) {
                stats.false_positives++;
            }
        }

        // Update timing stats
        stats.avg_check_time_us =
            (stats.avg_check_time_us * (stats.blocks_checked - 1) + check_time_us) /
            stats.blocks_checked;
        stats.max_check_time_us = std::max(stats.max_check_time_us, check_time_us);

        if (verbose_logging_ && is_attack) {
            std::cout << "[Defense] " << getMechanismName(mechanism)
                      << (detected ? " ✓ BLOCKED" : " ✗ MISSED")
                      << " attack in " << std::fixed << std::setprecision(2)
                      << check_time_us << "μs\n";
        }
    }

    /**
     * Record block creation
     */
    void recordBlockCreation(bool is_malicious, bool was_accepted) {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        impact_metrics_.total_blocks_created++;

        if (is_malicious) {
            if (was_accepted) {
                impact_metrics_.malicious_blocks_accepted++;
            } else {
                impact_metrics_.malicious_blocks_rejected++;
            }
        }

        impact_metrics_.updateChainIntegrity();
    }

    /**
     * Record network performance impact
     */
    void recordPerformanceImpact(double throughput_degradation_pct,
                                double latency_increase_ms,
                                size_t affected_vehicles) {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        impact_metrics_.network_throughput_degradation = throughput_degradation_pct;
        impact_metrics_.avg_block_latency_increase_ms = latency_increase_ms;
        impact_metrics_.honest_vehicles_affected = affected_vehicles;
    }

    /**
     * Generate defense capability report
     */
    void generateReport(std::ostream& out) const {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        auto test_end = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            test_end - test_start_time_).count();

        out << "\n";
        out << "╔══════════════════════════════════════════════════════════════╗\n";
        out << "║           DEFENSE RESILIENCE ANALYSIS REPORT                 ║\n";
        out << "╚══════════════════════════════════════════════════════════════╝\n";
        out << "\n";

        // Test duration
        out << "Test Duration: " << duration << " seconds\n";
        out << "\n";

        // Overall Impact Metrics
        out << "--- Attack Impact Metrics ---\n";
        out << "  Total blocks created:        " << impact_metrics_.total_blocks_created << "\n";
        out << "  Malicious blocks rejected:   " << impact_metrics_.malicious_blocks_rejected << "\n";
        out << "  Malicious blocks accepted:   " << impact_metrics_.malicious_blocks_accepted
            << " ⚠️\n";
        out << "  Chain integrity score:       "
            << std::fixed << std::setprecision(4)
            << impact_metrics_.chain_integrity_score * 100.0 << "%\n";

        if (impact_metrics_.network_throughput_degradation > 0) {
            out << "  Network degradation:         "
                << std::fixed << std::setprecision(2)
                << impact_metrics_.network_throughput_degradation << "%\n";
            out << "  Avg latency increase:        "
                << impact_metrics_.avg_block_latency_increase_ms << "ms\n";
        }
        out << "\n";

        // Defense Mechanism Performance
        out << "--- Defense Mechanism Effectiveness ---\n";
        out << std::left;
        out << std::setw(25) << "Mechanism"
            << std::setw(12) << "Checked"
            << std::setw(12) << "Detected"
            << std::setw(10) << "FP"
            << std::setw(10) << "FN"
            << std::setw(10) << "TPR"
            << std::setw(10) << "FPR"
            << std::setw(10) << "F1"
            << std::setw(12) << "Avg Time"
            << "\n";
        out << std::string(110, '-') << "\n";

        for (const auto& [mechanism, stats] : defense_stats_) {
            if (stats.blocks_checked > 0) {
                out << std::setw(25) << stats.mechanism_name
                    << std::setw(12) << stats.blocks_checked
                    << std::setw(12) << stats.attacks_detected
                    << std::setw(10) << stats.false_positives
                    << std::setw(10) << stats.false_negatives
                    << std::setw(10) << std::fixed << std::setprecision(3)
                    << stats.getDetectionRate()
                    << std::setw(10) << std::fixed << std::setprecision(3)
                    << stats.getFalsePositiveRate()
                    << std::setw(10) << std::fixed << std::setprecision(3)
                    << stats.getF1Score()
                    << std::setw(12) << std::fixed << std::setprecision(2)
                    << stats.avg_check_time_us << "μs"
                    << "\n";
            }
        }
        out << "\n";

        // Overall Defense Score
        double overall_detection_rate = calculateOverallDetectionRate();
        double overall_fpr = calculateOverallFPR();
        double overall_f1 = calculateOverallF1();

        out << "--- Overall Defense Performance ---\n";
        out << "  Detection Rate (TPR):        "
            << std::fixed << std::setprecision(2)
            << overall_detection_rate * 100.0 << "%\n";
        out << "  False Positive Rate:         "
            << std::fixed << std::setprecision(4)
            << overall_fpr * 100.0 << "%\n";
        out << "  F1 Score:                    "
            << std::fixed << std::setprecision(4)
            << overall_f1 << "\n";
        out << "\n";

        // Security Grade
        std::string grade = calculateSecurityGrade(overall_detection_rate,
                                                   overall_fpr,
                                                   impact_metrics_.chain_integrity_score);
        out << "  🛡️  SECURITY GRADE: " << grade << "\n";
        out << "\n";

        // Recommendations
        generateRecommendations(out);
    }

    /**
     * Export CSV format report (for paper data)
     */
    void exportCSV(const std::string& filename) const {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        std::ofstream csv(filename);
        if (!csv.is_open()) {
            std::cerr << "Failed to open CSV file: " << filename << "\n";
            return;
        }

        // Header
        csv << "mechanism,blocks_checked,attacks_detected,false_positives,false_negatives,"
            << "detection_rate,fpr,precision,f1_score,avg_check_time_us,max_check_time_us\n";

        // Data
        for (const auto& [mechanism, stats] : defense_stats_) {
            if (stats.blocks_checked > 0) {
                csv << stats.mechanism_name << ","
                    << stats.blocks_checked << ","
                    << stats.attacks_detected << ","
                    << stats.false_positives << ","
                    << stats.false_negatives << ","
                    << std::fixed << std::setprecision(6)
                    << stats.getDetectionRate() << ","
                    << stats.getFalsePositiveRate() << ","
                    << stats.getPrecision() << ","
                    << stats.getF1Score() << ","
                    << stats.avg_check_time_us << ","
                    << stats.max_check_time_us << "\n";
            }
        }

        csv.close();
        std::cout << "✓ Defense metrics exported to: " << filename << "\n";
    }

    /**
     * Analyze defense effectiveness by attack type
     */
    void analyzeDefenseByAttackType(const AttackStatistics& attack_stats) const {
        std::cout << "\n--- Defense Effectiveness by Attack Type ---\n";

        for (const auto& [attack_type, attempts] : attack_stats.attempts_by_type) {
            auto success_it = attack_stats.success_by_type.find(attack_type);
            size_t successes = (success_it != attack_stats.success_by_type.end()) ?
                              success_it->second : 0;

            double block_rate = attempts > 0 ?
                1.0 - (static_cast<double>(successes) / attempts) : 1.0;

            std::cout << "  " << std::left << std::setw(20) << attack_type
                      << ": " << std::right << std::setw(4) << successes
                      << "/" << std::setw(4) << attempts
                      << " succeeded (blocked: "
                      << std::fixed << std::setprecision(1)
                      << block_rate * 100.0 << "%)\n";
        }
        std::cout << "\n";
    }

private:
    void initializeDefenseStats() {
        defense_stats_[DefenseMechanism::SIGNATURE_VERIFICATION] =
            {"Signature Verify", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::REPUTATION_SCREENING] =
            {"Reputation Screen", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::DIVERSITY_VALIDATION] =
            {"Diversity Check", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::TOF_PROXIMITY_CHECK] =
            {"ToF Proximity", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::RATE_LIMITING] =
            {"Rate Limiting", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::WITNESS_CONSENSUS] =
            {"Witness Consensus", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::TEE_ATTESTATION] =
            {"TEE Attestation", 0, 0, 0, 0, 0.0, 0.0};
        defense_stats_[DefenseMechanism::MERKLE_PROOF] =
            {"Merkle Proof", 0, 0, 0, 0, 0.0, 0.0};
    }

    std::string getMechanismName(DefenseMechanism mechanism) const {
        auto it = defense_stats_.find(mechanism);
        return (it != defense_stats_.end()) ? it->second.mechanism_name : "Unknown";
    }

    double calculateOverallDetectionRate() const {
        size_t total_attacks = 0;
        size_t total_detected = 0;

        for (const auto& [_, stats] : defense_stats_) {
            total_attacks += (stats.attacks_detected + stats.false_negatives);
            total_detected += stats.attacks_detected;
        }

        return total_attacks > 0 ?
            static_cast<double>(total_detected) / total_attacks : 0.0;
    }

    double calculateOverallFPR() const {
        size_t total_legitimate = 0;
        size_t total_fp = 0;

        for (const auto& [_, stats] : defense_stats_) {
            size_t legitimate = stats.blocks_checked -
                (stats.attacks_detected + stats.false_negatives);
            total_legitimate += legitimate;
            total_fp += stats.false_positives;
        }

        return total_legitimate > 0 ?
            static_cast<double>(total_fp) / total_legitimate : 0.0;
    }

    double calculateOverallF1() const {
        double tpr = calculateOverallDetectionRate();
        double fpr = calculateOverallFPR();
        double precision = (tpr > 0 || fpr > 0) ? tpr / (tpr + fpr) : 0.0;

        return (precision + tpr) > 0 ?
            2.0 * (precision * tpr) / (precision + tpr) : 0.0;
    }

    std::string calculateSecurityGrade(double detection_rate,
                                       double fpr,
                                       double integrity) const {
        // Weighted score: 50% detection, 30% low FPR, 20% integrity
        double score = (detection_rate * 0.5) +
                      ((1.0 - fpr) * 0.3) +
                      (integrity * 0.2);

        if (score >= 0.95) return "A+ (Excellent)";
        if (score >= 0.90) return "A  (Very Good)";
        if (score >= 0.85) return "B+ (Good)";
        if (score >= 0.80) return "B  (Satisfactory)";
        if (score >= 0.70) return "C  (Needs Improvement)";
        return "D  (Poor)";
    }

    void generateRecommendations(std::ostream& out) const {
        out << "--- Security Recommendations ---\n";

        // Check each mechanism
        bool has_recommendations = false;

        for (const auto& [mechanism, stats] : defense_stats_) {
            if (stats.blocks_checked > 0) {
                double tpr = stats.getDetectionRate();
                double fpr = stats.getFalsePositiveRate();

                if (tpr < 0.9) {
                    out << "  ⚠️  " << stats.mechanism_name
                        << ": Low detection rate ("
                        << std::fixed << std::setprecision(1) << tpr * 100.0
                        << "%) - consider stricter validation\n";
                    has_recommendations = true;
                }

                if (fpr > 0.05) {
                    out << "  ⚠️  " << stats.mechanism_name
                        << ": High false positive rate ("
                        << std::fixed << std::setprecision(2) << fpr * 100.0
                        << "%) - consider tuning thresholds\n";
                    has_recommendations = true;
                }
            }
        }

        if (impact_metrics_.chain_integrity_score < 0.99) {
            out << "  ⚠️  Chain integrity compromised - strengthen consensus requirements\n";
            has_recommendations = true;
        }

        if (!has_recommendations) {
            out << "  ✓ All defense mechanisms performing well\n";
        }

        out << "\n";
    }
};

} // namespace security
} // namespace meshchain

#endif // MESHCHAIN_DEFENSE_RESILIENCE_H
