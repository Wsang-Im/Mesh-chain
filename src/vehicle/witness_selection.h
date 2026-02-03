#ifndef MESHCHAIN_WITNESS_SELECTION_H
#define MESHCHAIN_WITNESS_SELECTION_H

#include "../common/types.h"
#include "../common/block.h"
#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <iostream>

namespace meshchain {
namespace vehicle {

/**
 * Witness Selection and Diversity Enforcement
 *
 * Critical requirements from paper (Section 3.2):
 * 1. Manufacturer diversity: H_m ≥ 1.5 bits (Shannon entropy)
 * 2. Spatial diversity: d_min ≥ 3σ_tof (estimator-aware)
 * 3. Temporal diversity: MAD_t ≥ δ_t (heterogeneous contact durations)
 * 4. Reputation diversity: min_i R_i ≥ 0.3 and ∃i≠j: |R_i - R_j| ≥ 0.3
 */
class WitnessSelector {
public:
    struct Policy {
        double min_H_m;  // Minimum OEM entropy (default: 1.5 bits)
        double p_max;    // Per-OEM cap (default: 0.25)
        double min_d_m;  // Minimum spatial separation in meters
        double min_MAD_t;  // Minimum temporal heterogeneity
        double min_R;    // Minimum reputation (default: 0.3)
        double min_R_diff;  // Minimum reputation difference (default: 0.3)
    };

    struct DiversityCheckResult {
        bool passed;
        std::string failure_reason;
        DiversityMetrics metrics;

        DiversityCheckResult() : passed(true), failure_reason("") {}
    };

private:
    Policy policy_;

public:
    explicit WitnessSelector(const Policy& policy) : policy_(policy) {}

    /**
     * Select witnesses from candidates with diversity enforcement
     *
     * @param candidates Available witness candidates
     * @param profile Desired witness profile (w, τ)
     * @param sigma_tof ToF estimator standard deviation
     * @return Selected witnesses or empty if insufficient diversity
     */
    std::vector<WitnessCandidate> selectWitnesses(
            const std::vector<WitnessCandidate>& candidates,
            const WitnessProfile& profile,
            double sigma_tof) {

        std::cout << "  [selectWitnesses] Input: " << candidates.size()
                  << " candidates, need " << profile.w << " witnesses\n";

        if (candidates.size() < profile.w) {
            std::cout << "  [selectWitnesses] ❌ Insufficient candidates\n";
            return {};  // Insufficient candidates
        }

        // Filter eligible candidates
        std::vector<WitnessCandidate> eligible;
        for (const auto& c : candidates) {
            if (c.isEligible(policy_.min_R)) {
                eligible.push_back(c);
            }
        }

        std::cout << "  [selectWitnesses] Eligible: " << eligible.size()
                  << " (R >= " << policy_.min_R << ")\n";

        if (eligible.size() < profile.w) {
            std::cout << "  [selectWitnesses] ❌ Insufficient eligible\n";
            return {};  // Insufficient eligible
        }

        // Print OEM distribution
        std::map<std::string, size_t> oem_counts;
        for (const auto& c : eligible) {
            oem_counts[c.oem]++;
        }
        std::cout << "  [selectWitnesses] OEM distribution: ";
        for (const auto& [oem, count] : oem_counts) {
            std::cout << oem << "=" << count << " ";
        }
        std::cout << "\n";

        // Try to select diverse set (greedy approach with backtracking)
        std::vector<WitnessCandidate> selected;
        if (!greedySelect(eligible, profile.w, sigma_tof, selected)) {
            std::cout << "  [selectWitnesses] ❌ greedySelect failed\n";
            return {};  // Could not meet diversity requirements
        }

        std::cout << "  [selectWitnesses] ✓ greedySelect succeeded with "
                  << selected.size() << " witnesses\n";
        return selected;
    }

    /**
     * Compute diversity metrics for a witness set
     */
    DiversityMetrics computeDiversity(
            const std::vector<WitnessCandidate>& witnesses) const {

        DiversityMetrics metrics;

        // 1. Manufacturer diversity (Shannon entropy)
        metrics.H_m = computeOEMEntropy(witnesses);

        // 2. Spatial diversity (minimum pairwise distance)
        metrics.d_min = computeMinDistance(witnesses);

        // 3. Temporal diversity (MAD of contact times)
        metrics.MAD_t = computeTemporalMAD(witnesses);

        // 4. Reputation statistics
        metrics.min_R = std::numeric_limits<double>::max();
        for (const auto& w : witnesses) {
            metrics.min_R = std::min(metrics.min_R, w.reputation.R);
            metrics.R_profile.push_back(w.reputation.R);
        }

        return metrics;
    }

    /**
     * Verify diversity metrics against policy
     */
    bool verifyDiversity(const DiversityMetrics& metrics,
                        double sigma_tof) const {
        // Check OEM entropy
        if (metrics.H_m < policy_.min_H_m) {
            return false;
        }

        // Check spatial separation (d_min ≥ 3σ_tof * c or policy min_d_m)
        double required_dmin = std::max(
            3.0 * sigma_tof * SPEED_OF_LIGHT_M_PER_NS,
            policy_.min_d_m
        );
        if (metrics.d_min < required_dmin) {
            return false;
        }

        // Check temporal heterogeneity (relaxed in simulation if min_MAD_t is set)
        if (policy_.min_MAD_t > 0.0 && metrics.MAD_t < policy_.min_MAD_t) {
            return false;
        }

        // Check reputation constraints
        if (metrics.min_R < policy_.min_R) {
            return false;
        }

        // Check reputation diversity (∃i≠j: |R_i - R_j| ≥ 0.3)
        // Skip if only one witness
        if (metrics.R_profile.size() <= 1) {
            return true;  // Single witness doesn't need diversity check
        }

        bool has_rep_diversity = false;
        for (size_t i = 0; i < metrics.R_profile.size(); ++i) {
            for (size_t j = i + 1; j < metrics.R_profile.size(); ++j) {
                if (std::abs(metrics.R_profile[i] - metrics.R_profile[j]) >=
                    policy_.min_R_diff) {
                    has_rep_diversity = true;
                    break;
                }
            }
            if (has_rep_diversity) break;
        }

        if (!has_rep_diversity && metrics.R_profile.size() > 1) {
            return false;
        }

        return true;
    }

    /**
     * Verify diversity metrics with detailed failure reason
     */
    DiversityCheckResult verifyDiversityDetailed(const DiversityMetrics& metrics, double sigma_tof) const {
        DiversityCheckResult result;
        result.metrics = metrics;

        // Check OEM entropy (H_m ≥ 1.5)
        if (metrics.H_m < policy_.min_H_m) {
            result.passed = false;
            result.failure_reason = "OEM entropy too low: H_m = " +
                std::to_string(metrics.H_m) + " < " + std::to_string(policy_.min_H_m) +
                " (need more manufacturer diversity)";
            return result;
        }

        // Check spatial separation (d_min ≥ 3σ_tof * c or policy min_d_m)
        double required_dmin = std::max(
            3.0 * sigma_tof * SPEED_OF_LIGHT_M_PER_NS,
            policy_.min_d_m
        );
        if (metrics.d_min < required_dmin) {
            result.passed = false;
            result.failure_reason = "Spatial separation too small: d_min = " +
                std::to_string(metrics.d_min) + "m < " + std::to_string(required_dmin) +
                "m (3σ_tof=" + std::to_string(3.0 * sigma_tof * SPEED_OF_LIGHT_M_PER_NS) +
                "m, policy min=" + std::to_string(policy_.min_d_m) + "m)";
            return result;
        }

        // Check temporal heterogeneity (skip if min_MAD_t is 0)
        if (policy_.min_MAD_t > 0.0 && metrics.MAD_t < policy_.min_MAD_t) {
            result.passed = false;
            result.failure_reason = "Temporal heterogeneity too low: MAD_t = " +
                std::to_string(metrics.MAD_t) + "s < " + std::to_string(policy_.min_MAD_t) +
                "s (witnesses too similar in contact time)";
            return result;
        }

        // Check reputation constraints
        if (metrics.min_R < policy_.min_R) {
            result.passed = false;
            result.failure_reason = "Minimum reputation too low: min_R = " +
                std::to_string(metrics.min_R) + " < " + std::to_string(policy_.min_R);
            return result;
        }

        // Check reputation diversity (∃i≠j: |R_i - R_j| ≥ 0.3)
        bool has_rep_diversity = false;
        double max_R_diff = 0.0;
        for (size_t i = 0; i < metrics.R_profile.size(); ++i) {
            for (size_t j = i + 1; j < metrics.R_profile.size(); ++j) {
                double diff = std::abs(metrics.R_profile[i] - metrics.R_profile[j]);
                max_R_diff = std::max(max_R_diff, diff);
                if (diff >= policy_.min_R_diff) {
                    has_rep_diversity = true;
                    break;
                }
            }
            if (has_rep_diversity) break;
        }

        if (!has_rep_diversity && metrics.R_profile.size() > 1) {
            result.passed = false;
            result.failure_reason = "Reputation diversity too low: max_diff = " +
                std::to_string(max_R_diff) + " < " + std::to_string(policy_.min_R_diff) +
                " (all witnesses have similar reputation)";
            return result;
        }

        result.passed = true;
        result.failure_reason = "";
        return result;
    }

private:
    /**
     * Compute Shannon entropy of OEM distribution
     * H_m = -Σ p_i log2(p_i), where p_i = |witnesses from OEM_i| / w
     */
    double computeOEMEntropy(const std::vector<WitnessCandidate>& witnesses) const {
        if (witnesses.empty()) return 0.0;

        // Count vehicles per OEM
        std::map<std::string, size_t> oem_counts;
        for (const auto& w : witnesses) {
            oem_counts[w.oem]++;
        }

        // Calculate Shannon entropy
        double entropy = 0.0;
        double w = static_cast<double>(witnesses.size());
        for (const auto& [oem, count] : oem_counts) {
            double p_i = static_cast<double>(count) / w;
            if (p_i > 0.0) {
                entropy -= p_i * std::log2(p_i);
            }
        }

        return entropy;
    }

    /**
     * Compute minimum pairwise distance
     */
    double computeMinDistance(const std::vector<WitnessCandidate>& witnesses) const {
        if (witnesses.size() < 2) return 0.0;

        double min_dist = std::numeric_limits<double>::max();
        for (size_t i = 0; i < witnesses.size(); ++i) {
            for (size_t j = i + 1; j < witnesses.size(); ++j) {
                double dist = std::abs(witnesses[i].distance_m - witnesses[j].distance_m);
                min_dist = std::min(min_dist, dist);
            }
        }

        return min_dist;
    }

    /**
     * Compute Median Absolute Deviation of contact times
     * MAD_t measures temporal heterogeneity
     */
    double computeTemporalMAD(const std::vector<WitnessCandidate>& witnesses) const {
        if (witnesses.size() < 2) return 0.0;

        // Calculate contact durations in seconds
        std::vector<double> durations;
        auto now = std::chrono::system_clock::now();
        for (const auto& w : witnesses) {
            auto duration = now - w.first_contact;
            double seconds = std::chrono::duration<double>(duration).count();
            durations.push_back(seconds);
        }

        // Find median
        std::sort(durations.begin(), durations.end());
        double median;
        if (durations.size() % 2 == 0) {
            median = (durations[durations.size()/2 - 1] +
                     durations[durations.size()/2]) / 2.0;
        } else {
            median = durations[durations.size()/2];
        }

        // Calculate MAD
        std::vector<double> abs_deviations;
        for (double d : durations) {
            abs_deviations.push_back(std::abs(d - median));
        }
        std::sort(abs_deviations.begin(), abs_deviations.end());

        double mad;
        if (abs_deviations.size() % 2 == 0) {
            mad = (abs_deviations[abs_deviations.size()/2 - 1] +
                  abs_deviations[abs_deviations.size()/2]) / 2.0;
        } else {
            mad = abs_deviations[abs_deviations.size()/2];
        }

        return mad;
    }

    /**
     * Greedy selection with diversity constraints
     */
    bool greedySelect(const std::vector<WitnessCandidate>& eligible,
                     size_t target_count,
                     double sigma_tof,
                     std::vector<WitnessCandidate>& selected) {

        selected.clear();

        // Group by OEM for diversity enforcement
        std::map<std::string, std::vector<WitnessCandidate>> by_oem;
        for (const auto& c : eligible) {
            by_oem[c.oem].push_back(c);
        }

        // Calculate per-OEM cap (use ceil to avoid over-constraining)
        // With p_max=0.25 and w=7: ceil(1.75)=2, allowing enough flexibility
        size_t per_oem_cap = static_cast<size_t>(
            std::ceil(policy_.p_max * target_count)
        );

        // Greedy selection with rotation among OEMs
        std::vector<std::string> oems;
        for (const auto& [oem, _] : by_oem) {
            oems.push_back(oem);
        }

        std::map<std::string, size_t> oem_selected_count;
        size_t oem_idx = 0;

        while (selected.size() < target_count && oem_idx < oems.size() * target_count) {
            std::string current_oem = oems[oem_idx % oems.size()];
            oem_idx++;

            // Check if OEM cap reached
            if (oem_selected_count[current_oem] >= per_oem_cap) {
                continue;
            }

            // Find best candidate from this OEM
            const auto& candidates = by_oem[current_oem];
            for (const auto& candidate : candidates) {
                // Check if already selected
                bool already_selected = false;
                for (const auto& s : selected) {
                    if (s.id == candidate.id) {
                        already_selected = true;
                        break;
                    }
                }
                if (already_selected) continue;

                // Check spatial separation constraint
                bool spatial_ok = true;
                // Use policy's min_d_m (respects fallback relaxation)
                double required_sep = std::max(
                    3.0 * sigma_tof * SPEED_OF_LIGHT_M_PER_NS,
                    policy_.min_d_m
                );
                for (const auto& s : selected) {
                    double dist = std::abs(candidate.distance_m - s.distance_m);
                    if (dist < required_sep) {
                        spatial_ok = false;
                        break;
                    }
                }

                if (spatial_ok) {
                    selected.push_back(candidate);
                    oem_selected_count[current_oem]++;
                    break;
                }
            }
        }

        // Verify final diversity
        if (selected.size() < target_count) {
            // Debug: why did we fail to select enough?
            std::cout << "    [greedySelect] selected " << selected.size()
                     << " < target " << target_count << std::endl;
            std::cout << "    OEM distribution: ";
            for (const auto& [oem, count] : oem_selected_count) {
                std::cout << oem << "=" << count << " ";
            }
            std::cout << "\n    Per-OEM cap: " << per_oem_cap << std::endl;
            return false;
        }

        DiversityMetrics metrics = computeDiversity(selected);
        bool diversity_ok = verifyDiversity(metrics, sigma_tof);

        if (!diversity_ok) {
            auto detailed = verifyDiversityDetailed(metrics, sigma_tof);
            std::cout << "    [greedySelect] final diversity check failed - "
                     << detailed.failure_reason << std::endl;
        } else {
            std::cout << "    [greedySelect] ✓ Diversity check passed: H_m="
                     << metrics.H_m << ", d_min=" << metrics.d_min << "m\n";
        }

        return diversity_ok;
    }
};

} // namespace vehicle
} // namespace meshchain

#endif // MESHCHAIN_WITNESS_SELECTION_H
