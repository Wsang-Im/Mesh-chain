#ifndef MESHCHAIN_DIVERSITY_METRICS_H
#define MESHCHAIN_DIVERSITY_METRICS_H

#include <vector>
#include <string>
#include <map>
#include <cmath>
#include <algorithm>
#include <numeric>
#include "../common/types.h"

namespace meshchain {
namespace vehicle {

/**
 * Multi-Dimensional Diversity Policy (Algorithm from Paper Section 3.2)
 *
 * Enforces four diversity dimensions:
 * 1. Manufacturer diversity: Shannon entropy H_m >= 1.5 bits
 * 2. Spatial diversity: d_min >= 3*sigma_tof
 * 3. Temporal diversity: MAD_t >= delta_t
 * 4. Reputation diversity: min R_i >= 0.3 and exists |R_i - R_j| >= 0.3
 */

struct WitnessCandidate {
    std::string id;
    std::string manufacturer;  // OEM identifier
    double x, y;              // GPS coordinates (meters)
    double contact_time;      // Contact duration (seconds)
    double reputation;        // R in [0, 1]
    uint64_t first_seen_ts;   // Timestamp of first contact (ns)
};

struct DiversityMetrics {
    // Manufacturer diversity
    double shannon_entropy;          // H_m = -sum(p_i * log2(p_i))
    std::map<std::string, size_t> oem_counts;

    // Spatial diversity
    double min_distance;             // d_min (meters)
    double sigma_tof;                // ToF estimator std dev

    // Temporal diversity
    double mad_t;                    // Median Absolute Deviation of contact times

    // Reputation diversity
    double min_reputation;
    double max_reputation_diff;      // max|R_i - R_j|

    // Serialization for commitment
    std::vector<uint8_t> serialize() const;
};

struct DiversityPolicy {
    double min_entropy = 1.5;        // bits
    double spatial_multiplier = 3.0; // d_min >= 3*sigma_tof
    double min_mad_t = 5.0;          // seconds
    double min_reputation = 0.3;
    double min_rep_diff = 0.3;
    double max_oem_fraction = 0.25;  // p_max (per-OEM cap)
};

class DiversityMetricsCalculator {
public:
    explicit DiversityMetricsCalculator(const DiversityPolicy& policy = DiversityPolicy())
        : policy_(policy) {}

    /**
     * Compute all diversity metrics for a witness set
     */
    DiversityMetrics computeMetrics(const std::vector<WitnessCandidate>& witnesses) {
        DiversityMetrics metrics;

        if (witnesses.empty()) {
            return metrics;
        }

        // 1. Manufacturer diversity (Shannon entropy)
        metrics.shannon_entropy = computeManufacturerEntropy(witnesses, metrics.oem_counts);

        // 2. Spatial diversity (minimum pairwise distance)
        metrics.min_distance = computeMinDistance(witnesses);
        metrics.sigma_tof = 0.003;  // 3 meters for UWB at 10ns tolerance

        // 3. Temporal diversity (MAD of contact durations)
        metrics.mad_t = computeMAD(witnesses);

        // 4. Reputation diversity
        computeReputationMetrics(witnesses, metrics.min_reputation,
                                metrics.max_reputation_diff);

        return metrics;
    }

    /**
     * Verify if metrics satisfy policy constraints
     */
    bool verifyPolicy(const DiversityMetrics& metrics, size_t num_witnesses) const {
        // Check manufacturer diversity
        if (metrics.shannon_entropy < policy_.min_entropy) {
            return false;
        }

        // Check per-OEM cap
        for (const auto& [oem, count] : metrics.oem_counts) {
            double fraction = static_cast<double>(count) / num_witnesses;
            if (fraction > policy_.max_oem_fraction) {
                return false;
            }
        }

        // Check spatial diversity
        double required_min_dist = policy_.spatial_multiplier * metrics.sigma_tof;
        if (metrics.min_distance < required_min_dist) {
            return false;
        }

        // Check temporal diversity
        if (metrics.mad_t < policy_.min_mad_t) {
            return false;
        }

        // Check reputation diversity
        if (metrics.min_reputation < policy_.min_reputation) {
            return false;
        }
        if (metrics.max_reputation_diff < policy_.min_rep_diff) {
            return false;
        }

        return true;
    }

    /**
     * Compute effective adversarial rate beta_eff = min{beta, p_max}
     */
    double computeBetaEffective(double beta_global,
                               const std::map<std::string, size_t>& oem_counts,
                               size_t total) const {
        if (oem_counts.empty()) {
            return beta_global;
        }

        // Find maximum OEM fraction
        double max_oem_fraction = 0.0;
        for (const auto& [oem, count] : oem_counts) {
            double fraction = static_cast<double>(count) / total;
            max_oem_fraction = std::max(max_oem_fraction, fraction);
        }

        return std::min(beta_global, max_oem_fraction);
    }

private:
    DiversityPolicy policy_;

    /**
     * Shannon entropy: H_m = -sum(p_i * log2(p_i))
     * where p_i = |witnesses from OEM_i| / w
     */
    double computeManufacturerEntropy(const std::vector<WitnessCandidate>& witnesses,
                                     std::map<std::string, size_t>& oem_counts) {
        oem_counts.clear();

        // Count occurrences of each manufacturer
        for (const auto& w : witnesses) {
            oem_counts[w.manufacturer]++;
        }

        double entropy = 0.0;
        size_t total = witnesses.size();

        for (const auto& [oem, count] : oem_counts) {
            double p_i = static_cast<double>(count) / total;
            if (p_i > 0) {
                entropy -= p_i * std::log2(p_i);
            }
        }

        return entropy;
    }

    /**
     * Compute minimum pairwise Euclidean distance
     */
    double computeMinDistance(const std::vector<WitnessCandidate>& witnesses) {
        if (witnesses.size() < 2) {
            return 0.0;
        }

        double min_dist = std::numeric_limits<double>::max();

        for (size_t i = 0; i < witnesses.size(); ++i) {
            for (size_t j = i + 1; j < witnesses.size(); ++j) {
                double dx = witnesses[i].x - witnesses[j].x;
                double dy = witnesses[i].y - witnesses[j].y;
                double dist = std::sqrt(dx*dx + dy*dy);
                min_dist = std::min(min_dist, dist);
            }
        }

        return min_dist;
    }

    /**
     * Compute Median Absolute Deviation (MAD) of contact times
     * MAD = median(|x_i - median(x)|)
     */
    double computeMAD(const std::vector<WitnessCandidate>& witnesses) {
        if (witnesses.empty()) {
            return 0.0;
        }

        std::vector<double> contact_times;
        for (const auto& w : witnesses) {
            contact_times.push_back(w.contact_time);
        }

        // Compute median
        std::sort(contact_times.begin(), contact_times.end());
        double median = 0.0;
        size_t n = contact_times.size();
        if (n % 2 == 0) {
            median = (contact_times[n/2-1] + contact_times[n/2]) / 2.0;
        } else {
            median = contact_times[n/2];
        }

        // Compute absolute deviations
        std::vector<double> deviations;
        for (double t : contact_times) {
            deviations.push_back(std::abs(t - median));
        }

        // Compute MAD (median of deviations)
        std::sort(deviations.begin(), deviations.end());
        if (n % 2 == 0) {
            return (deviations[n/2-1] + deviations[n/2]) / 2.0;
        } else {
            return deviations[n/2];
        }
    }

    /**
     * Compute reputation metrics
     */
    void computeReputationMetrics(const std::vector<WitnessCandidate>& witnesses,
                                  double& min_rep, double& max_diff) {
        if (witnesses.empty()) {
            min_rep = 0.0;
            max_diff = 0.0;
            return;
        }

        min_rep = 1.0;
        double max_rep = 0.0;

        for (const auto& w : witnesses) {
            min_rep = std::min(min_rep, w.reputation);
            max_rep = std::max(max_rep, w.reputation);
        }

        max_diff = max_rep - min_rep;
    }
};

/**
 * Serialization for commitment (canonical CBOR)
 */
inline std::vector<uint8_t> DiversityMetrics::serialize() const {
    std::vector<uint8_t> result;

    // Simplified canonical serialization (in production, use CBOR library)
    auto append_double = [&result](double val) {
        uint64_t bits;
        std::memcpy(&bits, &val, sizeof(double));
        for (int i = 7; i >= 0; --i) {
            result.push_back((bits >> (i*8)) & 0xFF);
        }
    };

    append_double(shannon_entropy);
    append_double(min_distance);
    append_double(sigma_tof);
    append_double(mad_t);
    append_double(min_reputation);
    append_double(max_reputation_diff);

    return result;
}

} // namespace vehicle
} // namespace meshchain

#endif // MESHCHAIN_DIVERSITY_METRICS_H
