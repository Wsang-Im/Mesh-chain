#ifndef MESHCHAIN_SCALABILITY_METRICS_H
#define MESHCHAIN_SCALABILITY_METRICS_H

/**
 * Scalability Metrics Collector
 *
 * Tracks block creation success rates and network scalability metrics
 * across different vehicle densities (50, 100, 200, 300+ vehicles)
 */

#include "types.h"
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>

namespace meshchain {
namespace common {

struct BlockCreationAttempt {
    std::string vehicle_id;
    Timestamp attempted_at;
    bool success;
    double latency_ms;
    std::string failure_reason;
    size_t witness_count;
    size_t eligible_candidates;
    size_t nearby_vehicles;  // Total vehicles in range
    double position_x;  // Vehicle position for regional analysis
    double position_y;
    std::string nearest_rsu;  // Nearest RSU ID for regional clustering
};

struct DensityMetrics {
    size_t total_vehicles;
    size_t vehicles_in_range_avg;
    size_t vehicles_in_range_max;
    double avg_neighbor_count;
    double max_neighbor_count;
};

class ScalabilityMetrics {
public:
    explicit ScalabilityMetrics(const std::string& output_file = "scalability_metrics.csv")
        : output_file_(output_file), metrics_enabled_(true) {

        // Open CSV file
        csv_file_.open(output_file_, std::ios::out);
        if (csv_file_.is_open()) {
            // Write header
            csv_file_ << "timestamp,vehicle_id,success,latency_ms,failure_reason,"
                      << "witness_count,eligible_candidates,nearby_vehicles,"
                      << "total_vehicles,success_rate,position_x,position_y,nearest_rsu\n";
        }
    }

    ~ScalabilityMetrics() {
        if (csv_file_.is_open()) {
            csv_file_.close();
        }

        // Print final summary
        printSummary();
    }

    /**
     * Record a block creation attempt
     */
    void recordAttempt(const BlockCreationAttempt& attempt) {
        if (!metrics_enabled_) return;

        std::lock_guard<std::mutex> lock(mutex_);

        attempts_.push_back(attempt);

        // Update counters
        if (attempt.success) {
            successful_blocks_++;
            total_latency_ms_ += attempt.latency_ms;
        } else {
            failed_blocks_++;

            // Track failure reasons
            failure_reasons_[attempt.failure_reason]++;
        }

        // Write to CSV
        if (csv_file_.is_open()) {
            auto ts = std::chrono::system_clock::to_time_t(attempt.attempted_at);
            csv_file_ << ts << ","
                      << attempt.vehicle_id << ","
                      << (attempt.success ? "1" : "0") << ","
                      << attempt.latency_ms << ","
                      << attempt.failure_reason << ","
                      << attempt.witness_count << ","
                      << attempt.eligible_candidates << ","
                      << attempt.nearby_vehicles << ","
                      << current_total_vehicles_ << ","
                      << getSuccessRate() << ","
                      << attempt.position_x << ","
                      << attempt.position_y << ","
                      << attempt.nearest_rsu << "\n";
            csv_file_.flush();  // Ensure data is written
        }
    }

    /**
     * Update current vehicle density
     */
    void updateVehicleDensity(size_t total_vehicles, const DensityMetrics& density) {
        std::lock_guard<std::mutex> lock(mutex_);
        current_total_vehicles_ = total_vehicles;
        density_history_.push_back(density);
    }

    /**
     * Get current success rate
     */
    double getSuccessRate() const {
        size_t total = successful_blocks_ + failed_blocks_;
        if (total == 0) return 0.0;
        return (100.0 * successful_blocks_) / total;
    }

    /**
     * Get average latency for successful blocks
     */
    double getAverageLatency() const {
        if (successful_blocks_ == 0) return 0.0;
        return total_latency_ms_ / successful_blocks_;
    }

    /**
     * Print real-time statistics
     */
    void printRealtimeStats() const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::cout << "\n========== Scalability Metrics (Real-time) ==========\n";
        std::cout << "Current vehicles: " << current_total_vehicles_ << "\n";
        std::cout << "Block attempts: " << (successful_blocks_ + failed_blocks_) << "\n";
        std::cout << "  - Successful: " << successful_blocks_
                  << " (" << std::fixed << std::setprecision(1)
                  << getSuccessRate() << "%)\n";
        std::cout << "  - Failed: " << failed_blocks_ << "\n";

        if (successful_blocks_ > 0) {
            std::cout << "Avg latency: " << std::fixed << std::setprecision(2)
                      << getAverageLatency() << "ms\n";
        }

        if (!failure_reasons_.empty()) {
            std::cout << "\nFailure breakdown:\n";
            for (const auto& [reason, count] : failure_reasons_) {
                double pct = (100.0 * count) / failed_blocks_;
                std::cout << "  - " << reason << ": " << count
                          << " (" << std::fixed << std::setprecision(1)
                          << pct << "%)\n";
            }
        }
        std::cout << "====================================================\n\n";
    }

    /**
     * Print final summary
     */
    void printSummary() const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::cout << "\n========== Final Scalability Summary ==========\n";
        std::cout << "Total block attempts: " << (successful_blocks_ + failed_blocks_) << "\n";
        std::cout << "Successful: " << successful_blocks_
                  << " (" << std::fixed << std::setprecision(2)
                  << getSuccessRate() << "%)\n";
        std::cout << "Failed: " << failed_blocks_ << "\n";

        if (successful_blocks_ > 0) {
            std::cout << "Average latency: " << std::fixed << std::setprecision(2)
                      << getAverageLatency() << "ms (target: ≤100ms)\n";
        }

        if (!failure_reasons_.empty()) {
            std::cout << "\nFailure Analysis:\n";
            for (const auto& [reason, count] : failure_reasons_) {
                double pct = (100.0 * count) / failed_blocks_;
                std::cout << "  " << std::setw(40) << std::left << reason
                          << ": " << std::setw(5) << std::right << count
                          << " (" << std::fixed << std::setprecision(1)
                          << std::setw(5) << pct << "%)\n";
            }
        }

        // Density analysis
        if (!density_history_.empty()) {
            size_t total_density = 0;
            size_t max_density = 0;
            for (const auto& d : density_history_) {
                total_density += d.total_vehicles;
                max_density = std::max(max_density, d.total_vehicles);
            }
            double avg_density = static_cast<double>(total_density) / density_history_.size();

            std::cout << "\nVehicle Density:\n";
            std::cout << "  Average: " << std::fixed << std::setprecision(1)
                      << avg_density << " vehicles\n";
            std::cout << "  Peak: " << max_density << " vehicles\n";
        }

        std::cout << "\nMetrics saved to: " << output_file_ << "\n";
        std::cout << "=============================================\n\n";
    }

private:
    std::string output_file_;
    std::ofstream csv_file_;
    bool metrics_enabled_;

    mutable std::mutex mutex_;

    // Counters
    size_t successful_blocks_ = 0;
    size_t failed_blocks_ = 0;
    double total_latency_ms_ = 0.0;
    size_t current_total_vehicles_ = 0;

    // Detailed tracking
    std::vector<BlockCreationAttempt> attempts_;
    std::map<std::string, size_t> failure_reasons_;
    std::vector<DensityMetrics> density_history_;
};

} // namespace common
} // namespace meshchain

#endif // MESHCHAIN_SCALABILITY_METRICS_H
