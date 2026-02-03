#ifndef MESHCHAIN_DENSITY_ANALYZER_H
#define MESHCHAIN_DENSITY_ANALYZER_H

#include "types.h"
#include "spatial_index.h"
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace meshchain {
namespace common {

/**
 * Vehicle Density Analyzer for Mesh-Chain Scalability Testing
 *
 * Analyzes local vehicle density and clustering to demonstrate
 * mesh-chain performance in congested scenarios.
 *
 * Key Metrics:
 * - Local density (vehicles/km²)
 * - Cluster size (max vehicles in communication range)
 * - Regional distribution
 */
class DensityAnalyzer {
public:
    struct VehiclePosition {
        std::string vehicle_id;
        double x, y, z;  // Position in meters
        double timestamp;  // Simulation time
    };

    struct DensityMetrics {
        size_t total_vehicles;
        size_t max_cluster_size;  // Maximum vehicles in 300m range
        double avg_cluster_size;
        double max_local_density;  // vehicles/km²
        double avg_local_density;  // vehicles/km²
        std::map<std::string, size_t> cluster_sizes;  // vehicle_id -> cluster size
        std::vector<std::pair<double, double>> hotspots;  // (x, y) coordinates
    };

    struct RegionalStats {
        double center_x, center_y;  // Region center
        double radius_m;  // Region radius
        size_t vehicle_count;
        double density;  // vehicles/km²
        std::vector<std::string> vehicles;  // Vehicle IDs in region
    };

private:
    std::vector<VehiclePosition> positions_;
    SpatialIndex<std::string> spatial_index_;
    double communication_range_m_;  // DSRC range (default: 300m)

public:
    explicit DensityAnalyzer(double communication_range_m = 300.0)
        : communication_range_m_(communication_range_m) {}

    /**
     * Update vehicle positions
     * @param positions Current vehicle positions
     */
    void update(const std::vector<VehiclePosition>& positions) {
        positions_ = positions;

        // Rebuild spatial index
        std::vector<SpatialIndex<std::string>::Point3D> points;
        for (const auto& pos : positions_) {
            points.emplace_back(pos.x, pos.y, pos.z, pos.vehicle_id);
        }
        spatial_index_.build(points);
    }

    /**
     * Compute density metrics for current vehicle distribution
     */
    DensityMetrics computeMetrics() const {
        DensityMetrics metrics;
        metrics.total_vehicles = positions_.size();

        if (positions_.empty()) {
            metrics.max_cluster_size = 0;
            metrics.avg_cluster_size = 0.0;
            metrics.max_local_density = 0.0;
            metrics.avg_local_density = 0.0;
            return metrics;
        }

        // For each vehicle, count neighbors within communication range
        std::vector<size_t> cluster_sizes;
        double total_density = 0.0;
        double max_density = 0.0;

        for (const auto& pos : positions_) {
            SpatialIndex<std::string>::Point3D query(pos.x, pos.y, pos.z, pos.vehicle_id);
            size_t neighbors = spatial_index_.countInRange(query, communication_range_m_);

            // Cluster size includes the vehicle itself
            size_t cluster_size = neighbors;
            cluster_sizes.push_back(cluster_size);
            metrics.cluster_sizes[pos.vehicle_id] = cluster_size;

            // Calculate local density (vehicles/km²)
            // Area = π * r² (circular region)
            double area_km2 = M_PI * std::pow(communication_range_m_ / 1000.0, 2);
            double density = static_cast<double>(cluster_size) / area_km2;

            total_density += density;
            max_density = std::max(max_density, density);
        }

        // Compute statistics
        metrics.max_cluster_size = *std::max_element(cluster_sizes.begin(), cluster_sizes.end());
        metrics.avg_cluster_size = std::accumulate(cluster_sizes.begin(), cluster_sizes.end(), 0.0) /
                                  cluster_sizes.size();
        metrics.max_local_density = max_density;
        metrics.avg_local_density = total_density / positions_.size();

        // Find hotspots (locations with cluster size > threshold)
        size_t hotspot_threshold = metrics.max_cluster_size * 0.8;  // Top 20%
        for (const auto& pos : positions_) {
            if (metrics.cluster_sizes[pos.vehicle_id] >= hotspot_threshold) {
                metrics.hotspots.emplace_back(pos.x, pos.y);
            }
        }

        return metrics;
    }

    /**
     * Get regional statistics for a specific area
     * @param center_x Center X coordinate
     * @param center_y Center Y coordinate
     * @param radius_m Region radius in meters
     */
    RegionalStats getRegionalStats(double center_x, double center_y, double radius_m) const {
        RegionalStats stats;
        stats.center_x = center_x;
        stats.center_y = center_y;
        stats.radius_m = radius_m;

        SpatialIndex<std::string>::Point3D center(center_x, center_y, 0.0, "");
        auto vehicles_in_region = spatial_index_.rangeQuery(center, radius_m);

        stats.vehicle_count = vehicles_in_region.size();
        for (const auto& v : vehicles_in_region) {
            stats.vehicles.push_back(v.data);
        }

        // Calculate density
        double area_km2 = M_PI * std::pow(radius_m / 1000.0, 2);
        stats.density = static_cast<double>(stats.vehicle_count) / area_km2;

        return stats;
    }

    /**
     * Find largest cluster in the network
     * @return (vehicle_id, cluster_size, center_x, center_y)
     */
    std::tuple<std::string, size_t, double, double> findLargestCluster() const {
        if (positions_.empty()) {
            return {"", 0, 0.0, 0.0};
        }

        std::string max_vehicle_id;
        size_t max_cluster_size = 0;
        double max_x = 0.0, max_y = 0.0;

        for (const auto& pos : positions_) {
            SpatialIndex<std::string>::Point3D query(pos.x, pos.y, pos.z, pos.vehicle_id);
            size_t neighbors = spatial_index_.countInRange(query, communication_range_m_);

            if (neighbors > max_cluster_size) {
                max_cluster_size = neighbors;
                max_vehicle_id = pos.vehicle_id;
                max_x = pos.x;
                max_y = pos.y;
            }
        }

        return {max_vehicle_id, max_cluster_size, max_x, max_y};
    }

    /**
     * Print density report to console
     */
    void printReport() const {
        auto metrics = computeMetrics();
        auto [cluster_center_id, max_cluster, cluster_x, cluster_y] = findLargestCluster();

        std::cout << "\n========== VEHICLE DENSITY REPORT ==========\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Total Vehicles: " << metrics.total_vehicles << "\n";
        std::cout << "Communication Range: " << communication_range_m_ << " m\n\n";

        std::cout << "CLUSTER STATISTICS:\n";
        std::cout << "  Max Cluster Size: " << metrics.max_cluster_size
                 << " vehicles (at " << cluster_center_id << ")\n";
        std::cout << "  Avg Cluster Size: " << metrics.avg_cluster_size << " vehicles\n";
        std::cout << "  Cluster Center: (" << cluster_x << ", " << cluster_y << ")\n\n";

        std::cout << "DENSITY STATISTICS:\n";
        std::cout << "  Max Local Density: " << metrics.max_local_density << " vehicles/km²\n";
        std::cout << "  Avg Local Density: " << metrics.avg_local_density << " vehicles/km²\n\n";

        std::cout << "HOTSPOTS: " << metrics.hotspots.size() << " locations\n";
        if (!metrics.hotspots.empty() && metrics.hotspots.size() <= 5) {
            for (size_t i = 0; i < metrics.hotspots.size(); ++i) {
                std::cout << "  " << (i+1) << ". (" << metrics.hotspots[i].first
                         << ", " << metrics.hotspots[i].second << ")\n";
            }
        }
        std::cout << "============================================\n\n";
    }

    /**
     * Export density data to JSON for visualization
     * @return JSON string
     */
    std::string exportToJSON() const {
        auto metrics = computeMetrics();
        auto [cluster_center_id, max_cluster, cluster_x, cluster_y] = findLargestCluster();

        std::ostringstream json;
        json << std::fixed << std::setprecision(2);
        json << "{\n";
        json << "  \"total_vehicles\": " << metrics.total_vehicles << ",\n";
        json << "  \"communication_range_m\": " << communication_range_m_ << ",\n";
        json << "  \"max_cluster_size\": " << metrics.max_cluster_size << ",\n";
        json << "  \"avg_cluster_size\": " << metrics.avg_cluster_size << ",\n";
        json << "  \"max_local_density\": " << metrics.max_local_density << ",\n";
        json << "  \"avg_local_density\": " << metrics.avg_local_density << ",\n";
        json << "  \"largest_cluster\": {\n";
        json << "    \"vehicle_id\": \"" << cluster_center_id << "\",\n";
        json << "    \"size\": " << max_cluster << ",\n";
        json << "    \"center_x\": " << cluster_x << ",\n";
        json << "    \"center_y\": " << cluster_y << "\n";
        json << "  },\n";
        json << "  \"hotspots\": [\n";
        for (size_t i = 0; i < metrics.hotspots.size(); ++i) {
            json << "    {\"x\": " << metrics.hotspots[i].first
                << ", \"y\": " << metrics.hotspots[i].second << "}";
            if (i < metrics.hotspots.size() - 1) json << ",";
            json << "\n";
        }
        json << "  ]\n";
        json << "}\n";

        return json.str();
    }

    /**
     * Get current vehicle count
     */
    size_t getVehicleCount() const {
        return positions_.size();
    }
};

} // namespace common
} // namespace meshchain

#endif // MESHCHAIN_DENSITY_ANALYZER_H
