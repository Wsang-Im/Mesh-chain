#ifndef MESHCHAIN_SPATIAL_INDEX_H
#define MESHCHAIN_SPATIAL_INDEX_H

#include "types.h"
#include <vector>
#include <memory>
#include <algorithm>
#include <cmath>
#include <limits>
#include <optional>

namespace meshchain {
namespace common {

/**
 * 3D Spatial Index using KD-Tree for fast nearest neighbor queries
 *
 * Used to optimize witness selection in dense vehicle scenarios (300+ vehicles).
 * Reduces neighbor search from O(n) to O(log n) average case.
 *
 * Performance:
 * - Build: O(n log n)
 * - Range query: O(n^(2/3) + k) where k = results
 * - k-NN query: O(log n + k)
 */
template<typename T>
class SpatialIndex {
public:
    struct Point3D {
        double x, y, z;
        T data;  // Associated data (e.g., VehicleID)

        Point3D() : x(0), y(0), z(0) {}
        Point3D(double x_, double y_, double z_, const T& data_)
            : x(x_), y(y_), z(z_), data(data_) {}

        double distanceTo(const Point3D& other) const {
            double dx = x - other.x;
            double dy = y - other.y;
            double dz = z - other.z;
            return std::sqrt(dx*dx + dy*dy + dz*dz);
        }

        double get(size_t axis) const {
            switch(axis) {
                case 0: return x;
                case 1: return y;
                case 2: return z;
                default: return 0;
            }
        }

        // Comparison operator for std::pair in max-heap
        // (not used directly, but required by STL)
        bool operator<(const Point3D& other) const {
            if (x != other.x) return x < other.x;
            if (y != other.y) return y < other.y;
            return z < other.z;
        }
    };

private:
    struct Node {
        Point3D point;
        std::unique_ptr<Node> left;
        std::unique_ptr<Node> right;
        size_t axis;  // Split axis (0=x, 1=y, 2=z)

        Node(const Point3D& p, size_t a) : point(p), axis(a) {}
    };

    std::unique_ptr<Node> root_;
    size_t size_;
    static constexpr size_t K = 3;  // 3D space

public:
    SpatialIndex() : size_(0) {}

    /**
     * Build index from points
     * @param points Vector of 3D points with associated data
     */
    void build(std::vector<Point3D> points) {
        size_ = points.size();
        root_ = buildRecursive(points, 0, points.size(), 0);
    }

    /**
     * Find all points within range of query point
     * @param query Center point
     * @param range_m Maximum distance in meters
     * @return Vector of points within range, sorted by distance
     */
    std::vector<Point3D> rangeQuery(const Point3D& query, double range_m) const {
        std::vector<Point3D> results;
        if (root_) {
            rangeQueryRecursive(root_.get(), query, range_m, results);
        }

        // Sort by distance
        std::sort(results.begin(), results.end(),
            [&query](const Point3D& a, const Point3D& b) {
                return a.distanceTo(query) < b.distanceTo(query);
            });

        return results;
    }

    /**
     * Find k nearest neighbors
     * @param query Center point
     * @param k Number of neighbors to find
     * @return Vector of k nearest points, sorted by distance
     */
    std::vector<Point3D> kNearestNeighbors(const Point3D& query, size_t k) const {
        if (k == 0 || !root_) return {};

        std::vector<std::pair<double, Point3D>> heap;  // Max-heap of (distance, point)
        knnRecursive(root_.get(), query, k, heap);

        // Extract points and sort by distance (ascending)
        std::vector<Point3D> results;
        results.reserve(heap.size());
        for (const auto& [dist, point] : heap) {
            results.push_back(point);
        }

        std::sort(results.begin(), results.end(),
            [&query](const Point3D& a, const Point3D& b) {
                return a.distanceTo(query) < b.distanceTo(query);
            });

        return results;
    }

    /**
     * Count points within range (faster than rangeQuery if you only need count)
     */
    size_t countInRange(const Point3D& query, double range_m) const {
        size_t count = 0;
        if (root_) {
            countInRangeRecursive(root_.get(), query, range_m, count);
        }
        return count;
    }

    /**
     * Get total number of points in index
     */
    size_t size() const { return size_; }

    /**
     * Check if index is empty
     */
    bool empty() const { return size_ == 0; }

    /**
     * Clear the index
     */
    void clear() {
        root_.reset();
        size_ = 0;
    }

private:
    /**
     * Recursively build KD-Tree
     * @param points Point array (will be reordered)
     * @param start Start index
     * @param end End index (exclusive)
     * @param depth Current tree depth (determines split axis)
     */
    std::unique_ptr<Node> buildRecursive(std::vector<Point3D>& points,
                                         size_t start, size_t end, size_t depth) {
        if (start >= end) return nullptr;

        size_t axis = depth % K;
        size_t mid = start + (end - start) / 2;

        // Partition around median
        std::nth_element(points.begin() + start,
                        points.begin() + mid,
                        points.begin() + end,
                        [axis](const Point3D& a, const Point3D& b) {
                            return a.get(axis) < b.get(axis);
                        });

        auto node = std::make_unique<Node>(points[mid], axis);
        node->left = buildRecursive(points, start, mid, depth + 1);
        node->right = buildRecursive(points, mid + 1, end, depth + 1);

        return node;
    }

    /**
     * Recursive range query
     */
    void rangeQueryRecursive(const Node* node, const Point3D& query,
                            double range_m, std::vector<Point3D>& results) const {
        if (!node) return;

        double dist = node->point.distanceTo(query);
        if (dist <= range_m) {
            results.push_back(node->point);
        }

        // Check if we need to search children
        double axis_dist = query.get(node->axis) - node->point.get(node->axis);

        if (axis_dist < 0) {
            // Query is left of split
            rangeQueryRecursive(node->left.get(), query, range_m, results);
            if (std::abs(axis_dist) <= range_m) {
                // Range crosses split plane, check right too
                rangeQueryRecursive(node->right.get(), query, range_m, results);
            }
        } else {
            // Query is right of split
            rangeQueryRecursive(node->right.get(), query, range_m, results);
            if (std::abs(axis_dist) <= range_m) {
                // Range crosses split plane, check left too
                rangeQueryRecursive(node->left.get(), query, range_m, results);
            }
        }
    }

    /**
     * Recursive k-NN search using max-heap
     */
    void knnRecursive(const Node* node, const Point3D& query, size_t k,
                     std::vector<std::pair<double, Point3D>>& heap) const {
        if (!node) return;

        double dist = node->point.distanceTo(query);

        // Add to heap if we have room or if closer than farthest
        if (heap.size() < k) {
            heap.push_back({dist, node->point});
            std::push_heap(heap.begin(), heap.end());
        } else if (dist < heap.front().first) {
            std::pop_heap(heap.begin(), heap.end());
            heap.back() = {dist, node->point};
            std::push_heap(heap.begin(), heap.end());
        }

        // Decide which subtree to search first
        double axis_dist = query.get(node->axis) - node->point.get(node->axis);
        const Node* near = (axis_dist < 0) ? node->left.get() : node->right.get();
        const Node* far = (axis_dist < 0) ? node->right.get() : node->left.get();

        // Always search near side
        knnRecursive(near, query, k, heap);

        // Search far side if necessary
        if (heap.size() < k || std::abs(axis_dist) < heap.front().first) {
            knnRecursive(far, query, k, heap);
        }
    }

    /**
     * Recursive count in range
     */
    void countInRangeRecursive(const Node* node, const Point3D& query,
                              double range_m, size_t& count) const {
        if (!node) return;

        if (node->point.distanceTo(query) <= range_m) {
            count++;
        }

        double axis_dist = query.get(node->axis) - node->point.get(node->axis);

        if (axis_dist < 0) {
            countInRangeRecursive(node->left.get(), query, range_m, count);
            if (std::abs(axis_dist) <= range_m) {
                countInRangeRecursive(node->right.get(), query, range_m, count);
            }
        } else {
            countInRangeRecursive(node->right.get(), query, range_m, count);
            if (std::abs(axis_dist) <= range_m) {
                countInRangeRecursive(node->left.get(), query, range_m, count);
            }
        }
    }
};

} // namespace common
} // namespace meshchain

#endif // MESHCHAIN_SPATIAL_INDEX_H
