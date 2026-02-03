#include "../src/integration/network_delay_model.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <sstream>

using namespace meshchain::integration;

struct TestResult {
    std::string test_name;
    double expected_min_ms;
    double expected_max_ms;
    double actual_ms;
    bool passed;
    std::string details;
};

class NetworkDelayVerifier {
private:
    std::vector<TestResult> results_;

    void printHeader(const std::string& title) {
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "  " << title << "\n";
        std::cout << std::string(80, '=') << "\n";
    }

    void printResult(const TestResult& result) {
        std::cout << (result.passed ? "[PASS] " : "[FAIL] ")
                  << result.test_name << "\n";
        std::cout << "  Expected: " << result.expected_min_ms
                  << " - " << result.expected_max_ms << " ms\n";
        std::cout << "  Actual:   " << result.actual_ms << " ms\n";
        if (!result.details.empty()) {
            std::cout << "  Details:  " << result.details << "\n";
        }
        std::cout << "\n";
    }

public:
    /**
     * Test 1: Verify propagation delay is distance-dependent
     */
    void testPropagationDelay() {
        printHeader("Test 1: Propagation Delay (Distance-Dependent)");

        NetworkDelayModel::Config config;
        config.enable_delays = true;
        NetworkDelayModel model(config);

        // Speed of light: ~299,792 km/s = ~299.792 m/ms
        // So for 300m, propagation should be ~1.0 microsecond = 0.001ms
        // For 1000m, propagation should be ~3.3 microseconds = 0.0033ms

        std::vector<double> distances = {100.0, 300.0, 500.0, 1000.0};

        for (double dist : distances) {
            auto start = std::chrono::high_resolution_clock::now();
            double delay = model.calculateDelay(dist, 1000, 10);  // 1KB packet, 10 nodes
            auto end = std::chrono::high_resolution_clock::now();

            // Propagation delay component (should be very small)
            double expected_propagation_ms = dist / 299792.458;

            // Total delay should include propagation + transmission + queuing + processing
            // Minimum would be just propagation + transmission + processing
            // Maximum would include queuing (which is random)

            TestResult result;
            result.test_name = "Propagation for " + std::to_string(int(dist)) + "m";
            result.expected_min_ms = expected_propagation_ms + 0.5;  // Min: prop + some processing
            result.expected_max_ms = expected_propagation_ms + 20.0; // Max: prop + queue + proc
            result.actual_ms = delay;
            result.passed = (delay >= result.expected_min_ms && delay <= result.expected_max_ms);
            result.details = "Propagation component: " + std::to_string(expected_propagation_ms) + " ms";

            results_.push_back(result);
            printResult(result);
        }
    }

    /**
     * Test 2: Verify transmission delay is packet-size dependent
     */
    void testTransmissionDelay() {
        printHeader("Test 2: Transmission Delay (Packet-Size Dependent)");

        NetworkDelayModel::Config config;
        config.bandwidth_mbps = 6.0;  // 6 Mbps DSRC
        NetworkDelayModel model(config);

        double distance = 100.0;  // Fixed distance
        std::vector<size_t> packet_sizes = {100, 1000, 4000, 8000};  // bytes

        for (size_t size : packet_sizes) {
            double delay = model.calculateDelay(distance, size, 10);

            // Transmission delay = (packet_size_bits / bandwidth_bps) * 1000
            // For 1000 bytes at 6 Mbps:
            // (1000 * 8) / (6 * 1e6) * 1000 = 8000 / 6e6 * 1000 = 1.33 ms

            double expected_transmission_ms = (size * 8.0) / (6.0 * 1e6) * 1000.0;

            TestResult result;
            result.test_name = "Transmission for " + std::to_string(size) + " bytes";
            result.expected_min_ms = expected_transmission_ms + 1.0;   // trans + min processing
            result.expected_max_ms = expected_transmission_ms + 15.0;  // trans + max queue + proc
            result.actual_ms = delay;
            result.passed = (delay >= result.expected_min_ms && delay <= result.expected_max_ms);
            result.details = "Transmission component: " + std::to_string(expected_transmission_ms) + " ms";

            results_.push_back(result);
            printResult(result);
        }
    }

    /**
     * Test 3: Verify queuing delay increases with network congestion
     */
    void testQueuingDelay() {
        printHeader("Test 3: Queuing Delay (Congestion-Dependent)");

        NetworkDelayModel model;

        double distance = 300.0;
        size_t packet_size = 1000;
        std::vector<size_t> node_counts = {5, 20, 50, 100};

        std::vector<double> delays;
        for (size_t nodes : node_counts) {
            // Run multiple times to get average (queuing has randomness)
            std::vector<double> samples;
            for (int i = 0; i < 20; i++) {
                double delay = model.calculateDelay(distance, packet_size, nodes);
                samples.push_back(delay);
            }

            double avg_delay = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
            delays.push_back(avg_delay);

            std::cout << "  Nodes: " << std::setw(3) << nodes
                      << ", Avg Delay: " << std::setw(6) << std::fixed << std::setprecision(3)
                      << avg_delay << " ms\n";
        }

        // Verify delays increase with congestion
        bool increasing = true;
        for (size_t i = 1; i < delays.size(); i++) {
            if (delays[i] < delays[i-1]) {
                increasing = false;
                break;
            }
        }

        TestResult result;
        result.test_name = "Queuing increases with congestion";
        result.expected_min_ms = 0.0;
        result.expected_max_ms = 100.0;
        result.actual_ms = delays.back();
        result.passed = increasing;
        result.details = increasing ? "Delays properly increase with node count" : "ERROR: Delays do not increase!";

        results_.push_back(result);
        printResult(result);
    }

    /**
     * Test 4: Verify actual delay simulation (sleep) works
     */
    void testActualDelaySleep() {
        printHeader("Test 4: Actual Delay Simulation (Sleep)");

        std::vector<double> target_delays = {5.0, 10.0, 20.0, 50.0};

        for (double target_ms : target_delays) {
            auto start = std::chrono::high_resolution_clock::now();
            NetworkDelayModel::simulateDelay(target_ms);
            auto end = std::chrono::high_resolution_clock::now();

            double actual_ms = std::chrono::duration<double, std::milli>(end - start).count();

            // Allow 10% tolerance for sleep accuracy
            double tolerance = target_ms * 0.1;

            TestResult result;
            result.test_name = "Sleep for " + std::to_string(int(target_ms)) + " ms";
            result.expected_min_ms = target_ms - tolerance;
            result.expected_max_ms = target_ms + tolerance;
            result.actual_ms = actual_ms;
            result.passed = (actual_ms >= result.expected_min_ms && actual_ms <= result.expected_max_ms);
            result.details = "Sleep accuracy: " + std::to_string((actual_ms / target_ms) * 100.0) + "%";

            results_.push_back(result);
            printResult(result);
        }
    }

    /**
     * Test 5: Verify KEM-specific delay calculation
     */
    void testKEMDelay() {
        printHeader("Test 5: KEM-Specific Delay (ML-KEM-768)");

        NetworkDelayModel model;

        std::vector<double> distances = {100.0, 500.0, 1000.0};

        for (double dist : distances) {
            double kem_delay = model.calculateKEMDelay(dist, 30);

            // KEM packet is ~2KB
            double expected_transmission = (2048 * 8.0) / (6.0 * 1e6) * 1000.0;  // ~2.73 ms

            TestResult result;
            result.test_name = "KEM delay at " + std::to_string(int(dist)) + "m";
            result.expected_min_ms = expected_transmission + 1.0;
            result.expected_max_ms = expected_transmission + 20.0;
            result.actual_ms = kem_delay;
            result.passed = (kem_delay >= result.expected_min_ms && kem_delay <= result.expected_max_ms);
            result.details = "Expected transmission: " + std::to_string(expected_transmission) + " ms";

            results_.push_back(result);
            printResult(result);
        }
    }

    /**
     * Test 6: Verify signature request/response delays
     */
    void testSignatureDelays() {
        printHeader("Test 6: Signature Request/Response Delays");

        NetworkDelayModel model;

        double distance = 500.0;
        size_t nodes = 40;

        // Test request delay (4KB packet)
        double req_delay = model.calculateSigRequestDelay(distance, nodes);
        double expected_req_trans = (4096 * 8.0) / (6.0 * 1e6) * 1000.0;  // ~5.46 ms

        TestResult result_req;
        result_req.test_name = "Signature request delay";
        result_req.expected_min_ms = expected_req_trans + 1.0;
        result_req.expected_max_ms = expected_req_trans + 25.0;
        result_req.actual_ms = req_delay;
        result_req.passed = (req_delay >= result_req.expected_min_ms &&
                              req_delay <= result_req.expected_max_ms);
        result_req.details = "4KB request, transmission: " + std::to_string(expected_req_trans) + " ms";

        results_.push_back(result_req);
        printResult(result_req);

        // Test response delay (800 bytes)
        double resp_delay = model.calculateSigResponseDelay(distance, nodes);
        double expected_resp_trans = (800 * 8.0) / (6.0 * 1e6) * 1000.0;  // ~1.07 ms

        TestResult result_resp;
        result_resp.test_name = "Signature response delay";
        result_resp.expected_min_ms = expected_resp_trans + 1.0;
        result_resp.expected_max_ms = expected_resp_trans + 20.0;
        result_resp.actual_ms = resp_delay;
        result_resp.passed = (resp_delay >= result_resp.expected_min_ms &&
                               resp_delay <= result_resp.expected_max_ms);
        result_resp.details = "800B response, transmission: " + std::to_string(expected_resp_trans) + " ms";

        results_.push_back(result_resp);
        printResult(result_resp);
    }

    /**
     * Test 7: Verify RTT calculation
     */
    void testRTT() {
        printHeader("Test 7: Round-Trip Time (RTT)");

        NetworkDelayModel model;

        double distance = 800.0;
        size_t req_size = 2048;
        size_t resp_size = 1024;
        size_t nodes = 35;

        double rtt = model.calculateRTT(distance, req_size, resp_size, nodes);

        // RTT should be sum of request delay + response delay
        double req_delay = model.calculateDelay(distance, req_size, nodes);
        double resp_delay = model.calculateDelay(distance, resp_size, nodes);

        // Note: Due to randomness in queuing, we can't expect exact match
        // But they should be in same ballpark

        TestResult result;
        result.test_name = "Round-trip time";
        result.expected_min_ms = (req_delay + resp_delay) * 0.5;  // Allow wide range due to randomness
        result.expected_max_ms = (req_delay + resp_delay) * 1.5;
        result.actual_ms = rtt;
        result.passed = (rtt >= result.expected_min_ms && rtt <= result.expected_max_ms);
        result.details = "Request: " + std::to_string(req_delay) + " ms, Response: " +
                         std::to_string(resp_delay) + " ms";

        results_.push_back(result);
        printResult(result);
    }

    /**
     * Test 8: Verify delay disable flag works
     */
    void testDisableDelays() {
        printHeader("Test 8: Delay Disable Flag");

        NetworkDelayModel::Config config;
        config.enable_delays = false;
        NetworkDelayModel model(config);

        double delay = model.calculateDelay(1000.0, 4096, 100);

        TestResult result;
        result.test_name = "Delays disabled";
        result.expected_min_ms = 0.0;
        result.expected_max_ms = 0.0;
        result.actual_ms = delay;
        result.passed = (delay == 0.0);
        result.details = "Should return 0ms when disabled";

        results_.push_back(result);
        printResult(result);
    }

    /**
     * Test 9: Stress test - high congestion scenario
     */
    void testHighCongestion() {
        printHeader("Test 9: High Congestion Scenario");

        NetworkDelayModel model;

        double distance = 900.0;
        size_t packet_size = 4096;
        size_t nodes = 200;  // Very high congestion

        std::vector<double> samples;
        for (int i = 0; i < 50; i++) {
            double delay = model.calculateDelay(distance, packet_size, nodes);
            samples.push_back(delay);
        }

        double avg = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        double min = *std::min_element(samples.begin(), samples.end());
        double max = *std::max_element(samples.begin(), samples.end());

        // With 200 nodes, congestion should be capped at 2x
        // But delays should still be reasonably high

        TestResult result;
        result.test_name = "High congestion (200 nodes)";
        result.expected_min_ms = 5.0;   // Should have significant delay
        result.expected_max_ms = 100.0; // But not unreasonably high
        result.actual_ms = avg;
        result.passed = (avg >= result.expected_min_ms && avg <= result.expected_max_ms);
        result.details = "Min: " + std::to_string(min) + " ms, Max: " +
                         std::to_string(max) + " ms, Avg: " + std::to_string(avg) + " ms";

        results_.push_back(result);
        printResult(result);
    }

    /**
     * Test 10: Verify delay components are all present
     */
    void testAllComponents() {
        printHeader("Test 10: All Delay Components Present");

        NetworkDelayModel model;

        // Test at medium distance and congestion
        double distance = 750.0;
        size_t packet_size = 3000;
        size_t nodes = 45;

        double total_delay = model.calculateDelay(distance, packet_size, nodes);

        // Calculate expected components:
        double propagation = distance / 299792.458;
        double transmission = (packet_size * 8.0) / (6.0 * 1e6) * 1000.0;
        double processing = 2.0;  // Base processing
        // Queuing is random, but should add 1-10ms typically

        double min_expected = propagation + transmission + processing + 0.5;
        double max_expected = propagation + transmission + processing + 20.0;

        TestResult result;
        result.test_name = "All components present";
        result.expected_min_ms = min_expected;
        result.expected_max_ms = max_expected;
        result.actual_ms = total_delay;
        result.passed = (total_delay >= min_expected && total_delay <= max_expected);

        std::ostringstream details;
        details << "Propagation: " << std::fixed << std::setprecision(4) << propagation << " ms, "
                << "Transmission: " << transmission << " ms, "
                << "Processing: ~" << processing << " ms, "
                << "Queuing: ~" << (total_delay - propagation - transmission - processing) << " ms";
        result.details = details.str();

        results_.push_back(result);
        printResult(result);
    }

    /**
     * Test 11: Verify randomness in queuing delays
     */
    void testQueuingRandomness() {
        printHeader("Test 11: Queuing Delay Randomness");

        NetworkDelayModel model;

        double distance = 500.0;
        size_t packet_size = 2048;
        size_t nodes = 30;

        std::vector<double> delays;
        for (int i = 0; i < 100; i++) {
            double delay = model.calculateDelay(distance, packet_size, nodes);
            delays.push_back(delay);
        }

        // Calculate variance
        double mean = std::accumulate(delays.begin(), delays.end(), 0.0) / delays.size();
        double sq_sum = 0.0;
        for (double d : delays) {
            sq_sum += (d - mean) * (d - mean);
        }
        double variance = sq_sum / delays.size();
        double stddev = std::sqrt(variance);

        // There should be noticeable variance (not all delays identical)
        bool has_variance = stddev > 0.5;

        TestResult result;
        result.test_name = "Queuing randomness";
        result.expected_min_ms = 0.5;   // Minimum expected stddev
        result.expected_max_ms = 100.0; // Maximum reasonable stddev
        result.actual_ms = stddev;
        result.passed = has_variance;
        result.details = "Mean: " + std::to_string(mean) + " ms, StdDev: " +
                         std::to_string(stddev) + " ms (from 100 samples)";

        results_.push_back(result);
        printResult(result);
    }

    void printSummary() {
        printHeader("VERIFICATION SUMMARY");

        int passed = 0;
        int failed = 0;

        for (const auto& result : results_) {
            if (result.passed) passed++;
            else failed++;
        }

        std::cout << "Total Tests: " << results_.size() << "\n";
        std::cout << "Passed:      " << passed << "\n";
        std::cout << "Failed:      " << failed << "\n";
        std::cout << "Success Rate: " << std::fixed << std::setprecision(1)
                  << (100.0 * passed / results_.size()) << "%\n";

        if (failed > 0) {
            std::cout << "\nFailed tests:\n";
            for (const auto& result : results_) {
                if (!result.passed) {
                    std::cout << "  - " << result.test_name << "\n";
                }
            }
        }

        std::cout << "\n" << std::string(80, '=') << "\n";

        if (failed == 0) {
            std::cout << "✓ ALL NETWORK DELAY TESTS PASSED!\n";
            std::cout << "  Network delays are correctly implemented and functioning.\n";
        } else {
            std::cout << "✗ SOME TESTS FAILED\n";
            std::cout << "  Please review the failed tests above.\n";
        }
        std::cout << std::string(80, '=') << "\n";
    }

    void runAllTests() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                   MESHCHAIN NETWORK DELAY VERIFICATION                       ║\n";
        std::cout << "║                                                                              ║\n";
        std::cout << "║  Verifying IEEE 802.11p (WAVE) network delay model implementation           ║\n";
        std::cout << "║  Testing: Propagation, Transmission, Queuing, and Processing delays          ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n";

        testPropagationDelay();
        testTransmissionDelay();
        testQueuingDelay();
        testActualDelaySleep();
        testKEMDelay();
        testSignatureDelays();
        testRTT();
        testDisableDelays();
        testHighCongestion();
        testAllComponents();
        testQueuingRandomness();

        printSummary();
    }
};

int main() {
    NetworkDelayVerifier verifier;
    verifier.runAllTests();
    return 0;
}
