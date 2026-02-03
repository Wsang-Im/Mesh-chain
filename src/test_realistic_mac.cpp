/**
 * Unit test for Realistic MAC Layer
 *
 * Tests IEEE 802.11p CSMA/CA implementation WITHOUT OMNeT++
 */

#include "integration/realistic_mac_layer.h"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <vector>
#include <thread>

using namespace meshchain::integration;

// Test colors
#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"

void print_test(const std::string& name, bool passed) {
    std::cout << (passed ? GREEN "✓" : RED "✗") << RESET
              << " " << name << std::endl;
    if (!passed) {
        std::cerr << RED << "FAILED!" << RESET << std::endl;
        exit(1);
    }
}

/**
 * Test 1: Basic packet transmission timing
 *
 * Verify that DIFS + backoff + transmission time is realistic
 */
void test_basic_transmission() {
    std::cout << "\n=== Test 1: Basic Transmission Timing ===" << std::endl;

    RealisticMACLayer mac;

    // Enqueue a 1000-byte packet
    std::vector<uint8_t> payload(1000, 0x42);
    mac.enqueuePacket("pkt1", payload);

    auto start = std::chrono::high_resolution_clock::now();

    // Process transmission
    bool transmitted = mac.processTransmission();

    auto end = std::chrono::high_resolution_clock::now();
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // Expected time:
    // - DIFS: 58 μs
    // - Backoff: 0-15 slots × 13 μs = 0-195 μs (average ~97.5 μs)
    // - Transmission: 40 μs (PHY header) + (1000 × 8 / 6) μs ≈ 1373 μs
    // Total: ~1528 μs minimum, ~1568 μs average

    std::cout << "Transmission time: " << duration_us << " μs" << std::endl;
    std::cout << "Expected: 1300-3000 μs (DIFS + backoff + TX)" << std::endl;

    print_test("Packet transmitted", transmitted);
    print_test("Timing realistic", duration_us >= 1200 && duration_us <= 3000);
    print_test("Queue empty after", mac.isEmpty());

    auto stats = mac.getStatistics();
    std::cout << "Packets sent: " << stats.packets_sent << std::endl;
    std::cout << "Collisions: " << stats.collisions << std::endl;
    std::cout << "Avg backoff: " << stats.avg_backoff_time_us << " μs" << std::endl;

    print_test("Stats valid", stats.packets_sent == 1 && stats.collisions == 0);
}

/**
 * Test 2: Backoff mechanism
 *
 * Verify that random backoff is applied correctly
 */
void test_backoff_mechanism() {
    std::cout << "\n=== Test 2: Backoff Mechanism ===" << std::endl;

    std::vector<double> backoff_times;

    // Transmit 10 packets and measure backoff variation
    for (int i = 0; i < 10; i++) {
        RealisticMACLayer mac;
        std::vector<uint8_t> payload(100, 0x42);
        mac.enqueuePacket("pkt", payload);

        auto start = std::chrono::high_resolution_clock::now();
        mac.processTransmission();
        auto end = std::chrono::high_resolution_clock::now();

        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        backoff_times.push_back(duration_us);
    }

    // Calculate variance
    double mean = 0;
    for (double t : backoff_times) mean += t;
    mean /= backoff_times.size();

    double variance = 0;
    for (double t : backoff_times) {
        variance += (t - mean) * (t - mean);
    }
    variance /= backoff_times.size();

    std::cout << "Mean time: " << mean << " μs" << std::endl;
    std::cout << "Variance: " << variance << " μs²" << std::endl;
    std::cout << "Sample times:" << std::endl;
    for (size_t i = 0; i < backoff_times.size(); i++) {
        std::cout << "  " << i+1 << ": " << backoff_times[i] << " μs" << std::endl;
    }

    // Backoff should have variance (random 0-15 slots × 13 μs = 0-195 μs range)
    print_test("Backoff has variance", variance > 100);  // Should have at least 100 μs² variance
    print_test("Times within expected range", mean >= 200 && mean <= 1500);  // DIFS + backoff + TX(100B)
}

/**
 * Test 3: Channel busy detection
 *
 * Verify that channel state is tracked correctly
 */
void test_channel_busy() {
    std::cout << "\n=== Test 3: Channel Busy Detection ===" << std::endl;

    ChannelState channel;

    // Initially idle
    print_test("Channel initially idle", !channel.isBusy());

    // Mark busy for 1000 μs
    channel.markBusy(1000.0);
    print_test("Channel busy after marking", channel.isBusy());

    double remaining = channel.getRemainingBusyTime();
    std::cout << "Remaining busy time: " << remaining << " μs" << std::endl;
    print_test("Remaining time reasonable", remaining > 900 && remaining <= 1000);

    // Wait for channel to become idle
    std::this_thread::sleep_for(std::chrono::microseconds(1100));
    print_test("Channel idle after timeout", !channel.isBusy());
}

/**
 * Test 4: Transmission time calculation
 *
 * Verify IEEE 802.11p timing formulas
 */
void test_transmission_time() {
    std::cout << "\n=== Test 4: Transmission Time Calculation ===" << std::endl;

    RealisticMACLayer mac;

    // Test various packet sizes
    struct TestCase {
        size_t size_bytes;
        double expected_us_min;
        double expected_us_max;
    };

    std::vector<TestCase> tests = {
        {100, 170, 180},      // Small packet
        {500, 700, 720},      // Medium packet
        {1000, 1370, 1380},   // Large packet
        {2312, 3100, 3130},   // Maximum 802.11 frame
    };

    for (const auto& test : tests) {
        double tx_time = mac.calculateTransmissionTime(test.size_bytes);
        std::cout << "Size: " << test.size_bytes << " bytes → "
                  << tx_time << " μs" << std::endl;

        bool in_range = (tx_time >= test.expected_us_min && tx_time <= test.expected_us_max);
        print_test("TX time for " + std::to_string(test.size_bytes) + " bytes", in_range);
    }
}

/**
 * Test 5: Multiple packet queue
 *
 * Verify queue processing
 */
void test_multiple_packets() {
    std::cout << "\n=== Test 5: Multiple Packet Queue ===" << std::endl;

    RealisticMACLayer mac;

    // Enqueue 5 packets
    for (int i = 0; i < 5; i++) {
        std::vector<uint8_t> payload(100, i);
        mac.enqueuePacket("pkt" + std::to_string(i), payload);
    }

    print_test("Queue size is 5", mac.getQueueSize() == 5);

    // Process all packets
    int transmitted = 0;
    auto start = std::chrono::high_resolution_clock::now();

    while (!mac.isEmpty()) {
        if (mac.processTransmission()) {
            transmitted++;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "Transmitted: " << transmitted << " packets" << std::endl;
    std::cout << "Total time: " << total_time_ms << " ms" << std::endl;

    print_test("All packets transmitted", transmitted == 5);
    print_test("Queue empty", mac.isEmpty());

    auto stats = mac.getStatistics();
    std::cout << "Total packets sent: " << stats.packets_sent << std::endl;
    print_test("Statistics correct", stats.packets_sent == 5);
}

/**
 * Test 6: Realistic V2X message timing
 *
 * Simulate actual CAM/DENM message sizes
 */
void test_v2x_message_timing() {
    std::cout << "\n=== Test 6: V2X Message Timing ===" << std::endl;

    RealisticMACLayer mac;

    // CAM message: typically 300-500 bytes
    std::vector<uint8_t> cam_payload(400, 0x42);
    mac.enqueuePacket("cam", cam_payload);

    auto start = std::chrono::high_resolution_clock::now();
    mac.processTransmission();
    auto end = std::chrono::high_resolution_clock::now();
    auto cam_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "CAM (400 bytes) transmission: " << cam_time_us << " μs" << std::endl;

    // Expected: DIFS(58) + backoff(~97) + TX(40 + 533) ≈ 728 μs
    print_test("CAM timing realistic", cam_time_us >= 600 && cam_time_us <= 1200);

    // TLS handshake message: ~2KB
    RealisticMACLayer mac2;
    std::vector<uint8_t> tls_payload(2048, 0x42);
    mac2.enqueuePacket("tls", tls_payload);

    start = std::chrono::high_resolution_clock::now();
    mac2.processTransmission();
    end = std::chrono::high_resolution_clock::now();
    auto tls_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "TLS (2KB) transmission: " << tls_time_us << " μs" << std::endl;

    // Expected: DIFS(58) + backoff(~97) + TX(40 + 2730) ≈ 2925 μs
    print_test("TLS timing realistic", tls_time_us >= 2500 && tls_time_us <= 4000);
}

/**
 * Test 7: Statistics tracking
 *
 * Verify statistics are accumulated correctly
 */
void test_statistics() {
    std::cout << "\n=== Test 7: Statistics Tracking ===" << std::endl;

    RealisticMACLayer mac;

    // Transmit several packets
    for (int i = 0; i < 3; i++) {
        std::vector<uint8_t> payload(200, i);
        mac.enqueuePacket("pkt" + std::to_string(i), payload);
        mac.processTransmission();
    }

    auto stats = mac.getStatistics();

    std::cout << "Packets sent: " << stats.packets_sent << std::endl;
    std::cout << "Collisions: " << stats.collisions << std::endl;
    std::cout << "Retries: " << stats.retries << std::endl;
    std::cout << "Avg backoff time: " << stats.avg_backoff_time_us << " μs" << std::endl;

    print_test("Packets sent tracked", stats.packets_sent == 3);
    print_test("No collisions (single node)", stats.collisions == 0);
    print_test("Backoff time reasonable", stats.avg_backoff_time_us >= 0 && stats.avg_backoff_time_us <= 200);
}

int main() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════╗\n";
    std::cout << "║   Realistic MAC Layer Unit Tests                      ║\n";
    std::cout << "║   IEEE 802.11p CSMA/CA Implementation                 ║\n";
    std::cout << "╚════════════════════════════════════════════════════════╝\n";

    try {
        test_basic_transmission();
        test_backoff_mechanism();
        test_channel_busy();
        test_transmission_time();
        test_multiple_packets();
        test_v2x_message_timing();
        test_statistics();

        std::cout << "\n" << GREEN << "╔════════════════════════════════════════════════════════╗" << RESET << "\n";
        std::cout << GREEN << "║   ALL TESTS PASSED ✓                                   ║" << RESET << "\n";
        std::cout << GREEN << "╚════════════════════════════════════════════════════════╝" << RESET << "\n\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << RED << "\n✗ Test failed with exception: " << e.what() << RESET << std::endl;
        return 1;
    }
}
