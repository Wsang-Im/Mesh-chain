/**
 * Integration test: Verify MAC layer works with WaveStackOMNeT
 * Tests both MAC disabled (backward compatibility) and MAC enabled
 */

#include "integration/wave_stack_omnetpp.h"
#include "integration/traci_client.h"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace meshchain::integration;

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
 * Test 9: Backward compatibility - MAC disabled (default)
 */
void test_mac_disabled() {
    std::cout << "\n=== Test 9: Backward Compatibility (MAC Disabled) ===\n";

    // Create minimal WAVE config (enable_realistic_mac defaults to false)
    WaveStackOMNeT::Config config;
    config.node_id = "test_vehicle_1";
    config.tx_power_dbm = 20.0;
    config.frequency_ghz = 5.9;
    config.bandwidth_mhz = 10.0;
    config.data_rate_mbps = 6.0;
    config.range_m = 300.0;
    config.packet_loss_rate = 0.1;
    config.cam_interval_ms = 100;
    config.denm_priority = 6;
    // NOTE: enable_realistic_mac = false (default)

    print_test("Config created with MAC disabled", config.enable_realistic_mac == false);

    // Create dummy TraCI (not actually used for this test)
    TraCIClient::Config traci_config;
    traci_config.sumo_host = "localhost";
    traci_config.sumo_port = 8813;
    traci_config.sumo_config = "";
    traci_config.use_gui = false;
    traci_config.auto_start_sumo = false;
    traci_config.step_length_s = 0.1;
    traci_config.max_duration_s = 300.0;
    traci_config.step_length_s = 0.1;
    traci_config.max_duration_s = 300.0;
    auto traci = std::make_shared<TraCIClient>(traci_config);

    // Create WaveStack
    auto wave_stack = std::make_shared<WaveStackOMNeT>(config, traci);

    print_test("WaveStack created successfully", wave_stack != nullptr);

    // Send a test message (should be instant, no MAC delays)
    WaveStackOMNeT::WaveMessage msg;
    msg.type = WaveStackOMNeT::MessageType::CUSTOM;
    msg.sender_id = "test_vehicle_1";
    msg.receiver_id = "test_vehicle_2";
    msg.sent_at = std::chrono::system_clock::now();
    msg.priority = 5;
    msg.payload = std::vector<uint8_t>(500, 0x42);  // 500-byte payload

    auto start = std::chrono::high_resolution_clock::now();
    wave_stack->sendP2P("test_vehicle_2", msg.payload);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "Send time (MAC disabled): " << duration_us << " μs\n";

    // Without MAC layer, send should be near-instant (<100 μs)
    print_test("Send is instant (< 100 μs)", duration_us < 100);

    // Check MAC statistics (should be null when disabled)
    auto mac_stats = wave_stack->getMACStatistics();
    print_test("MAC statistics unavailable when disabled", !mac_stats.has_value());

    size_t sent, received, lost;
    wave_stack->getStatistics(sent, received, lost);
    std::cout << "WAVE stats: sent=" << sent << ", received=" << received << ", lost=" << lost << "\n";
    print_test("Message sent successfully", sent == 1);
}

/**
 * Test 10: MAC enabled - realistic CSMA/CA delays
 */
void test_mac_enabled() {
    std::cout << "\n=== Test 10: MAC Enabled (Realistic CSMA/CA) ===\n";

    // Create WAVE config with MAC ENABLED
    WaveStackOMNeT::Config config;
    config.node_id = "test_vehicle_2";
    config.tx_power_dbm = 20.0;
    config.frequency_ghz = 5.9;
    config.bandwidth_mhz = 10.0;
    config.data_rate_mbps = 6.0;
    config.range_m = 300.0;
    config.packet_loss_rate = 0.1;
    config.cam_interval_ms = 100;
    config.denm_priority = 6;
    config.enable_realistic_mac = true;  // ← ENABLE MAC!

    print_test("Config created with MAC enabled", config.enable_realistic_mac == true);

    // Create dummy TraCI
    TraCIClient::Config traci_config;
    traci_config.sumo_host = "localhost";
    traci_config.sumo_port = 8813;
    traci_config.sumo_config = "";
    traci_config.use_gui = false;
    traci_config.auto_start_sumo = false;
    traci_config.step_length_s = 0.1;
    traci_config.max_duration_s = 300.0;
    auto traci = std::make_shared<TraCIClient>(traci_config);

    // Create WaveStack
    auto wave_stack = std::make_shared<WaveStackOMNeT>(config, traci);

    print_test("WaveStack created with MAC layer", wave_stack != nullptr);

    // Send a test message (should have realistic delays: DIFS + backoff + TX)
    std::vector<uint8_t> payload(500, 0x42);  // 500-byte payload

    auto start = std::chrono::high_resolution_clock::now();
    wave_stack->sendP2P("test_vehicle_3", payload);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "Send time (MAC enabled): " << duration_us << " μs\n";

    // Expected time: DIFS(58) + backoff(~97) + TX(40 + 500*8/6 ≈ 706) ≈ 861 μs
    // Allow range: 700-1500 μs
    print_test("Send has realistic MAC delay (700-1500 μs)", duration_us >= 700 && duration_us <= 1500);

    // Check MAC statistics (should be available)
    auto mac_stats = wave_stack->getMACStatistics();
    print_test("MAC statistics available when enabled", mac_stats.has_value());

    if (mac_stats.has_value()) {
        std::cout << "MAC stats:\n";
        std::cout << "  Packets sent: " << mac_stats->packets_sent << "\n";
        std::cout << "  Collisions: " << mac_stats->collisions << "\n";
        std::cout << "  Retries: " << mac_stats->retries << "\n";
        std::cout << "  Avg backoff: " << mac_stats->avg_backoff_time_us << " μs\n";

        print_test("MAC sent 1 packet", mac_stats->packets_sent == 1);
        print_test("No collisions (single node)", mac_stats->collisions == 0);
        print_test("Backoff time reasonable (0-200 μs)",
                   mac_stats->avg_backoff_time_us >= 0 && mac_stats->avg_backoff_time_us <= 200);
    }

    size_t sent, received, lost;
    wave_stack->getStatistics(sent, received, lost);
    std::cout << "WAVE stats: sent=" << sent << ", received=" << received << ", lost=" << lost << "\n";
    print_test("Message sent successfully", sent == 1);
}

/**
 * Test 11: Performance comparison - MAC vs no MAC
 */
void test_performance_comparison() {
    std::cout << "\n=== Test 11: Performance Comparison ===\n";

    // Test 1: No MAC (baseline)
    WaveStackOMNeT::Config config_no_mac;
    config_no_mac.node_id = "perf_test_1";
    config_no_mac.tx_power_dbm = 20.0;
    config_no_mac.frequency_ghz = 5.9;
    config_no_mac.bandwidth_mhz = 10.0;
    config_no_mac.data_rate_mbps = 6.0;
    config_no_mac.range_m = 300.0;
    config_no_mac.enable_realistic_mac = false;

    TraCIClient::Config traci_config1;
    traci_config1.sumo_host = "localhost";
    traci_config1.sumo_port = 8813;
    traci_config1.sumo_config = "";
    traci_config1.use_gui = false;
    traci_config1.auto_start_sumo = false;
    traci_config1.step_length_s = 0.1;
    traci_config1.max_duration_s = 300.0;
    auto traci1 = std::make_shared<TraCIClient>(traci_config1);
    auto wave_no_mac = std::make_shared<WaveStackOMNeT>(config_no_mac, traci1);

    // Send 5 messages without MAC
    std::vector<uint8_t> payload(400, 0x42);  // CAM-sized message
    auto start_no_mac = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 5; i++) {
        wave_no_mac->sendP2P("peer", payload);
    }

    auto end_no_mac = std::chrono::high_resolution_clock::now();
    auto duration_no_mac_us = std::chrono::duration_cast<std::chrono::microseconds>(end_no_mac - start_no_mac).count();

    std::cout << "5 messages without MAC: " << duration_no_mac_us << " μs total\n";
    std::cout << "  → " << (duration_no_mac_us / 5.0) << " μs per message\n";

    // Test 2: With MAC
    WaveStackOMNeT::Config config_with_mac;
    config_with_mac.node_id = "perf_test_2";
    config_with_mac.tx_power_dbm = 20.0;
    config_with_mac.frequency_ghz = 5.9;
    config_with_mac.bandwidth_mhz = 10.0;
    config_with_mac.data_rate_mbps = 6.0;
    config_with_mac.range_m = 300.0;
    config_with_mac.enable_realistic_mac = true;

    TraCIClient::Config traci_config2;
    traci_config2.sumo_host = "localhost";
    traci_config2.sumo_port = 8813;
    traci_config2.sumo_config = "";
    traci_config2.use_gui = false;
    traci_config2.auto_start_sumo = false;
    traci_config2.step_length_s = 0.1;
    traci_config2.max_duration_s = 300.0;
    auto traci2 = std::make_shared<TraCIClient>(traci_config2);
    auto wave_with_mac = std::make_shared<WaveStackOMNeT>(config_with_mac, traci2);

    // Send 5 messages with MAC
    auto start_with_mac = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 5; i++) {
        wave_with_mac->sendP2P("peer", payload);
    }

    auto end_with_mac = std::chrono::high_resolution_clock::now();
    auto duration_with_mac_us = std::chrono::duration_cast<std::chrono::microseconds>(end_with_mac - start_with_mac).count();

    std::cout << "5 messages with MAC: " << duration_with_mac_us << " μs total\n";
    std::cout << "  → " << (duration_with_mac_us / 5.0) << " μs per message\n";

    double overhead_ratio = static_cast<double>(duration_with_mac_us) / static_cast<double>(duration_no_mac_us);
    std::cout << "MAC overhead: " << std::fixed << std::setprecision(1) << overhead_ratio << "x\n";

    // MAC should add significant delay (at least 10x)
    print_test("MAC adds realistic overhead (> 10x)", overhead_ratio > 10.0);

    // Check MAC stats
    auto mac_stats = wave_with_mac->getMACStatistics();
    if (mac_stats.has_value()) {
        std::cout << "MAC processed " << mac_stats->packets_sent << " packets\n";
        print_test("MAC sent all 5 packets", mac_stats->packets_sent == 5);
    }
}

int main() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════╗\n";
    std::cout << "║   MAC Layer Integration Tests                         ║\n";
    std::cout << "║   Verify WaveStackOMNeT + RealisticMACLayer           ║\n";
    std::cout << "╚════════════════════════════════════════════════════════╝\n";

    try {
        test_mac_disabled();           // Test 9
        test_mac_enabled();            // Test 10
        test_performance_comparison(); // Test 11

        std::cout << "\n" << GREEN << "╔════════════════════════════════════════════════════════╗" << RESET << "\n";
        std::cout << GREEN << "║   ALL INTEGRATION TESTS PASSED ✓                       ║" << RESET << "\n";
        std::cout << GREEN << "║   MAC layer successfully integrated!                   ║" << RESET << "\n";
        std::cout << GREEN << "╚════════════════════════════════════════════════════════╝" << RESET << "\n\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << RED << "\n✗ Test failed with exception: " << e.what() << RESET << std::endl;
        return 1;
    }
}
