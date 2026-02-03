#include "network/token_bucket_qos.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <cassert>

using namespace meshchain;
using namespace meshchain::network;

struct TestResult {
    std::string test_name;
    bool passed;
    std::string details;
};

void printResult(const TestResult& result) {
    std::cout << (result.passed ? "[PASS] " : "[FAIL] ")
              << result.test_name << "\n";
    if (!result.details.empty()) {
        std::cout << "  " << result.details << "\n";
    }
}

/**
 * Test 1: Basic token consumption
 */
TestResult test_basic_consumption() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 0.5;  // Mid-range reputation

    std::string sender = "vehicle_1";

    // First request should succeed
    auto decision = qos.enforceQoS(sender, MessageType::OTHER, rep);

    bool passed = decision.accept;
    std::string details = "First request: " +
                         std::string(decision.accept ? "Accepted" : "Dropped");

    return TestResult{"Basic token consumption", passed, details};
}

/**
 * Test 2: Rate limiting (burst then drop)
 */
TestResult test_rate_limiting() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 0.5;  // rate = 10 * 0.25 = 2.5 msg/s, burst = 12.5

    std::string sender = "vehicle_2";

    // Consume many messages rapidly
    int accepted = 0;
    int dropped = 0;

    for (int i = 0; i < 20; ++i) {
        auto decision = qos.enforceQoS(sender, MessageType::OTHER, rep);
        if (decision.accept) {
            accepted++;
        } else {
            dropped++;
        }
    }

    bool passed = (dropped > 0);  // Should hit rate limit
    std::string details = "Accepted: " + std::to_string(accepted) +
                         ", Dropped: " + std::to_string(dropped);

    return TestResult{"Rate limiting enforcement", passed, details};
}

/**
 * Test 3: Reputation-based rate (quadratic scaling)
 */
TestResult test_reputation_scaling() {
    TokenBucketQoS qos;

    // High reputation sender
    Reputation high_rep;
    high_rep.R = 0.9;  // rate = 10 * 0.81 = 8.1 msg/s

    // Low reputation sender
    Reputation low_rep;
    low_rep.R = 0.3;  // rate = 10 * 0.09 = 0.9 msg/s

    std::string sender_high = "vehicle_high";
    std::string sender_low = "vehicle_low";

    // Both send 10 messages
    int high_accepted = 0;
    int low_accepted = 0;

    for (int i = 0; i < 10; ++i) {
        if (qos.enforceQoS(sender_high, MessageType::OTHER, high_rep).accept) {
            high_accepted++;
        }
        if (qos.enforceQoS(sender_low, MessageType::OTHER, low_rep).accept) {
            low_accepted++;
        }
    }

    bool passed = (high_accepted > low_accepted);
    std::string details = "High rep accepted: " + std::to_string(high_accepted) +
                         ", Low rep accepted: " + std::to_string(low_accepted);

    return TestResult{"Reputation-based scaling", passed, details};
}

/**
 * Test 4: Token refill over time
 */
TestResult test_token_refill() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 0.5;
    std::string sender = "vehicle_refill";

    // Exhaust tokens
    for (int i = 0; i < 15; ++i) {
        qos.enforceQoS(sender, MessageType::OTHER, rep);
    }

    // Check tokens are low
    double tokens_before = qos.getTokens(sender);

    // Wait for refill
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    double tokens_after = qos.getTokens(sender);

    bool passed = (tokens_after > tokens_before);
    std::string details = "Tokens before: " + std::to_string(tokens_before) +
                         ", after 500ms: " + std::to_string(tokens_after);

    return TestResult{"Token refill over time", passed, details};
}

/**
 * Test 5: Message type costs
 */
TestResult test_message_costs() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 1.0;  // High rep to get large bucket
    std::string sender = "vehicle_costs";

    // Reset to known state
    qos.resetBucket(sender);
    qos.enforceQoS(sender, MessageType::OTHER, rep);  // Initialize

    double tokens_initial = qos.getTokens(sender);

    // Send expensive message (BLOCK = 5)
    qos.enforceQoS(sender, MessageType::BLOCK, rep);
    double tokens_after_block = qos.getTokens(sender);

    // Send cheap message (OTHER = 1)
    qos.enforceQoS(sender, MessageType::OTHER, rep);
    double tokens_after_other = qos.getTokens(sender);

    double block_cost = tokens_initial - tokens_after_block;
    double other_cost = tokens_after_block - tokens_after_other;

    bool passed = (block_cost > other_cost * 4);  // BLOCK should cost 5x more
    std::string details = "BLOCK consumed: " + std::to_string(block_cost) +
                         ", OTHER consumed: " + std::to_string(other_cost);

    return TestResult{"Message type costs", passed, details};
}

/**
 * Test 6: Reputation penalty on drop
 */
TestResult test_reputation_penalty() {
    TokenBucketQoS::Config config;
    config.enable_penalties = true;
    config.penalty_amount = 0.05;

    TokenBucketQoS qos(config);
    Reputation rep;
    rep.R = 0.5;
    std::string sender = "vehicle_penalty";

    double initial_rep = rep.R;

    // Exhaust tokens to trigger drop
    for (int i = 0; i < 20; ++i) {
        qos.enforceQoS(sender, MessageType::BLOCK, rep);
    }

    double final_rep = rep.R;

    bool passed = (final_rep < initial_rep);
    std::string details = "Initial rep: " + std::to_string(initial_rep) +
                         ", Final rep: " + std::to_string(final_rep);

    return TestResult{"Reputation penalty on drop", passed, details};
}

/**
 * Test 7: Priority assignment
 */
TestResult test_priority_assignment() {
    TokenBucketQoS qos;

    Reputation high_rep;
    high_rep.R = 0.9;

    Reputation low_rep;
    low_rep.R = 0.3;

    auto high_decision = qos.enforceQoS("vehicle_high_pri", MessageType::OTHER, high_rep);
    auto low_decision = qos.enforceQoS("vehicle_low_pri", MessageType::OTHER, low_rep);

    bool passed = (high_decision.priority > low_decision.priority);
    std::string details = "High priority: " + std::to_string(high_decision.priority) +
                         ", Low priority: " + std::to_string(low_decision.priority);

    return TestResult{"Priority assignment", passed, details};
}

/**
 * Test 8: Concurrent senders isolation
 */
TestResult test_sender_isolation() {
    TokenBucketQoS qos;
    Reputation rep1, rep2;
    rep1.R = 0.8;
    rep2.R = 0.8;

    std::string sender1 = "vehicle_A";
    std::string sender2 = "vehicle_B";

    // Sender 1 exhausts tokens
    for (int i = 0; i < 50; ++i) {
        qos.enforceQoS(sender1, MessageType::OTHER, rep1);
    }

    // Sender 2 should still have tokens
    auto decision = qos.enforceQoS(sender2, MessageType::OTHER, rep2);

    bool passed = decision.accept;
    std::string details = "Sender2 first request: " +
                         std::string(decision.accept ? "Accepted" : "Dropped");

    return TestResult{"Sender isolation", passed, details};
}

/**
 * Test 9: Burst capacity
 */
TestResult test_burst_capacity() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 1.0;  // Max reputation: rate = 10, burst = 50
    std::string sender = "vehicle_burst";

    int burst_accepted = 0;

    // Try to send burst of 50 messages
    for (int i = 0; i < 50; ++i) {
        if (qos.enforceQoS(sender, MessageType::OTHER, rep).accept) {
            burst_accepted++;
        }
    }

    bool passed = (burst_accepted >= 45);  // Should accept most of burst
    std::string details = "Burst accepted: " + std::to_string(burst_accepted) + "/50";

    return TestResult{"Burst capacity", passed, details};
}

/**
 * Test 10: Sustained rate limit (faster version)
 */
TestResult test_sustained_rate() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 0.5;  // rate = 2.5 msg/s
    std::string sender = "vehicle_sustained";

    int accepted = 0;
    int total = 0;

    // Send 10 rapid messages, wait 100ms, send 5 more
    for (int i = 0; i < 10; ++i) {
        total++;
        if (qos.enforceQoS(sender, MessageType::OTHER, rep).accept) {
            accepted++;
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    for (int i = 0; i < 5; ++i) {
        total++;
        if (qos.enforceQoS(sender, MessageType::OTHER, rep).accept) {
            accepted++;
        }
    }

    bool passed = (accepted >= 10 && accepted <= 15);
    std::string details = "Accepted: " + std::to_string(accepted) +
                         "/" + std::to_string(total);

    return TestResult{"Sustained rate limit", passed, details};
}

/**
 * Test 11: Fill percentage monitoring
 */
TestResult test_fill_monitoring() {
    TokenBucketQoS qos;
    Reputation rep;
    rep.R = 0.5;
    std::string sender = "vehicle_monitor";

    // Initialize
    qos.enforceQoS(sender, MessageType::OTHER, rep);

    double fill_full = qos.getFillPercentage(sender);

    // Consume some tokens
    for (int i = 0; i < 5; ++i) {
        qos.enforceQoS(sender, MessageType::OTHER, rep);
    }

    double fill_partial = qos.getFillPercentage(sender);

    bool passed = (fill_partial < fill_full);
    std::string details = "Full: " + std::to_string(fill_full * 100) +
                         "%, Partial: " + std::to_string(fill_partial * 100) + "%";

    return TestResult{"Fill percentage monitoring", passed, details};
}

/**
 * Test 12: Statistics tracking
 */
TestResult test_statistics() {
    TokenBucketQoS qos;
    Reputation rep1, rep2;
    rep1.R = 0.8;
    rep2.R = 0.4;

    qos.enforceQoS("sender1", MessageType::OTHER, rep1);
    qos.enforceQoS("sender2", MessageType::BLOCK, rep2);

    auto stats = qos.getStatistics();

    bool passed = (stats.total_buckets >= 2);
    std::string details = "Total buckets: " + std::to_string(stats.total_buckets);

    return TestResult{"Statistics tracking", passed, details};
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║    Token Bucket QoS Verification (Paper Algorithm 6)        ║\n";
    std::cout << "║    Testing reputation-weighted rate limiting                ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::vector<TestResult> results;

    // Run all tests multiple times
    const int NUM_RUNS = 10;

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::cout << "===== RUN " << run << " =====\n";

        results.push_back(test_basic_consumption());
        results.push_back(test_rate_limiting());
        results.push_back(test_reputation_scaling());
        results.push_back(test_token_refill());
        results.push_back(test_message_costs());
        results.push_back(test_reputation_penalty());
        results.push_back(test_priority_assignment());
        results.push_back(test_sender_isolation());
        results.push_back(test_burst_capacity());
        results.push_back(test_sustained_rate());
        results.push_back(test_fill_monitoring());
        results.push_back(test_statistics());

        std::cout << "\n";
    }

    // Print summary
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    VERIFICATION SUMMARY                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    int total = results.size();
    int passed = 0;
    for (const auto& result : results) {
        if (result.passed) passed++;
    }

    std::cout << "Total Tests: " << total << "\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << (total - passed) << "\n";
    std::cout << "Success Rate: " << std::fixed << std::setprecision(1)
              << (100.0 * passed / total) << "%\n\n";

    // Print failed tests if any
    if (passed < total) {
        std::cout << "Failed tests:\n";
        for (const auto& result : results) {
            if (!result.passed) {
                printResult(result);
            }
        }
    }

    std::cout << (passed == total ? "✓ ALL TESTS PASSED!\n" : "✗ SOME TESTS FAILED\n");
    std::cout << "══════════════════════════════════════════════════════════════\n\n";

    return (passed == total) ? 0 : 1;
}
