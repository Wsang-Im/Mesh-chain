#include "storage/oprf_search.h"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <chrono>

using namespace meshchain;
using namespace meshchain::storage;

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
 * Test 1: Basic OPRF protocol (blind, evaluate, unblind)
 */
TestResult test_basic_oprf_protocol() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string query = "test_vehicle_id_12345";

    // Client: blind query
    BlindedToken blinded = index.blindToken(query);

    // Server: evaluate
    EvaluatedToken evaluated = index.evaluateToken(blinded);

    // Client: unblind
    SearchToken token = index.unblindToken(evaluated, query);

    bool passed = (token.token.size() == 32);  // SHA3-256 output
    std::string details = "Token size: " + std::to_string(token.token.size()) + " bytes";

    return TestResult{"Basic OPRF protocol", passed, details};
}

/**
 * Test 2: Same query produces same token (deterministic)
 */
TestResult test_deterministic_tokens() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string query = "vehicle_abc";

    // First execution
    BlindedToken blinded1 = index.blindToken(query);
    EvaluatedToken evaluated1 = index.evaluateToken(blinded1);
    SearchToken token1 = index.unblindToken(evaluated1, query);

    // Second execution
    BlindedToken blinded2 = index.blindToken(query);
    EvaluatedToken evaluated2 = index.evaluateToken(blinded2);
    SearchToken token2 = index.unblindToken(evaluated2, query);

    // With same query and key, final tokens must be identical
    bool passed = (token1.token == token2.token);
    std::string details = "Tokens match: " + std::string(passed ? "yes" : "no");

    return TestResult{"Deterministic token generation", passed, details};
}

/**
 * Test 3: Different queries produce different tokens
 */
TestResult test_different_queries() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string query1 = "vehicle_A";
    std::string query2 = "vehicle_B";

    BlindedToken b1 = index.blindToken(query1);
    EvaluatedToken e1 = index.evaluateToken(b1);
    SearchToken t1 = index.unblindToken(e1, query1);

    BlindedToken b2 = index.blindToken(query2);
    EvaluatedToken e2 = index.evaluateToken(b2);
    SearchToken t2 = index.unblindToken(e2, query2);

    bool different = (t1.token != t2.token);
    std::string details = different ? "Tokens differ (correct)" : "Tokens same (ERROR)";

    return TestResult{"Different queries produce different tokens", different, details};
}

/**
 * Test 4: Insert and exact-match search
 */
TestResult test_insert_and_search() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string attribute = "vehicle_X";
    Hash256 record_ptr;
    std::fill(record_ptr.begin(), record_ptr.end(), 0xAA);

    // Server: insert
    index.insert(attribute, record_ptr, 0.5);

    // Client: search via OPRF protocol
    auto results = OPRFSearchProtocol::executeSearch(attribute, index);

    // Should find the record (plus padding)
    bool found = false;
    for (const auto& ptr : results) {
        if (ptr == record_ptr) {
            found = true;
            break;
        }
    }

    std::string details = "Found: " + std::string(found ? "yes" : "no") +
                         ", Results count: " + std::to_string(results.size());

    return TestResult{"Insert and exact-match search", found, details};
}

/**
 * Test 5: Search miss returns dummy results
 */
TestResult test_search_miss_padding() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    // Insert one record
    index.insert("exists", Hash256{}, 0.5);

    // Search for non-existent record
    auto results = OPRFSearchProtocol::executeSearch("does_not_exist", index);

    // Should still return fixed-size dummy results
    bool passed = (results.size() > 0);
    std::string details = "Dummy results count: " + std::to_string(results.size());

    return TestResult{"Search miss returns padding", passed, details};
}

/**
 * Test 6: Bucketing for range queries
 */
TestResult test_bucketing() {
    BucketConfig config(10, 0.0, 100.0);  // 10 buckets, range [0, 100]

    size_t bucket1 = config.getBucket(5.0);    // Should be bucket 0
    size_t bucket2 = config.getBucket(55.0);   // Should be bucket 5
    size_t bucket3 = config.getBucket(95.0);   // Should be bucket 9

    bool passed = (bucket1 == 0) && (bucket2 == 5) && (bucket3 == 9);
    std::string details = "Buckets: [5.0→" + std::to_string(bucket1) +
                         ", 55.0→" + std::to_string(bucket2) +
                         ", 95.0→" + std::to_string(bucket3) + "]";

    return TestResult{"Bucketing for ranges", passed, details};
}

/**
 * Test 7: Range query across multiple buckets
 */
TestResult test_range_query() {
    OPRFKey key;
    BucketConfig config(10, 0.0, 100.0);
    OPRFSearchIndex index(key, config);

    // Insert records with different values
    Hash256 ptr1, ptr2, ptr3, ptr4;
    std::fill(ptr1.begin(), ptr1.end(), 0x01);
    std::fill(ptr2.begin(), ptr2.end(), 0x02);
    std::fill(ptr3.begin(), ptr3.end(), 0x03);
    std::fill(ptr4.begin(), ptr4.end(), 0x04);

    index.insert("vehicle_A", ptr1, 15.0);  // Bucket 1
    index.insert("vehicle_B", ptr2, 25.0);  // Bucket 2
    index.insert("vehicle_C", ptr3, 45.0);  // Bucket 4
    index.insert("vehicle_D", ptr4, 85.0);  // Bucket 8

    // Range query [20, 50] should match buckets 2, 3, 4
    auto results = OPRFSearchProtocol::executeRangeQuery(20.0, 50.0, index, config);

    // Should find records in buckets 2 and 4 (ptr2, ptr3)
    bool found_ptr2 = false, found_ptr3 = false;
    for (const auto& ptr : results) {
        if (ptr == ptr2) found_ptr2 = true;
        if (ptr == ptr3) found_ptr3 = true;
    }

    bool passed = (found_ptr2 && found_ptr3);
    std::string details = "Range query found: " + std::to_string(results.size()) +
                         " records (ptr2: " + std::string(found_ptr2 ? "yes" : "no") +
                         ", ptr3: " + std::string(found_ptr3 ? "yes" : "no") + ")";

    return TestResult{"Range query across buckets", passed, details};
}

/**
 * Test 8: Multiple records per attribute
 */
TestResult test_multiple_records() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string attribute = "location_sector_5";
    Hash256 ptr1, ptr2, ptr3;
    std::fill(ptr1.begin(), ptr1.end(), 0x11);
    std::fill(ptr2.begin(), ptr2.end(), 0x22);
    std::fill(ptr3.begin(), ptr3.end(), 0x33);

    // Insert multiple records with same attribute
    index.insert(attribute, ptr1, 0.5);
    index.insert(attribute, ptr2, 0.5);
    index.insert(attribute, ptr3, 0.5);

    // Search should return all three (plus padding)
    auto results = OPRFSearchProtocol::executeSearch(attribute, index);

    int found_count = 0;
    for (const auto& ptr : results) {
        if (ptr == ptr1 || ptr == ptr2 || ptr == ptr3) {
            found_count++;
        }
    }

    bool passed = (found_count == 3);
    std::string details = "Found " + std::to_string(found_count) + "/3 records";

    return TestResult{"Multiple records per attribute", passed, details};
}

/**
 * Test 9: Obliviousness (server cannot learn query)
 */
TestResult test_obliviousness() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string query1 = "secret_query_A";
    std::string query2 = "secret_query_B";

    // Blind both queries
    BlindedToken blinded1 = index.blindToken(query1);
    BlindedToken blinded2 = index.blindToken(query2);

    // Blinded tokens should not reveal original queries
    // (Cannot test true obliviousness here, but check tokens differ)
    bool different_blindings = (blinded1.blinded_value != blinded2.blinded_value);

    std::string details = "Blinded tokens differ: " +
                         std::string(different_blindings ? "yes" : "no");

    return TestResult{"OPRF obliviousness property", different_blindings, details};
}

/**
 * Test 10: Bucket boundary conditions
 */
TestResult test_bucket_boundaries() {
    BucketConfig config(10, 0.0, 100.0);

    size_t bucket_min = config.getBucket(-10.0);   // Below min → bucket 0
    size_t bucket_max = config.getBucket(150.0);   // Above max → bucket 9

    bool passed = (bucket_min == 0) && (bucket_max == 9);
    std::string details = "Boundary buckets: [-10.0→" + std::to_string(bucket_min) +
                         ", 150.0→" + std::to_string(bucket_max) + "]";

    return TestResult{"Bucket boundary handling", passed, details};
}

/**
 * Test 11: Statistics tracking
 */
TestResult test_statistics() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    // Insert several records
    for (int i = 0; i < 5; ++i) {
        std::string attr = "attr_" + std::to_string(i);
        Hash256 ptr;
        std::fill(ptr.begin(), ptr.end(), static_cast<uint8_t>(i));
        index.insert(attr, ptr, i * 10.0);
    }

    auto stats = index.getStatistics();

    bool passed = (stats.total_entries >= 5);
    std::string details = "Entries: " + std::to_string(stats.total_entries) +
                         ", Records: " + std::to_string(stats.total_records) +
                         ", Buckets used: " + std::to_string(stats.num_buckets_used);

    return TestResult{"Statistics tracking", passed, details};
}

/**
 * Test 12: Performance - bulk operations
 */
TestResult test_bulk_operations() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    auto start = std::chrono::high_resolution_clock::now();

    // Insert 100 records
    for (int i = 0; i < 100; ++i) {
        std::string attr = "bulk_" + std::to_string(i);
        Hash256 ptr;
        std::fill(ptr.begin(), ptr.end(), static_cast<uint8_t>(i % 256));
        index.insert(attr, ptr, i % 100);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Perform 10 searches
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; ++i) {
        std::string query = "bulk_" + std::to_string(i * 10);
        OPRFSearchProtocol::executeSearch(query, index);
    }
    end = std::chrono::high_resolution_clock::now();
    auto search_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    bool passed = (duration.count() < 1000);  // Should be fast
    std::string details = "100 inserts: " + std::to_string(duration.count()) + "ms, " +
                         "10 searches: " + std::to_string(search_duration.count()) + "ms";

    return TestResult{"Bulk operations performance", passed, details};
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║    OPRF-Based Structured Encryption Verification            ║\n";
    std::cout << "║    Testing searchable encryption (Paper Section 4.3)        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::vector<TestResult> results;

    // Run all tests multiple times
    const int NUM_RUNS = 10;

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::cout << "===== RUN " << run << " =====\n";

        results.push_back(test_basic_oprf_protocol());
        results.push_back(test_deterministic_tokens());
        results.push_back(test_different_queries());
        results.push_back(test_insert_and_search());
        results.push_back(test_search_miss_padding());
        results.push_back(test_bucketing());
        results.push_back(test_range_query());
        results.push_back(test_multiple_records());
        results.push_back(test_obliviousness());
        results.push_back(test_bucket_boundaries());
        results.push_back(test_statistics());
        results.push_back(test_bulk_operations());

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
