#include "crypto/pqc_signatures.h"
#include "crypto/liboqs_wrapper.h"
#include "common/v2x_messages.h"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <vector>

using namespace meshchain;
using namespace meshchain::crypto;

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
 * Test 1: Basic FALCON signature generation and verification
 */
TestResult test_basic_falcon_signature() {
    FalconSigner signer;
    signer.generateKeys();

    std::string message = "Test message for FALCON-512";
    std::vector<uint8_t> data(message.begin(), message.end());

    // Sign
    std::vector<uint8_t> signature = signer.sign(data);

    // Verify with correct public key
    std::vector<uint8_t> public_key = signer.getPublicKey();
    bool valid = signer.verify(data, signature, public_key);

    bool passed = valid && (signature.size() > 0) && (public_key.size() == 897);
    std::string details = "Signature size: " + std::to_string(signature.size()) +
                         " bytes, Public key size: " + std::to_string(public_key.size()) +
                         " bytes, Verification: " + (valid ? "PASS" : "FAIL");

    return TestResult{"Basic FALCON signature", passed, details};
}

/**
 * Test 2: Invalid signature detection
 */
TestResult test_invalid_signature_detection() {
    FalconSigner signer;
    signer.generateKeys();

    std::string message = "Original message";
    std::vector<uint8_t> data(message.begin(), message.end());

    // Sign original message
    std::vector<uint8_t> signature = signer.sign(data);
    std::vector<uint8_t> public_key = signer.getPublicKey();

    // Tamper with signature
    if (!signature.empty()) {
        signature[0] ^= 0x01;  // Flip one bit
    }

    // Should fail verification
    bool valid = signer.verify(data, signature, public_key);

    bool passed = !valid;  // Should be invalid
    std::string details = "Tampered signature detected: " + std::string(passed ? "YES" : "NO");

    return TestResult{"Invalid signature detection", passed, details};
}

/**
 * Test 3: Modified message detection
 */
TestResult test_modified_message_detection() {
    FalconSigner signer;
    signer.generateKeys();

    std::string message = "Original message";
    std::vector<uint8_t> data(message.begin(), message.end());

    // Sign
    std::vector<uint8_t> signature = signer.sign(data);
    std::vector<uint8_t> public_key = signer.getPublicKey();

    // Modify message
    std::string modified_message = "Modified message";
    std::vector<uint8_t> modified_data(modified_message.begin(), modified_message.end());

    // Should fail verification
    bool valid = signer.verify(modified_data, signature, public_key);

    bool passed = !valid;  // Should be invalid
    std::string details = "Modified message detected: " + std::string(passed ? "YES" : "NO");

    return TestResult{"Modified message detection", passed, details};
}

/**
 * Test 4: Wrong public key detection
 */
TestResult test_wrong_public_key_detection() {
    FalconSigner signer1;
    signer1.generateKeys();

    FalconSigner signer2;
    signer2.generateKeys();

    std::string message = "Test message";
    std::vector<uint8_t> data(message.begin(), message.end());

    // Sign with signer1
    std::vector<uint8_t> signature = signer1.sign(data);

    // Try to verify with signer2's public key
    std::vector<uint8_t> wrong_public_key = signer2.getPublicKey();
    bool valid = signer1.verify(data, signature, wrong_public_key);

    bool passed = !valid;  // Should be invalid
    std::string details = "Wrong public key detected: " + std::string(passed ? "YES" : "NO");

    return TestResult{"Wrong public key detection", passed, details};
}

/**
 * Test 5: InconsistencyReport signature verification
 */
TestResult test_inconsistency_report_signature() {
    FalconSigner signer;
    signer.generateKeys();

    // Create report
    InconsistencyReport report;
    report.reporter_id = "vehicle_A";
    report.accused_id = "vehicle_B";
    std::fill(report.block_hash.begin(), report.block_hash.end(), 0xAB);
    report.claimed_data = {0x01, 0x02, 0x03};
    report.observed_data = {0x04, 0x05, 0x06};
    report.inconsistency_score = 0.8;

    // Get data to sign
    std::vector<uint8_t> data_to_sign = report.getDataToSign();

    // Sign
    report.signature = signer.sign(data_to_sign);

    // Verify
    std::vector<uint8_t> public_key = signer.getPublicKey();
    bool valid = signer.verify(data_to_sign, report.signature, public_key);

    bool passed = valid;
    std::string details = "Report signature verification: " + std::string(passed ? "PASS" : "FAIL");

    return TestResult{"InconsistencyReport signature", passed, details};
}

/**
 * Test 6: Multiple signatures with same key
 */
TestResult test_multiple_signatures_same_key() {
    FalconSigner signer;
    signer.generateKeys();
    std::vector<uint8_t> public_key = signer.getPublicKey();

    int successful_verifications = 0;
    const int num_tests = 10;

    for (int i = 0; i < num_tests; ++i) {
        std::string message = "Message " + std::to_string(i);
        std::vector<uint8_t> data(message.begin(), message.end());

        std::vector<uint8_t> signature = signer.sign(data);
        bool valid = signer.verify(data, signature, public_key);

        if (valid) {
            successful_verifications++;
        }
    }

    bool passed = (successful_verifications == num_tests);
    std::string details = "Verified " + std::to_string(successful_verifications) +
                         "/" + std::to_string(num_tests) + " signatures";

    return TestResult{"Multiple signatures same key", passed, details};
}

/**
 * Test 7: Signature determinism check
 */
TestResult test_signature_determinism() {
    FalconSigner signer;
    signer.generateKeys();

    std::string message = "Test message";
    std::vector<uint8_t> data(message.begin(), message.end());

    // Sign twice
    std::vector<uint8_t> sig1 = signer.sign(data);
    std::vector<uint8_t> sig2 = signer.sign(data);

    // FALCON signatures include randomness, so they should differ
    bool different = (sig1 != sig2);

    // But both should verify
    std::vector<uint8_t> public_key = signer.getPublicKey();
    bool valid1 = signer.verify(data, sig1, public_key);
    bool valid2 = signer.verify(data, sig2, public_key);

    bool passed = different && valid1 && valid2;
    std::string details = "Signatures differ: " + std::string(different ? "YES" : "NO") +
                         ", Both verify: " + std::string(valid1 && valid2 ? "YES" : "NO");

    return TestResult{"Signature randomness", passed, details};
}

/**
 * Test 8: Empty data signature
 */
TestResult test_empty_data_signature() {
    FalconSigner signer;
    signer.generateKeys();

    std::vector<uint8_t> empty_data;

    // Sign empty data
    std::vector<uint8_t> signature = signer.sign(empty_data);

    // Verify
    std::vector<uint8_t> public_key = signer.getPublicKey();
    bool valid = signer.verify(empty_data, signature, public_key);

    bool passed = valid;
    std::string details = "Empty data signature: " + std::string(passed ? "PASS" : "FAIL");

    return TestResult{"Empty data signature", passed, details};
}

/**
 * Test 9: Large data signature
 */
TestResult test_large_data_signature() {
    FalconSigner signer;
    signer.generateKeys();

    // 10 KB of data
    std::vector<uint8_t> large_data(10240, 0x42);

    // Sign
    std::vector<uint8_t> signature = signer.sign(large_data);

    // Verify
    std::vector<uint8_t> public_key = signer.getPublicKey();
    bool valid = signer.verify(large_data, signature, public_key);

    bool passed = valid;
    std::string details = "Large data (" + std::to_string(large_data.size()) +
                         " bytes) signature: " + std::string(passed ? "PASS" : "FAIL");

    return TestResult{"Large data signature", passed, details};
}

/**
 * Test 10: Public key size validation
 */
TestResult test_public_key_size() {
    FalconSigner signer;
    signer.generateKeys();

    std::vector<uint8_t> public_key = signer.getPublicKey();

    // FALCON-512 public key should be 897 bytes
    bool correct_size = (public_key.size() == 897);

    bool passed = correct_size;
    std::string details = "Public key size: " + std::to_string(public_key.size()) +
                         " bytes (expected: 897)";

    return TestResult{"Public key size validation", passed, details};
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║    FALCON-512 Signature Verification Test                   ║\n";
    std::cout << "║    Testing PQC signature generation and verification        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::vector<TestResult> results;

    // Run all tests 10 times as required
    const int NUM_RUNS = 10;

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::cout << "===== RUN " << run << " =====\n";

        results.push_back(test_basic_falcon_signature());
        results.push_back(test_invalid_signature_detection());
        results.push_back(test_modified_message_detection());
        results.push_back(test_wrong_public_key_detection());
        results.push_back(test_inconsistency_report_signature());
        results.push_back(test_multiple_signatures_same_key());
        results.push_back(test_signature_determinism());
        results.push_back(test_empty_data_signature());
        results.push_back(test_large_data_signature());
        results.push_back(test_public_key_size());

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
