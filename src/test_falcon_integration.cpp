#include "integration/integrated_vehicle.h"
#include "integration/traci_client.h"
#include <iostream>
#include <iomanip>
#include <memory>

using namespace meshchain;
using namespace meshchain::integration;

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
 * Test 1: Public key registration and retrieval
 */
TestResult test_public_key_registration() {
    // Create mock TraCI client with config
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock_sumo_config.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    // Create vehicle config
    IntegratedVehicle::Config config;
    config.vehicle_id = "test_vehicle_1";
    config.traci = traci;
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 10.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Get vehicle's public key
    std::vector<uint8_t> pub_key = vehicle.getMyPublicKey();

    // Register another vehicle's key
    std::vector<uint8_t> peer_key(897, 0xAB);  // Mock FALCON-512 public key
    vehicle.registerPeerPublicKey("peer_vehicle", peer_key);

    bool passed = (pub_key.size() == 897);  // FALCON-512 public key size
    std::string details = "Public key size: " + std::to_string(pub_key.size()) + " bytes";

    return TestResult{"Public key registration", passed, details};
}

/**
 * Test 2: Valid signature verification
 */
TestResult test_valid_signature_verification() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock_sumo_config.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config1;
    config1.vehicle_id = "vehicle_A";
    config1.traci = traci;
    config1.wave_config.cam_interval_ms = 100;
    config1.tof_config.sigma_tof_ns = 10.0;
    config1.sigma_tof_ns = 1.0;

    IntegratedVehicle::Config config2;
    config2.vehicle_id = "vehicle_B";
    config2.traci = traci;
    config2.wave_config.cam_interval_ms = 100;
    config2.tof_config.sigma_tof_ns = 10.0;
    config2.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle_a(config1);
    IntegratedVehicle vehicle_b(config2);

    // Exchange public keys
    vehicle_b.registerPeerPublicKey("vehicle_A", vehicle_a.getMyPublicKey());

    // Vehicle A creates and signs a report
    InconsistencyReport report;
    report.reporter_id = "vehicle_A";
    report.accused_id = "vehicle_C";
    std::fill(report.block_hash.begin(), report.block_hash.end(), 0xCD);
    report.claimed_data = {0x01, 0x02, 0x03};
    report.observed_data = {0x04, 0x05, 0x06};
    report.inconsistency_score = 0.75;

    // Vehicle A signs the report
    std::vector<uint8_t> data_to_sign = report.getDataToSign();
    report.signature = vehicle_a.getMyPublicKey();  // Get signer first

    // Actually sign using private FALCON signer
    // (In real code, this would be in the report creation function)
    auto falcon_signer = std::make_shared<crypto::FalconSigner>();
    falcon_signer->generateKeys();
    report.signature = falcon_signer->sign(data_to_sign);

    // Register the signer's public key
    vehicle_b.registerPeerPublicKey("vehicle_A", falcon_signer->getPublicKey());

    // Vehicle B verifies the signature
    bool valid = vehicle_b.verifyPeerSignature("vehicle_A", data_to_sign, report.signature);

    bool passed = valid;
    std::string details = "Signature verification result: " + std::string(valid ? "VALID" : "INVALID");

    return TestResult{"Valid signature verification", passed, details};
}

/**
 * Test 3: Invalid signature rejection
 */
TestResult test_invalid_signature_rejection() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock_sumo_config.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "vehicle_verifier";
    config.traci = traci;
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 10.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create signer
    auto falcon_signer = std::make_shared<crypto::FalconSigner>();
    falcon_signer->generateKeys();

    // Register public key
    vehicle.registerPeerPublicKey("attacker", falcon_signer->getPublicKey());

    // Create report
    InconsistencyReport report;
    report.reporter_id = "attacker";
    report.accused_id = "victim";
    std::fill(report.block_hash.begin(), report.block_hash.end(), 0xEF);
    report.claimed_data = {0x11, 0x22, 0x33};
    report.observed_data = {0x44, 0x55, 0x66};
    report.inconsistency_score = 0.9;

    // Sign report
    std::vector<uint8_t> data_to_sign = report.getDataToSign();
    report.signature = falcon_signer->sign(data_to_sign);

    // Tamper with signature
    if (!report.signature.empty()) {
        report.signature[0] ^= 0x01;
    }

    // Verify (should fail)
    bool valid = vehicle.verifyPeerSignature("attacker", data_to_sign, report.signature);

    bool passed = !valid;  // Should be invalid
    std::string details = "Tampered signature rejected: " + std::string(passed ? "YES" : "NO");

    return TestResult{"Invalid signature rejection", passed, details};
}

/**
 * Test 4: Multiple peer key management
 */
TestResult test_multiple_peer_keys() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock_sumo_config.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "central_vehicle";
    config.traci = traci;
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 10.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create multiple signers
    std::vector<std::shared_ptr<crypto::FalconSigner>> signers;
    std::vector<std::string> peer_ids;

    for (int i = 0; i < 5; ++i) {
        auto signer = std::make_shared<crypto::FalconSigner>();
        signer->generateKeys();
        signers.push_back(signer);

        std::string peer_id = "peer_" + std::to_string(i);
        peer_ids.push_back(peer_id);

        vehicle.registerPeerPublicKey(peer_id, signer->getPublicKey());
    }

    // Verify signatures from all peers
    int successful_verifications = 0;
    std::string message = "Test message from peer";
    std::vector<uint8_t> data(message.begin(), message.end());

    for (size_t i = 0; i < signers.size(); ++i) {
        std::vector<uint8_t> signature = signers[i]->sign(data);
        bool valid = vehicle.verifyPeerSignature(peer_ids[i], data, signature);

        if (valid) {
            successful_verifications++;
        }
    }

    bool passed = (successful_verifications == 5);
    std::string details = "Verified " + std::to_string(successful_verifications) + "/5 peer signatures";

    return TestResult{"Multiple peer key management", passed, details};
}

/**
 * Test 5: Unknown peer rejection
 */
TestResult test_unknown_peer_rejection() {
    TraCIClient::Config traci_config;
    traci_config.sumo_config = "mock_sumo_config.sumocfg";
    auto traci = std::make_shared<TraCIClient>(traci_config);

    IntegratedVehicle::Config config;
    config.vehicle_id = "vehicle_checker";
    config.traci = traci;
    config.wave_config.cam_interval_ms = 100;
    config.tof_config.sigma_tof_ns = 10.0;
    config.sigma_tof_ns = 1.0;

    IntegratedVehicle vehicle(config);

    // Create signer but DON'T register public key
    auto falcon_signer = std::make_shared<crypto::FalconSigner>();
    falcon_signer->generateKeys();

    std::string message = "Test message";
    std::vector<uint8_t> data(message.begin(), message.end());
    std::vector<uint8_t> signature = falcon_signer->sign(data);

    // Try to verify without registering key
    bool valid = vehicle.verifyPeerSignature("unknown_peer", data, signature);

    bool passed = !valid;  // Should fail (no public key)
    std::string details = "Unknown peer rejected: " + std::string(passed ? "YES" : "NO");

    return TestResult{"Unknown peer rejection", passed, details};
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║    FALCON Signature Integration Test                        ║\n";
    std::cout << "║    Testing IntegratedVehicle signature verification         ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::vector<TestResult> results;

    // Run all tests 10 times
    const int NUM_RUNS = 10;

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::cout << "===== RUN " << run << " =====\n";

        results.push_back(test_public_key_registration());
        results.push_back(test_valid_signature_verification());
        results.push_back(test_invalid_signature_rejection());
        results.push_back(test_multiple_peer_keys());
        results.push_back(test_unknown_peer_rejection());

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
