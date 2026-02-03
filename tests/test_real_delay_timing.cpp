#include "src/integration/network_delay_model.h"
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace meshchain::integration;

int main() {
    NetworkDelayModel model;
    
    std::cout << "=== Testing Real Network Delay Timing ===\n\n";
    
    // Test 1: Simulate a realistic TLS handshake scenario
    std::cout << "Test 1: TLS Handshake (ML-KEM) at 500m with 30 nodes\n";
    double distance = 500.0;
    size_t nodes = 30;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // ClientHello
    double client_hello_delay = model.calculateKEMDelay(distance, nodes);
    std::cout << "  ClientHello delay calculated: " << client_hello_delay << " ms\n";
    NetworkDelayModel::simulateDelay(client_hello_delay);
    
    auto after_client_hello = std::chrono::high_resolution_clock::now();
    double actual_client_hello = std::chrono::duration<double, std::milli>(
        after_client_hello - start).count();
    std::cout << "  ClientHello actual sleep: " << actual_client_hello << " ms\n";
    
    // ServerHello
    double server_hello_delay = model.calculateKEMDelay(distance, nodes);
    std::cout << "  ServerHello delay calculated: " << server_hello_delay << " ms\n";
    NetworkDelayModel::simulateDelay(server_hello_delay);
    
    auto after_server_hello = std::chrono::high_resolution_clock::now();
    double total_handshake = std::chrono::duration<double, std::milli>(
        after_server_hello - start).count();
    std::cout << "  Total handshake time: " << total_handshake << " ms\n";
    std::cout << "  Expected: " << (client_hello_delay + server_hello_delay) << " ms\n\n";
    
    // Test 2: Signature request/response
    std::cout << "Test 2: Signature Request/Response at 800m with 40 nodes\n";
    distance = 800.0;
    nodes = 40;
    
    start = std::chrono::high_resolution_clock::now();
    
    double req_delay = model.calculateSigRequestDelay(distance, nodes);
    double resp_delay = model.calculateSigResponseDelay(distance, nodes);
    double total_expected = req_delay + resp_delay;
    
    std::cout << "  Request delay: " << req_delay << " ms\n";
    std::cout << "  Response delay: " << resp_delay << " ms\n";
    std::cout << "  Total expected: " << total_expected << " ms\n";
    
    NetworkDelayModel::simulateDelay(total_expected);
    
    auto end = std::chrono::high_resolution_clock::now();
    double actual_total = std::chrono::duration<double, std::milli>(end - start).count();
    
    std::cout << "  Actual sleep time: " << actual_total << " ms\n";
    std::cout << "  Accuracy: " << std::fixed << std::setprecision(2) 
              << (actual_total / total_expected * 100.0) << "%\n\n";
    
    // Test 3: Multiple sequential delays (simulating witness collection)
    std::cout << "Test 3: Collecting 5 witness signatures sequentially\n";
    start = std::chrono::high_resolution_clock::now();
    
    std::vector<double> distances = {300, 500, 700, 450, 600};
    double total_witness_delay = 0;
    
    for (size_t i = 0; i < distances.size(); i++) {
        double witness_delay = model.calculateSigRequestDelay(distances[i], 35) +
                               model.calculateSigResponseDelay(distances[i], 35);
        total_witness_delay += witness_delay;
        std::cout << "  Witness " << (i+1) << " at " << distances[i] << "m: " 
                  << witness_delay << " ms\n";
        NetworkDelayModel::simulateDelay(witness_delay);
    }
    
    end = std::chrono::high_resolution_clock::now();
    double actual_witness_total = std::chrono::duration<double, std::milli>(end - start).count();
    
    std::cout << "  Total expected: " << total_witness_delay << " ms\n";
    std::cout << "  Actual time: " << actual_witness_total << " ms\n";
    std::cout << "  Difference: " << std::abs(actual_witness_total - total_witness_delay) << " ms\n";
    
    return 0;
}
