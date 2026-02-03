/**
 * Test GF256 arithmetic
 */

#include "storage/shamir_secret_sharing.h"
#include <iostream>
#include <iomanip>

using namespace meshchain::storage;

int main() {
    std::cout << "=== GF256 Arithmetic Test ===\n\n";

    GF256::initializeTables();

    // Test 1: Identity
    std::cout << "Test 1: a * 1 = a\n";
    for (uint8_t a : {2, 3, 5, 42, 255}) {
        uint8_t result = GF256::multiply(a, 1);
        std::cout << "  " << static_cast<int>(a) << " * 1 = "
                  << static_cast<int>(result)
                  << (result == a ? " ✅" : " ❌") << "\n";
    }

    // Test 2: Zero
    std::cout << "\nTest 2: a * 0 = 0\n";
    for (uint8_t a : {2, 3, 5, 42, 255}) {
        uint8_t result = GF256::multiply(a, 0);
        std::cout << "  " << static_cast<int>(a) << " * 0 = "
                  << static_cast<int>(result)
                  << (result == 0 ? " ✅" : " ❌") << "\n";
    }

    // Test 3: a / a = 1
    std::cout << "\nTest 3: a / a = 1\n";
    for (uint8_t a : {2, 3, 5, 42, 255}) {
        uint8_t result = GF256::divide(a, a);
        std::cout << "  " << static_cast<int>(a) << " / " << static_cast<int>(a)
                  << " = " << static_cast<int>(result)
                  << (result == 1 ? " ✅" : " ❌") << "\n";
    }

    // Test 4: a * (1/a) = 1
    std::cout << "\nTest 4: a * (1/a) = 1\n";
    for (uint8_t a : {2, 3, 5, 42, 255}) {
        uint8_t inv = GF256::divide(1, a);
        uint8_t result = GF256::multiply(a, inv);
        std::cout << "  " << static_cast<int>(a) << " * (1/" << static_cast<int>(a)
                  << ") = " << static_cast<int>(result)
                  << (result == 1 ? " ✅" : " ❌") << "\n";
    }

    // Test 5: (a * b) / b = a
    std::cout << "\nTest 5: (a * b) / b = a\n";
    uint8_t a = 42, b = 7;
    uint8_t product = GF256::multiply(a, b);
    uint8_t result = GF256::divide(product, b);
    std::cout << "  (" << static_cast<int>(a) << " * " << static_cast<int>(b)
              << ") / " << static_cast<int>(b) << " = " << static_cast<int>(result)
              << (result == a ? " ✅" : " ❌") << "\n";

    // Test 6: Addition (XOR)
    std::cout << "\nTest 6: Addition (XOR)\n";
    std::cout << "  5 + 3 = " << static_cast<int>(GF256::add(5, 3))
              << " (expected: 6)" << (GF256::add(5, 3) == 6 ? " ✅" : " ❌") << "\n";

    return 0;
}
