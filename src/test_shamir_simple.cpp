/**
 * Minimal Shamir test - single byte
 */

#include "storage/shamir_secret_sharing.h"
#include <iostream>
#include <iomanip>

using namespace meshchain::storage;

int main() {
    std::cout << "=== Minimal Shamir Test ===\n\n";

    // Secret: single byte
    std::vector<uint8_t> secret = {0x42};
    std::cout << "Secret: 0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(secret[0]) << std::dec << "\n\n";

    // Split (3,5)
    ShamirSecretSharing sss(3, 5);
    auto shares = sss.split(secret);

    std::cout << "Shares:\n";
    for (size_t i = 0; i < shares.size(); ++i) {
        std::cout << "  Share " << static_cast<int>(shares[i].x) << ": y=0x"
                  << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(shares[i].y[0]) << std::dec << "\n";
    }

    // Reconstruct from first 3
    std::vector<ShamirShare> subset = {shares[0], shares[1], shares[2]};
    auto reconstructed = sss.reconstruct(subset);

    std::cout << "\nReconstructed: 0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(reconstructed[0]) << std::dec << "\n";

    if (reconstructed[0] == secret[0]) {
        std::cout << "✅ Match!\n";
        return 0;
    } else {
        std::cout << "❌ Mismatch!\n";
        return 1;
    }
}
