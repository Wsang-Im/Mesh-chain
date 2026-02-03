/**
 * Debug test: Shamir Secret Sharing with AEAD key
 */

#include "storage/shamir_secret_sharing.h"
#include "crypto/secure_channel.h"
#include <iostream>
#include <iomanip>

using namespace meshchain;
using namespace meshchain::storage;
using namespace meshchain::crypto;

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), size_t(16)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > 16) {
        std::cout << "... (" << std::dec << data.size() << " bytes)";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== Shamir + AEAD Integration Test ===\n\n";

    // 1. Generate random AEAD key
    std::vector<uint8_t> original_key(AEAD::KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < original_key.size(); ++i) {
        original_key[i] = static_cast<uint8_t>(dis(gen));
    }

    printHex("Original key", original_key);

    // 2. Split key using Shamir (3,5)
    ShamirSecretSharing sss(3, 5);
    auto shares = sss.split(original_key);

    std::cout << "\nSplit into " << shares.size() << " shares\n";
    for (size_t i = 0; i < shares.size(); ++i) {
        std::cout << "  Share " << static_cast<int>(shares[i].x)
                  << ": " << shares[i].y.size() << " bytes\n";
    }

    // 3. Reconstruct key from first 3 shares
    std::vector<ShamirShare> subset;
    for (size_t i = 0; i < 3; ++i) {
        subset.push_back(shares[i]);
    }

    auto reconstructed_key = sss.reconstruct(subset);
    printHex("\nReconstructed key", reconstructed_key);

    // 4. Compare keys
    if (reconstructed_key == original_key) {
        std::cout << "✅ Keys match!\n\n";
    } else {
        std::cout << "❌ Keys DON'T match!\n";
        std::cout << "Original size: " << original_key.size() << "\n";
        std::cout << "Reconstructed size: " << reconstructed_key.size() << "\n";

        std::cout << "\nByte-by-byte comparison:\n";
        for (size_t i = 0; i < std::min(original_key.size(), reconstructed_key.size()); ++i) {
            if (original_key[i] != reconstructed_key[i]) {
                std::cout << "  [" << i << "] "
                          << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(original_key[i])
                          << " != "
                          << std::setw(2) << std::setfill('0')
                          << static_cast<int>(reconstructed_key[i])
                          << std::dec << "\n";
            }
        }
        return 1;
    }

    // 5. Test AEAD with original key
    std::string message = "Test message for AEAD";
    std::vector<uint8_t> plaintext(message.begin(), message.end());

    std::cout << "Encrypting with original key...\n";
    auto encrypted = AEAD::encrypt(original_key, plaintext);
    printHex("Ciphertext", encrypted.ciphertext);

    std::cout << "\nDecrypting with reconstructed key...\n";
    try {
        auto decrypted = AEAD::decrypt(reconstructed_key, encrypted);
        std::string decrypted_message(decrypted.begin(), decrypted.end());

        if (decrypted_message == message) {
            std::cout << "✅ Decryption successful!\n";
            std::cout << "   Message: \"" << decrypted_message << "\"\n";
            return 0;
        } else {
            std::cout << "❌ Decrypted message doesn't match!\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ Decryption failed: " << e.what() << "\n";
        return 1;
    }
}
