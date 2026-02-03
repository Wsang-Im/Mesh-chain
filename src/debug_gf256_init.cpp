/**
 * Debug GF256 table initialization
 */

#include <iostream>
#include <iomanip>
#include <cstdint>

int main() {
    static constexpr uint16_t POLY = 0x11B;
    uint8_t exp_table[512] = {0};
    uint8_t log_table[256] = {0};

    std::cout << "Initializing GF(256) tables...\n\n";

    uint16_t x = 1;
    for (int i = 0; i < 255; ++i) {
        exp_table[i] = static_cast<uint8_t>(x);
        log_table[x] = static_cast<uint8_t>(i);

        if (i < 30 || x == 3 || (i >= 23 && i <= 27)) {
            std::cout << "i=" << std::setw(3) << i
                      << ": x=" << std::setw(3) << x
                      << " (0x" << std::hex << std::setw(2) << std::setfill('0') << x << std::dec << ")"
                      << " -> exp[" << i << "]=" << static_cast<int>(exp_table[i])
                      << ", log[" << x << "]=" << static_cast<int>(log_table[x]) << "\n";
        }

        x <<= 1;
        if (x & 0x100) {
            x ^= POLY;
        }
    }

    std::cout << "\nChecking log_table[3]: " << static_cast<int>(log_table[3]) << "\n";
    std::cout << "exp_table[log_table[3]]: " << static_cast<int>(exp_table[log_table[3]]) << "\n";

    std::cout << "\nSearching for 3 in exp_table...\n";
    for (int i = 0; i < 255; ++i) {
        if (exp_table[i] == 3) {
            std::cout << "Found! exp_table[" << i << "] = 3\n";
            std::cout << "So alpha^" << i << " = 3\n";
            break;
        }
    }

    return 0;
}
