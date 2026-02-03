#include "src/storage/oprf_search.h"
#include <iostream>

using namespace meshchain;
using namespace meshchain::storage;

int main() {
    OPRFKey key;
    BucketConfig config;
    OPRFSearchIndex index(key, config);

    std::string attribute = "vehicle_X";
    Hash256 record_ptr;
    std::fill(record_ptr.begin(), record_ptr.end(), 0xAA);

    // Insert
    std::cout << "Inserting record with attribute: " << attribute << "\n";
    index.insert(attribute, record_ptr, 0.5);

    // Generate token directly for comparison
    SearchToken direct_token = index.generateSearchToken(attribute);
    std::cout << "Direct token (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) {
        printf("%02x", direct_token.token[i]);
    }
    std::cout << "\n";

    // Search via OPRF protocol
    BlindedToken blinded = index.blindToken(attribute);
    EvaluatedToken evaluated = index.evaluateToken(blinded);
    SearchToken search_token = index.unblindToken(evaluated, attribute);

    std::cout << "Search token (first 8 bytes): ";
    for (int i = 0; i < 8; ++i) {
        printf("%02x", search_token.token[i]);
    }
    std::cout << "\n";

    // Check if they match
    bool match = (direct_token.token == search_token.token);
    std::cout << "Tokens match: " << (match ? "YES" : "NO") << "\n";

    // Search
    auto results = index.search(search_token);
    std::cout << "Search results: " << results.size() << " records\n";

    bool found = false;
    for (const auto& ptr : results) {
        if (ptr == record_ptr) {
            found = true;
            break;
        }
    }

    std::cout << "Record found: " << (found ? "YES" : "NO") << "\n";

    return found ? 0 : 1;
}
