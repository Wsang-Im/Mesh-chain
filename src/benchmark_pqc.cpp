/**
 * PQC Cryptography Benchmark for Cortex-A72
 *
 * Purpose: Measure the actual performance of ML-KEM-768 and FALCON-512
 * Measurement items:
 * 1. ML-KEM-768 Key Generation (KeyGen)
 * 2. ML-KEM-768 Encapsulation (Encaps)
 * 3. ML-KEM-768 Decapsulation (Decaps)
 * 4. FALCON-512 Key Generation (KeyGen)
 * 5. FALCON-512 Signature Generation (Sign)
 * 6. FALCON-512 Signature Verification (Verify)
 *
 * Each operation is repeated multiple times to measure mean, min, max, and median
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <cmath>

// liboqs header
#include <oqs/oqs.h>

using namespace std;
using namespace std::chrono;

// Time measurement helper
class Timer {
public:
    void start() {
        start_time = high_resolution_clock::now();
    }

    double stop_us() {  // in microseconds
        auto end_time = high_resolution_clock::now();
        return duration_cast<microseconds>(end_time - start_time).count();
    }

    double stop_ms() {  // in milliseconds
        return stop_us() / 1000.0;
    }

private:
    high_resolution_clock::time_point start_time;
};

// Statistics calculation
struct Statistics {
    double min;
    double max;
    double mean;
    double median;
    double stddev;

    static Statistics calculate(vector<double>& samples) {
        Statistics stats;

        if (samples.empty()) {
            stats.min = stats.max = stats.mean = stats.median = stats.stddev = 0.0;
            return stats;
        }

        // Sort
        sort(samples.begin(), samples.end());

        // Min/Max
        stats.min = samples.front();
        stats.max = samples.back();

        // Mean
        double sum = 0.0;
        for (double s : samples) sum += s;
        stats.mean = sum / samples.size();

        // Median
        size_t mid = samples.size() / 2;
        if (samples.size() % 2 == 0) {
            stats.median = (samples[mid-1] + samples[mid]) / 2.0;
        } else {
            stats.median = samples[mid];
        }

        // Standard deviation
        double variance = 0.0;
        for (double s : samples) {
            double diff = s - stats.mean;
            variance += diff * diff;
        }
        stats.stddev = sqrt(variance / samples.size());

        return stats;
    }

    void print(const string& name, const string& unit) const {
        cout << fixed << setprecision(3);
        cout << "  " << name << ":\n";
        cout << "    Mean: " << mean << " " << unit << "\n";
        cout << "    Median: " << median << " " << unit << "\n";
        cout << "    Min: " << min << " " << unit << "\n";
        cout << "    Max: " << max << " " << unit << "\n";
        cout << "    StdDev: " << stddev << " " << unit << "\n";
    }
};

// ML-KEM-768 benchmark
void benchmark_mlkem768(int iterations, ofstream& csv_file) {
    cout << "\n========================================\n";
    cout << "ML-KEM-768 (Kyber768) Benchmark\n";
    cout << "========================================\n";
    cout << "Iterations: " << iterations << "\n\n";

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        cerr << "Error: ML-KEM-768 initialization failed\n";
        return;
    }

    vector<double> keygen_times;
    vector<double> encaps_times;
    vector<double> decaps_times;

    Timer timer;

    // Warmup
    cout << "Warming up...\n";
    for (int i = 0; i < 10; i++) {
        uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
        uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
        uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
        uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
        uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

        OQS_KEM_keypair(kem, public_key, secret_key);
        OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
        OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    }

    cout << "Running benchmark...\n";

    // Actual measurement
    for (int i = 0; i < iterations; i++) {
        uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
        uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
        uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
        uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
        uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

        // KeyGen
        timer.start();
        OQS_KEM_keypair(kem, public_key, secret_key);
        keygen_times.push_back(timer.stop_us());

        // Encaps
        timer.start();
        OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
        encaps_times.push_back(timer.stop_us());

        // Decaps
        timer.start();
        OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
        decaps_times.push_back(timer.stop_us());

        if ((i + 1) % 100 == 0) {
            cout << "  Progress: " << (i + 1) << "/" << iterations << "\r" << flush;
        }
    }
    cout << "\n";

    // Calculate statistics
    Statistics keygen_stats = Statistics::calculate(keygen_times);
    Statistics encaps_stats = Statistics::calculate(encaps_times);
    Statistics decaps_stats = Statistics::calculate(decaps_times);

    // Print results
    cout << "\nResults:\n";
    keygen_stats.print("KeyGen", "μs");
    cout << "\n";
    encaps_stats.print("Encaps", "μs");
    cout << "\n";
    decaps_stats.print("Decaps", "μs");

    // Save to CSV
    csv_file << "ML-KEM-768,KeyGen," << keygen_stats.mean << "," << keygen_stats.median
             << "," << keygen_stats.min << "," << keygen_stats.max << "," << keygen_stats.stddev << "\n";
    csv_file << "ML-KEM-768,Encaps," << encaps_stats.mean << "," << encaps_stats.median
             << "," << encaps_stats.min << "," << encaps_stats.max << "," << encaps_stats.stddev << "\n";
    csv_file << "ML-KEM-768,Decaps," << decaps_stats.mean << "," << decaps_stats.median
             << "," << decaps_stats.min << "," << decaps_stats.max << "," << decaps_stats.stddev << "\n";

    OQS_KEM_free(kem);
}

// FALCON-512 benchmark
void benchmark_falcon512(int iterations, ofstream& csv_file) {
    cout << "\n========================================\n";
    cout << "FALCON-512 Benchmark\n";
    cout << "========================================\n";
    cout << "Iterations: " << iterations << "\n\n";

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) {
        cerr << "Error: FALCON-512 initialization failed\n";
        return;
    }

    vector<double> keygen_times;
    vector<double> sign_times;
    vector<double> verify_times;

    Timer timer;

    // Test message
    const char* message = "This is a test message for FALCON-512 signature benchmark on Cortex-A72";
    size_t message_len = strlen(message);

    // Warmup
    cout << "Warming up...\n";
    for (int i = 0; i < 10; i++) {
        uint8_t public_key[OQS_SIG_falcon_512_length_public_key];
        uint8_t secret_key[OQS_SIG_falcon_512_length_secret_key];
        uint8_t signature[OQS_SIG_falcon_512_length_signature];
        size_t signature_len;

        OQS_SIG_keypair(sig, public_key, secret_key);
        OQS_SIG_sign(sig, signature, &signature_len, (const uint8_t*)message, message_len, secret_key);
        OQS_SIG_verify(sig, (const uint8_t*)message, message_len, signature, signature_len, public_key);
    }

    cout << "Running benchmark...\n";

    // Actual measurement
    for (int i = 0; i < iterations; i++) {
        uint8_t public_key[OQS_SIG_falcon_512_length_public_key];
        uint8_t secret_key[OQS_SIG_falcon_512_length_secret_key];
        uint8_t signature[OQS_SIG_falcon_512_length_signature];
        size_t signature_len;

        // KeyGen
        timer.start();
        OQS_SIG_keypair(sig, public_key, secret_key);
        keygen_times.push_back(timer.stop_us());

        // Sign
        timer.start();
        OQS_SIG_sign(sig, signature, &signature_len, (const uint8_t*)message, message_len, secret_key);
        sign_times.push_back(timer.stop_us());

        // Verify
        timer.start();
        OQS_SIG_verify(sig, (const uint8_t*)message, message_len, signature, signature_len, public_key);
        verify_times.push_back(timer.stop_us());

        if ((i + 1) % 100 == 0) {
            cout << "  Progress: " << (i + 1) << "/" << iterations << "\r" << flush;
        }
    }
    cout << "\n";

    // Calculate statistics
    Statistics keygen_stats = Statistics::calculate(keygen_times);
    Statistics sign_stats = Statistics::calculate(sign_times);
    Statistics verify_stats = Statistics::calculate(verify_times);

    // Print results
    cout << "\nResults:\n";
    keygen_stats.print("KeyGen", "μs");
    cout << "\n";
    sign_stats.print("Sign", "μs");
    cout << "\n";
    verify_stats.print("Verify", "μs");

    // Save to CSV
    csv_file << "FALCON-512,KeyGen," << keygen_stats.mean << "," << keygen_stats.median
             << "," << keygen_stats.min << "," << keygen_stats.max << "," << keygen_stats.stddev << "\n";
    csv_file << "FALCON-512,Sign," << sign_stats.mean << "," << sign_stats.median
             << "," << sign_stats.min << "," << sign_stats.max << "," << sign_stats.stddev << "\n";
    csv_file << "FALCON-512,Verify," << verify_stats.mean << "," << verify_stats.median
             << "," << verify_stats.min << "," << verify_stats.max << "," << verify_stats.stddev << "\n";

    OQS_SIG_free(sig);
}

// Print system information
void print_system_info() {
    cout << "========================================\n";
    cout << "System Information\n";
    cout << "========================================\n";

    // CPU information
    ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        string line;
        bool found_model = false;
        while (getline(cpuinfo, line) && !found_model) {
            if (line.find("model name") != string::npos ||
                line.find("Processor") != string::npos) {
                cout << line << "\n";
                found_model = true;
            }
        }
        cpuinfo.close();
    }

    // liboqs version (OQS_VERSION macro may not be available)
    cout << "liboqs: installed\n";

    cout << "========================================\n\n";
}

int main(int argc, char** argv) {
    int iterations = 1000;  // default value

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            cerr << "Error: iteration count must be positive.\n";
            return 1;
        }
    }

    cout << "\n";
    cout << "╔════════════════════════════════════════════════════╗\n";
    cout << "║  PQC Cryptography Benchmark for Cortex-A72        ║\n";
    cout << "║  ML-KEM-768 & FALCON-512 Performance Test         ║\n";
    cout << "╚════════════════════════════════════════════════════╝\n";
    cout << "\n";

    print_system_info();

    // Open CSV file
    ofstream csv_file("pqc_benchmark_results.csv");
    csv_file << "Algorithm,Operation,Mean(us),Median(us),Min(us),Max(us),StdDev(us)\n";

    // Run benchmarks
    benchmark_mlkem768(iterations, csv_file);
    benchmark_falcon512(iterations, csv_file);

    csv_file.close();

    cout << "\n========================================\n";
    cout << "Benchmark completed!\n";
    cout << "Results saved to 'pqc_benchmark_results.csv'.\n";
    cout << "========================================\n\n";

    return 0;
}
