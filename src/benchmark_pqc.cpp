/**
 * PQC Cryptography Benchmark for Cortex-A72
 *
 * 목적: ML-KEM-768과 FALCON-512의 실제 성능을 측정
 * 측정 항목:
 * 1. ML-KEM-768 키 생성 (KeyGen)
 * 2. ML-KEM-768 캡슐화 (Encaps)
 * 3. ML-KEM-768 역캡슐화 (Decaps)
 * 4. FALCON-512 키 생성 (KeyGen)
 * 5. FALCON-512 서명 생성 (Sign)
 * 6. FALCON-512 서명 검증 (Verify)
 *
 * 각 연산을 여러 번 반복하여 평균, 최소, 최대, 중간값을 측정
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <cmath>

// liboqs 헤더
#include <oqs/oqs.h>

using namespace std;
using namespace std::chrono;

// 시간 측정 헬퍼
class Timer {
public:
    void start() {
        start_time = high_resolution_clock::now();
    }

    double stop_us() {  // 마이크로초 단위
        auto end_time = high_resolution_clock::now();
        return duration_cast<microseconds>(end_time - start_time).count();
    }

    double stop_ms() {  // 밀리초 단위
        return stop_us() / 1000.0;
    }

private:
    high_resolution_clock::time_point start_time;
};

// 통계 계산
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

        // 정렬
        sort(samples.begin(), samples.end());

        // 최소/최대
        stats.min = samples.front();
        stats.max = samples.back();

        // 평균
        double sum = 0.0;
        for (double s : samples) sum += s;
        stats.mean = sum / samples.size();

        // 중간값
        size_t mid = samples.size() / 2;
        if (samples.size() % 2 == 0) {
            stats.median = (samples[mid-1] + samples[mid]) / 2.0;
        } else {
            stats.median = samples[mid];
        }

        // 표준편차
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
        cout << "    평균: " << mean << " " << unit << "\n";
        cout << "    중간: " << median << " " << unit << "\n";
        cout << "    최소: " << min << " " << unit << "\n";
        cout << "    최대: " << max << " " << unit << "\n";
        cout << "    표준편차: " << stddev << " " << unit << "\n";
    }
};

// ML-KEM-768 벤치마크
void benchmark_mlkem768(int iterations, ofstream& csv_file) {
    cout << "\n========================================\n";
    cout << "ML-KEM-768 (Kyber768) 벤치마크\n";
    cout << "========================================\n";
    cout << "반복 횟수: " << iterations << "\n\n";

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        cerr << "Error: ML-KEM-768 초기화 실패\n";
        return;
    }

    vector<double> keygen_times;
    vector<double> encaps_times;
    vector<double> decaps_times;

    Timer timer;

    // 워밍업
    cout << "워밍업 중...\n";
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

    cout << "벤치마크 실행 중...\n";

    // 실제 측정
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
            cout << "  진행: " << (i + 1) << "/" << iterations << "\r" << flush;
        }
    }
    cout << "\n";

    // 통계 계산
    Statistics keygen_stats = Statistics::calculate(keygen_times);
    Statistics encaps_stats = Statistics::calculate(encaps_times);
    Statistics decaps_stats = Statistics::calculate(decaps_times);

    // 결과 출력
    cout << "\n결과:\n";
    keygen_stats.print("KeyGen", "μs");
    cout << "\n";
    encaps_stats.print("Encaps", "μs");
    cout << "\n";
    decaps_stats.print("Decaps", "μs");

    // CSV 저장
    csv_file << "ML-KEM-768,KeyGen," << keygen_stats.mean << "," << keygen_stats.median
             << "," << keygen_stats.min << "," << keygen_stats.max << "," << keygen_stats.stddev << "\n";
    csv_file << "ML-KEM-768,Encaps," << encaps_stats.mean << "," << encaps_stats.median
             << "," << encaps_stats.min << "," << encaps_stats.max << "," << encaps_stats.stddev << "\n";
    csv_file << "ML-KEM-768,Decaps," << decaps_stats.mean << "," << decaps_stats.median
             << "," << decaps_stats.min << "," << decaps_stats.max << "," << decaps_stats.stddev << "\n";

    OQS_KEM_free(kem);
}

// FALCON-512 벤치마크
void benchmark_falcon512(int iterations, ofstream& csv_file) {
    cout << "\n========================================\n";
    cout << "FALCON-512 벤치마크\n";
    cout << "========================================\n";
    cout << "반복 횟수: " << iterations << "\n\n";

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) {
        cerr << "Error: FALCON-512 초기화 실패\n";
        return;
    }

    vector<double> keygen_times;
    vector<double> sign_times;
    vector<double> verify_times;

    Timer timer;

    // 테스트 메시지
    const char* message = "This is a test message for FALCON-512 signature benchmark on Cortex-A72";
    size_t message_len = strlen(message);

    // 워밍업
    cout << "워밍업 중...\n";
    for (int i = 0; i < 10; i++) {
        uint8_t public_key[OQS_SIG_falcon_512_length_public_key];
        uint8_t secret_key[OQS_SIG_falcon_512_length_secret_key];
        uint8_t signature[OQS_SIG_falcon_512_length_signature];
        size_t signature_len;

        OQS_SIG_keypair(sig, public_key, secret_key);
        OQS_SIG_sign(sig, signature, &signature_len, (const uint8_t*)message, message_len, secret_key);
        OQS_SIG_verify(sig, (const uint8_t*)message, message_len, signature, signature_len, public_key);
    }

    cout << "벤치마크 실행 중...\n";

    // 실제 측정
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
            cout << "  진행: " << (i + 1) << "/" << iterations << "\r" << flush;
        }
    }
    cout << "\n";

    // 통계 계산
    Statistics keygen_stats = Statistics::calculate(keygen_times);
    Statistics sign_stats = Statistics::calculate(sign_times);
    Statistics verify_stats = Statistics::calculate(verify_times);

    // 결과 출력
    cout << "\n결과:\n";
    keygen_stats.print("KeyGen", "μs");
    cout << "\n";
    sign_stats.print("Sign", "μs");
    cout << "\n";
    verify_stats.print("Verify", "μs");

    // CSV 저장
    csv_file << "FALCON-512,KeyGen," << keygen_stats.mean << "," << keygen_stats.median
             << "," << keygen_stats.min << "," << keygen_stats.max << "," << keygen_stats.stddev << "\n";
    csv_file << "FALCON-512,Sign," << sign_stats.mean << "," << sign_stats.median
             << "," << sign_stats.min << "," << sign_stats.max << "," << sign_stats.stddev << "\n";
    csv_file << "FALCON-512,Verify," << verify_stats.mean << "," << verify_stats.median
             << "," << verify_stats.min << "," << verify_stats.max << "," << verify_stats.stddev << "\n";

    OQS_SIG_free(sig);
}

// 시스템 정보 출력
void print_system_info() {
    cout << "========================================\n";
    cout << "시스템 정보\n";
    cout << "========================================\n";

    // CPU 정보
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

    // liboqs 버전 (OQS_VERSION 매크로가 없을 수 있음)
    cout << "liboqs: 설치됨\n";

    cout << "========================================\n\n";
}

int main(int argc, char** argv) {
    int iterations = 1000;  // 기본값

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            cerr << "Error: 반복 횟수는 양수여야 합니다.\n";
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

    // CSV 파일 오픈
    ofstream csv_file("pqc_benchmark_results.csv");
    csv_file << "Algorithm,Operation,Mean(us),Median(us),Min(us),Max(us),StdDev(us)\n";

    // 벤치마크 실행
    benchmark_mlkem768(iterations, csv_file);
    benchmark_falcon512(iterations, csv_file);

    csv_file.close();

    cout << "\n========================================\n";
    cout << "벤치마크 완료!\n";
    cout << "결과가 'pqc_benchmark_results.csv'에 저장되었습니다.\n";
    cout << "========================================\n\n";

    return 0;
}
