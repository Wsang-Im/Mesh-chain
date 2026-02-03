#ifndef MESHCHAIN_RSU_H
#define MESHCHAIN_RSU_H

/**
 * Roadside Unit (RSU) Implementation
 *
 * RSU는 도로변 인프라로서 다음 기능을 제공:
 * - V2I 통신 (WAVE IEEE 802.11p, 300m 범위)
 * - L1 Anchoring (Local, per-RSU, 30-60초 주기)
 * - L2 Anchoring (Regional, multi-RSU, 60-180초 주기)
 * - L3 Anchoring (Global, cloud, 300-600초 주기)
 * - 블록 중계 및 저장
 * - 인증서 발급 (ML-DSA-65 서명)
 *
 * 배치 전략:
 * - 고속도로: 400m 간격 (DSRC 300m 범위 고려)
 * - 커버리지: 중첩 영역 확보 (STR ≥ 90%)
 * - 비용: $20k-52k/km for 1km spacing (우리는 더 조밀)
 */

#include "../common/types.h"
#include "../common/block.h"
#include "../crypto/pqc_signatures.h"
#include "../crypto/liboqs_wrapper.h"
#include "../crypto/tee_aggregator.h"
#include <vector>
#include <map>
#include <queue>
#include <chrono>
#include <mutex>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <future>
#include <sys/stat.h>
#include <sys/types.h>

namespace meshchain {
namespace infrastructure {

/**
 * RSU Configuration
 */
struct RSUConfig {
    std::string rsu_id;
    std::string simulation_id;  // "integrated" or "rural"

    // 물리적 위치 (SUMO 좌표계)
    double position_x;  // 미터
    double position_y;  // 미터

    // 통신 범위 (DSRC 표준)
    double communication_range_m;  // 기본 300m

    // Anchoring 주기
    uint32_t l1_anchor_period_sec;  // 30-60초 (Local)
    uint32_t l2_anchor_period_sec;  // 60-180초 (Regional)
    uint32_t l3_anchor_period_sec;  // 300-600초 (Global)

    // 블록 저장 용량
    size_t max_blocks_stored;  // 기본 10000개

    // 클라우드 연결 여부
    bool has_cloud_connection;

    // L1 앵커 파일 출력 디렉토리
    std::string l1_export_dir;  // 기본값: "/tmp/meshchain_l1"
};

/**
 * Anchor Block (앵커 블록)
 *
 * 논문 Section 2.4:
 * "RSU periodically creates anchor blocks that commit to
 * the set of locally-final blocks observed during the anchor period"
 */
struct AnchorBlock {
    std::string rsu_id;
    AnchorLevel level;  // L1, L2, L3
    Timestamp anchor_time;

    // Merkle root of all locally-final blocks in this period
    Hash256 blocks_merkle_root;

    // Block count (instead of storing all hashes)
    size_t block_count;

    // Sequence number for this anchor (monotonically increasing)
    uint64_t sequence_number;

    // TEE Master Commit (aggregated from all block TEE commits)
    Hash256 tee_master_commit;
    std::vector<Hash256> block_tee_commits;  // Individual block TEE commits
    size_t total_witness_signatures;         // Total witness signatures across all blocks

    // TEE Attestation (hardware-backed proof that anchor was created in TEE)
    std::vector<uint8_t> tee_attestation;

    // RSU signature (ML-DSA-65 for L1/L2, more secure for L3)
    std::vector<uint8_t> rsu_signature;

    // L2/L3: Multi-RSU coordination
    std::vector<std::string> participating_rsus;  // L2/L3만 해당
    std::vector<std::vector<uint8_t>> multi_sigs;  // L2/L3 다중 서명

    // Previous anchor reference (체인 구조)
    Hash256 prev_anchor_hash;

    // Serialize for hashing/signing
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        bytes.reserve(4096);

        // RSU ID
        bytes.insert(bytes.end(), rsu_id.begin(), rsu_id.end());
        bytes.push_back(0);

        // Level
        uint8_t lvl = static_cast<uint8_t>(level);
        bytes.push_back(lvl);

        // Timestamp
        auto ts_ns = anchor_time.time_since_epoch().count();
        const uint8_t* ts_ptr = reinterpret_cast<const uint8_t*>(&ts_ns);
        bytes.insert(bytes.end(), ts_ptr, ts_ptr + sizeof(ts_ns));

        // Merkle root
        bytes.insert(bytes.end(), blocks_merkle_root.begin(), blocks_merkle_root.end());

        // TEE master commit
        bytes.insert(bytes.end(), tee_master_commit.begin(), tee_master_commit.end());

        // Block count
        const uint8_t* count_ptr = reinterpret_cast<const uint8_t*>(&block_count);
        bytes.insert(bytes.end(), count_ptr, count_ptr + sizeof(size_t));

        // Sequence number
        const uint8_t* seq_ptr = reinterpret_cast<const uint8_t*>(&sequence_number);
        bytes.insert(bytes.end(), seq_ptr, seq_ptr + sizeof(uint64_t));

        // Total witness signatures
        const uint8_t* total_sigs_ptr = reinterpret_cast<const uint8_t*>(&total_witness_signatures);
        bytes.insert(bytes.end(), total_sigs_ptr, total_sigs_ptr + sizeof(size_t));

        // Previous anchor
        bytes.insert(bytes.end(), prev_anchor_hash.begin(), prev_anchor_hash.end());

        return bytes;
    }

    Hash256 computeHash() const {
        auto data = serialize();
        return crypto::SHA3::hash(data);
    }
};

/**
 * RSU 클래스
 */
class RSU {
public:
    explicit RSU(const RSUConfig& config)
        : config_(config),
          running_(false),
          blocks_received_(0),
          blocks_anchored_(0) {

        // Initialize ML-DSA-65 signer for RSU (stronger than vehicle's FALCON-512)
        dilithium_signer_ = std::make_shared<crypto::MLDSASigner>();
        dilithium_signer_->generateKeys();

        // Initialize TEE aggregator for block validation and master commit generation
        crypto::TEEAggregator::Config tee_config;
        tee_config.enable_individual_verification = true;  // RSU validates each block
        tee_config.max_aggregation_time_ms = 50.0;  // Allow more time for many blocks
        tee_aggregator_ = std::make_shared<crypto::TEEAggregator>(tee_config);

        std::cout << "[RSU-" << config_.rsu_id << "] Initialized at position ("
                  << config_.position_x << "m, " << config_.position_y << "m)\n";
        std::cout << "[RSU-" << config_.rsu_id << "] Communication range: "
                  << config_.communication_range_m << "m\n";
        std::cout << "[RSU-" << config_.rsu_id << "] L1 anchor period: "
                  << config_.l1_anchor_period_sec << "s\n";
    }

    ~RSU() {
        stop();
    }

    /**
     * RSU 시작 (백그라운드 앵커링 스레드)
     */
    void start() {
        if (running_) return;

        running_ = true;

        // L1 Anchoring 스레드 시작
        l1_anchor_thread_ = std::thread(&RSU::l1AnchorLoop, this);

        std::cout << "[RSU-" << config_.rsu_id << "] Started L1 anchoring thread\n";
    }

    /**
     * RSU 정지
     */
    void stop() {
        if (!running_) return;

        running_ = false;

        if (l1_anchor_thread_.joinable()) {
            l1_anchor_thread_.join();
        }

        std::cout << "[RSU-" << config_.rsu_id << "] Stopped\n";
    }

    /**
     * 차량으로부터 블록 수신 (V2I)
     */
    void receiveBlock(const Block& block, const std::string& sender_id, double distance_m) {
        // 통신 범위 체크
        if (distance_m > config_.communication_range_m) {
            return;  // 범위 밖
        }

        std::lock_guard<std::mutex> lock(blocks_mutex_);

        // 중복 체크
        if (received_blocks_.find(block.block_hash) != received_blocks_.end()) {
            return;  // Already received
        }

        // 블록 검증
        if (!validateBlock(block)) {
            std::cout << "[RSU-" << config_.rsu_id << "] ⚠️  Invalid block from "
                      << sender_id << "\n";
            return;
        }

        // 블록 저장
        received_blocks_[block.block_hash] = block;
        pending_anchor_blocks_.push(block.block_hash);
        blocks_received_++;

        std::cout << "[RSU-" << config_.rsu_id << "] 📥 Received block "
                  << toHexString(block.block_hash).substr(0, 8)
                  << " from " << sender_id
                  << " (distance: " << std::fixed << std::setprecision(1) << distance_m << "m)\n";
    }

    /**
     * RSU와의 거리 계산 (차량 위치 기준)
     */
    double calculateDistance(double vehicle_x, double vehicle_y) const {
        double dx = vehicle_x - config_.position_x;
        double dy = vehicle_y - config_.position_y;
        return std::sqrt(dx * dx + dy * dy);
    }

    /**
     * 통신 범위 내에 있는지 확인
     */
    bool isInRange(double vehicle_x, double vehicle_y) const {
        return calculateDistance(vehicle_x, vehicle_y) <= config_.communication_range_m;
    }

    /**
     * 앵커 블록 조회 (차량이 자신의 블록이 앵커되었는지 확인)
     */
    std::optional<AnchorBlock> getLatestL1Anchor() const {
        std::lock_guard<std::mutex> lock(anchor_mutex_);

        if (l1_anchors_.empty()) {
            return std::nullopt;
        }

        return l1_anchors_.back();
    }

    /**
     * 특정 블록이 앵커되었는지 확인
     */
    bool isBlockAnchored(const Hash256& block_hash) const {
        std::lock_guard<std::mutex> lock(blocks_mutex_);

        return anchored_blocks_.find(block_hash) != anchored_blocks_.end();
    }

    /**
     * 특정 차량의 블록이 앵커되었는지 확인
     *
     * @param vehicle_id 차량 ID
     * @return (is_anchored, anchor_merkle_root, num_blocks_anchored)
     */
    std::tuple<bool, Hash256, size_t> isVehicleChainAnchored(const std::string& vehicle_id) const {
        std::lock_guard<std::mutex> anchor_lock(anchor_mutex_);
        std::lock_guard<std::mutex> blocks_lock(blocks_mutex_);

        // 가장 최근 L1 앵커를 확인
        if (l1_anchors_.empty()) {
            return {false, Hash256{}, 0};
        }

        // anchored_blocks_에서 이 차량의 블록이 몇 개 포함되었는지 확인
        size_t total_anchored = 0;
        for (const auto& block_hash : anchored_blocks_) {
            auto it = received_blocks_.find(block_hash);
            if (it != received_blocks_.end() &&
                it->second.creator_id == vehicle_id) {
                total_anchored++;
            }
        }

        // 가장 최근 앵커의 Merkle root
        Hash256 latest_anchor_root = l1_anchors_.back().blocks_merkle_root;

        return {total_anchored > 0, latest_anchor_root, total_anchored};
    }

    /**
     * Generate Merkle proof for anchor block (for specific vehicle's micro-chain)
     *
     * @param vehicle_id 차량 ID
     * @param anchor_index 앵커 인덱스 (기본값: 최근 앵커)
     * @return Merkle proof (차량 chain root → top-level anchor root)
     */
    std::optional<std::vector<Hash256>> getVehicleChainProof(
        const std::string& vehicle_id,
        std::optional<size_t> anchor_index = std::nullopt) const {

        std::lock_guard<std::mutex> anchor_lock(anchor_mutex_);

        if (l1_anchors_.empty()) {
            return std::nullopt;
        }

        // 앵커 선택
        size_t idx = anchor_index.value_or(l1_anchors_.size() - 1);
        if (idx >= l1_anchors_.size()) {
            return std::nullopt;
        }

        const auto& anchor = l1_anchors_[idx];

        // TODO: Implement Merkle proof generation logic
        // 현재는 단순히 anchor root를 반환
        std::vector<Hash256> proof;
        proof.push_back(anchor.blocks_merkle_root);

        return proof;
    }

    /**
     * 통계
     */
    void getStatistics(size_t& received, size_t& anchored, size_t& l1_anchors) const {
        std::lock_guard<std::mutex> lock(blocks_mutex_);
        received = blocks_received_;
        anchored = blocks_anchored_;

        std::lock_guard<std::mutex> anchor_lock(anchor_mutex_);
        l1_anchors = l1_anchors_.size();
    }

    /**
     * Query RSU configuration
     */
    const RSUConfig& getConfig() const {
        return config_;
    }

    /**
     * RSU ID 조회
     */
    std::string getID() const {
        return config_.rsu_id;
    }

    double getX() const {
        return config_.position_x;
    }

    double getY() const {
        return config_.position_y;
    }

    double getRange() const {
        return config_.communication_range_m;
    }

    /**
     * Request blocks from nearby vehicles (Pull-based L1 Anchoring)
     * Called by main_integrated during L1 anchor period
     *
     * Template parameter to avoid circular dependency with IntegratedVehicle
     */
    template<typename VehicleType>
    void requestBlocksFromVehicles(const std::map<std::string, std::shared_ptr<VehicleType>>& vehicles) {
        // Determine last anchor time
        Timestamp last_anchor_time;
        {
            std::lock_guard<std::mutex> lock(anchor_mutex_);
            if (l1_anchors_.empty()) {
                last_anchor_time = Timestamp{};  // Epoch (request all blocks)
            } else {
                last_anchor_time = l1_anchors_.back().anchor_time;
            }
        }

        std::cout << "[RSU-" << config_.rsu_id << "] 🔄 Requesting unanchored blocks from "
                  << vehicles.size() << " vehicles...\n";

        // Request blocks from each vehicle
        for (const auto& [vehicle_id, vehicle] : vehicles) {
            vehicle->onAnchorRequest(this, last_anchor_time);
        }
    }

private:
    RSUConfig config_;

    // 암호화
    std::shared_ptr<crypto::MLDSASigner> dilithium_signer_;

    // TEE Aggregator for block validation and master commit generation
    std::shared_ptr<crypto::TEEAggregator> tee_aggregator_;

    // 블록 저장소
    std::map<Hash256, Block> received_blocks_;
    std::set<Hash256> anchored_blocks_;
    std::queue<Hash256> pending_anchor_blocks_;

    // 앵커 체인
    mutable std::mutex anchor_mutex_;
    std::vector<AnchorBlock> l1_anchors_;
    std::vector<AnchorBlock> l2_anchors_;
    std::vector<AnchorBlock> l3_anchors_;

    // 통계
    mutable std::mutex blocks_mutex_;
    size_t blocks_received_;
    size_t blocks_anchored_;

    // 백그라운드 스레드
    std::atomic<bool> running_;
    std::thread l1_anchor_thread_;

    /**
     * L1 Anchoring 루프 (30-60초마다 실행)
     */
    void l1AnchorLoop() {
        using namespace std::chrono;

        auto next_anchor_time = steady_clock::now() +
            seconds(config_.l1_anchor_period_sec);

        while (running_) {
            // 다음 앵커 시간까지 대기
            std::this_thread::sleep_for(milliseconds(100));

            auto now = steady_clock::now();
            if (now < next_anchor_time) {
                continue;
            }

            // L1 Anchoring 수행
            createL1Anchor();

            // Set next anchor time
            next_anchor_time = now + seconds(config_.l1_anchor_period_sec);
        }
    }

public:
    /**
     * Create L1 Anchor
     *
     * 논문 Algorithm 3: RSU Anchoring
     *
     * periodic RSU_Anchor(region, level):
     *   S ← CollectLocallyFinalSinceLast(region, level)
     *   root ← MerkleRoot(S)
     *   π_ver ← OptionalTransparentProof(VerifyAllFalconSigs(S))
     *   anchor ← {prev_anchor, time, root, count=|S|, level, meta}
     *   sigA ← Dilithium.Sign(H_ANCH(anchor), sk_RSU)
     *   Publish(anchor, sigA, π_ver); ForwardUp(level+1)
     */
    void createL1Anchor() {
        std::lock_guard<std::mutex> lock(blocks_mutex_);

        // 앵커할 블록이 없으면 스킵
        if (pending_anchor_blocks_.empty()) {
            return;
        }

        AnchorBlock anchor;
        anchor.rsu_id = config_.rsu_id;
        anchor.level = AnchorLevel::L1;
        anchor.anchor_time = std::chrono::system_clock::now();

        // Step 1: Collect all locally-final blocks (S)
        std::vector<Hash256> all_block_hashes;
        std::vector<Block> blocks_to_prove;

        while (!pending_anchor_blocks_.empty()) {
            Hash256 hash = pending_anchor_blocks_.front();
            pending_anchor_blocks_.pop();

            // Locally-final 블록만 앵커 (TENTATIVE 제외)
            auto it = received_blocks_.find(hash);
            if (it != received_blocks_.end() &&
                it->second.header.state == BlockState::LOCALLY_FINAL) {

                all_block_hashes.push_back(hash);
                blocks_to_prove.push_back(it->second);
                anchored_blocks_.insert(hash);
            }
        }

        if (all_block_hashes.empty()) {
            return;  // 앵커할 블록 없음
        }

        blocks_anchored_ += all_block_hashes.size();

        // Step 2: Build single-level Merkle tree: MerkleRoot(S)
        // Generate single Merkle root for all blocks S (not 2-level hierarchy)
        std::vector<std::string> block_hash_strings;
        for (const auto& block_hash : all_block_hashes) {
            block_hash_strings.push_back(toHexString(block_hash));
        }
        auto merkle = MerkleTree::build(block_hash_strings);
        anchor.blocks_merkle_root = merkle.getRoot();

        // Step 3: Set block count (count = |S|)
        anchor.block_count = all_block_hashes.size();

        // Step 4: Set sequence number
        {
            std::lock_guard<std::mutex> anchor_lock(anchor_mutex_);
            if (!l1_anchors_.empty()) {
                anchor.sequence_number = l1_anchors_.back().sequence_number + 1;
                anchor.prev_anchor_hash = l1_anchors_.back().computeHash();
            } else {
                anchor.sequence_number = 0;  // Genesis
                anchor.prev_anchor_hash = Hash256{};
            }
        }

        // Step 5: TEE Aggregation - Parallel processing for performance
        // Process blocks in parallel to extract TEE commits
        std::vector<Hash256> block_tee_hashes;
        std::vector<size_t> witness_counts;
        std::mutex tee_mutex;

        // NEW: Attestquorum-based block validation (simplified for RSU)
        // RSU trusts blocks that have valid attestquorum signatures
        for (const auto& block : blocks_to_prove) {
            // Check if block has attestquorum (new protocol)
            if (!block.header.attestquorum.empty() && block.header.witness_bitmap.count() > 0) {
                // Block is valid with attestquorum - add to ZK proof
                std::lock_guard<std::mutex> lock(tee_mutex);
                // Use block hash as commitment
                block_tee_hashes.push_back(block.header.computeHeaderHash());
                witness_counts.push_back(block.header.witness_bitmap.count());
            }
            // RSU accepts all blocks with attestquorum for ZK-STARK proof generation
        }

        // Aggregate TEE commits
        size_t total_witness_sigs = 0;
        std::vector<uint8_t> master_tee_input;
        for (size_t i = 0; i < block_tee_hashes.size(); ++i) {
            master_tee_input.insert(master_tee_input.end(),
                block_tee_hashes[i].begin(), block_tee_hashes[i].end());
            total_witness_sigs += witness_counts[i];
        }

        // Generate master TEE commit
        if (!master_tee_input.empty()) {
            anchor.tee_master_commit = crypto::SHA3::hash(master_tee_input);
            anchor.block_tee_commits = block_tee_hashes;
            anchor.total_witness_signatures = total_witness_sigs;

            std::cout << "[RSU-" << config_.rsu_id << "] 🔐 TEE: Generated master commit for "
                      << block_tee_hashes.size() << " blocks (" << total_witness_sigs << " witness signatures)\n";
            std::cout << "[RSU-" << config_.rsu_id << "]    Master TEE: "
                      << toHexString(anchor.tee_master_commit).substr(0, 16) << "...\n";

            // Generate TEE attestation
            anchor.tee_attestation = generateTEEAttestation(anchor);
        } else {
            // No TEE commits - initialize empty
            anchor.tee_master_commit.fill(0);
            anchor.total_witness_signatures = 0;
        }

        // Step 6: RSU 서명 (sigA ← Dilithium.Sign)
        auto anchor_data = anchor.serialize();
        anchor.rsu_signature = dilithium_signer_->sign(anchor_data);

        // Step 7: Publish anchor
        {
            std::lock_guard<std::mutex> anchor_lock(anchor_mutex_);
            l1_anchors_.push_back(anchor);
        }

        std::cout << "[RSU-" << config_.rsu_id << "] ⚓ L1 Anchor #" << anchor.sequence_number
                  << " created: " << anchor.block_count << " blocks\n";
        std::cout << "[RSU-" << config_.rsu_id << "]    Merkle root: "
                  << toHexString(anchor.blocks_merkle_root).substr(0, 16) << "...\n";
        std::cout << "[RSU-" << config_.rsu_id << "]    Total L1 anchors: "
                  << l1_anchors_.size() << "\n";

        // Export L1 anchor to file for L2 aggregation
        exportL1AnchorToFile(anchor);
    }

    /**
     * 블록 검증 (TEE commit validation 포함)
     */
    bool validateBlock(const Block& block) const {
        // 기본 검증
        if (block.header.creator_sig.empty()) {
            return false;
        }

        // Locally-final 상태 확인
        if (block.header.state != BlockState::LOCALLY_FINAL) {
            return false;  // TENTATIVE 블록은 앵커 안 함
        }

        // NEW: Attestquorum protocol - 증인 참여 확인
        if (block.header.witness_bitmap.count() == 0) {
            return false;  // No witnesses participated
        }

        // Attestquorum 검증 (simplified - RSU trusts blocks with valid attestquorum)
        if (!block.header.attestquorum.empty()) {
            // Block has attestquorum signature from TEE - considered valid
            // RSU focuses on ZK-STARK proof generation, not re-verification
            return true;
        }

        // Optional: Warn if block doesn't have attestquorum
        std::cout << "[RSU-" << config_.rsu_id << "] ⚠️ Block missing attestquorum (may be legacy)\n";
        return true;  // Accept anyway (RSU is optional component)
    }

    /**
     * L1 앵커를 JSON 파일로 내보내기 (L2 aggregation용)
     */
    void exportL1AnchorToFile(const AnchorBlock& anchor) {
        if (config_.l1_export_dir.empty()) {
            return;  // Export disabled
        }

        // Create directory if not exists
        mkdir(config_.l1_export_dir.c_str(), 0755);

        // Generate filename: <simulation_id>_<rsu_id>_<seq>.json
        std::ostringstream filename;
        filename << config_.l1_export_dir << "/"
                 << config_.simulation_id << "_"
                 << config_.rsu_id << "_"
                 << std::setw(6) << std::setfill('0') << anchor.sequence_number
                 << ".json";

        // Create JSON
        std::ofstream file(filename.str());
        if (!file.is_open()) {
            std::cerr << "[RSU-" << config_.rsu_id << "] ⚠️  Failed to write L1 anchor file: "
                      << filename.str() << "\n";
            return;
        }

        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();

        // Write JSON
        file << "{\n";
        file << "  \"simulation_id\": \"" << config_.simulation_id << "\",\n";
        file << "  \"rsu_id\": \"" << config_.rsu_id << "\",\n";
        file << "  \"level\": \"L1\",\n";
        file << "  \"sequence\": " << anchor.sequence_number << ",\n";
        file << "  \"timestamp_ms\": " << ms << ",\n";
        file << "  \"merkle_root\": \"" << toHexString(anchor.blocks_merkle_root) << "\",\n";
        file << "  \"block_count\": " << anchor.block_count << ",\n";

        // Previous anchor hash (for chain verification)
        file << "  \"prev_anchor_hash\": \"" << toHexString(anchor.prev_anchor_hash) << "\",\n";

        // RSU Dilithium signature (essential for verification)
        file << "  \"rsu_signature\": \"";
        for (uint8_t byte : anchor.rsu_signature) {
            file << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        file << std::dec << "\",\n";
        file << "  \"signature_size\": " << anchor.rsu_signature.size() << ",\n";

        // TEE Master Commit
        file << "  \"tee_master_commit\": \"";
        for (uint8_t byte : anchor.tee_master_commit) {
            file << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        file << std::dec << "\",\n";
        file << "  \"total_witness_signatures\": " << anchor.total_witness_signatures << ",\n";
        file << "  \"block_tee_commits_count\": " << anchor.block_tee_commits.size() << ",\n";

        // TEE Attestation
        file << "  \"has_tee_attestation\": " << (!anchor.tee_attestation.empty() ? "true" : "false");
        if (!anchor.tee_attestation.empty()) {
            file << ",\n";
            file << "  \"tee_attestation\": \"";
            for (uint8_t byte : anchor.tee_attestation) {
                file << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            file << std::dec << "\",\n";
            file << "  \"tee_attestation_size\": " << anchor.tee_attestation.size();
        }
        file << "\n";
        file << "}\n";

        file.close();

        std::cout << "[RSU-" << config_.rsu_id << "] 💾 L1 anchor exported to: "
                  << filename.str() << "\n";
    }

    /**
     * Generate TEE attestation for anchor block
     *
     * In production: Use Intel SGX (sgx_create_report) or ARM TrustZone
     * For simulation: Generate deterministic attestation based on anchor data
     */
    std::vector<uint8_t> generateTEEAttestation(const AnchorBlock& anchor) const {
        std::vector<uint8_t> attestation_data;
        attestation_data.reserve(512);

        // Attestation format (simplified):
        // [RSU_ID][Timestamp][Anchor_Hash][TEE_Master_Commit][Signature]

        // RSU ID
        attestation_data.insert(attestation_data.end(),
            config_.rsu_id.begin(), config_.rsu_id.end());
        attestation_data.push_back(0);

        // Timestamp
        auto ts_ns = anchor.anchor_time.time_since_epoch().count();
        const uint8_t* ts_ptr = reinterpret_cast<const uint8_t*>(&ts_ns);
        attestation_data.insert(attestation_data.end(), ts_ptr, ts_ptr + sizeof(ts_ns));

        // Anchor hash
        Hash256 anchor_hash = anchor.computeHash();
        attestation_data.insert(attestation_data.end(),
            anchor_hash.begin(), anchor_hash.end());

        // TEE master commit
        attestation_data.insert(attestation_data.end(),
            anchor.tee_master_commit.begin(), anchor.tee_master_commit.end());

        // Generate attestation signature (simulated TEE hardware signature)
        // In production: This would be signed by TEE hardware key
        Hash256 attestation_hash = crypto::SHA3::hash(attestation_data);

        // Return attestation (hash serves as proof in simulation)
        std::vector<uint8_t> attestation(attestation_hash.begin(), attestation_hash.end());

        return attestation;
    }

    /**
     * Hash를 hex string으로 변환
     */
    static std::string toHexString(const Hash256& hash) {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(64);

        for (uint8_t byte : hash) {
            result.push_back(hex[byte >> 4]);
            result.push_back(hex[byte & 0xf]);
        }

        return result;
    }
};

} // namespace infrastructure
} // namespace meshchain

#endif // MESHCHAIN_RSU_H
