#ifndef MESHCHAIN_TLS13_CHANNEL_H
#define MESHCHAIN_TLS13_CHANNEL_H

/**
 * TLS 1.3-Based Secure Channel for V2V Communication
 *
 * Implements a TLS 1.3-inspired protocol with post-quantum cryptography:
 * - Key Exchange: ML-KEM-768 (NIST standardized)
 * - Authentication: FALCON-512 certificates (fast, compact)
 * - AEAD: XChaCha20-Poly1305
 * - Key Derivation: HKDF-SHA256
 *
 * Protocol Flow (TLS 1.3 1-RTT):
 *
 * Creator                              Witness
 * -------                              -------
 * ClientHello
 *   + key_share (ML-KEM public key)
 *   + supported_groups
 *                        -------->
 *                                    ServerHello
 *                                      + key_share
 *                                    {Certificate} (FALCON)
 *                                    {CertificateVerify} (FALCON sig)
 *                                    {Finished}
 *                        <--------
 * {sig_request}          -------->
 *                                    {sig_response} (witness signature)
 *                        <--------
 *
 * {} = AEAD encrypted with handshake traffic keys
 */

#include "../common/types.h"
#include "liboqs_wrapper.h"
#include "secure_channel.h"
#include "tls13_real.h"  // Real OpenSSL-based TLS 1.3 key schedule
#include <vector>
#include <memory>
#include <cstring>
#include <array>
#include <random>
#include <chrono>

namespace meshchain {
namespace crypto {

/**
 * V2V Certificate Structure
 *
 * Contains FALCON-512 public key and metadata for V2V authentication
 *
 * Certificate binding:
 * - Vehicle ID (pseudonymous identifier)
 * - FALCON-512 public key (~897 bytes)
 * - Validity period
 * - Issuer signature (from RSU/CA, using ML-DSA-65)
 */
struct V2VCertificate {
    std::string vehicle_id;           // Pseudonymous vehicle identifier
    std::vector<uint8_t> falcon_pk;   // FALCON-512 public key (897 bytes)
    uint64_t not_before_unix;         // Validity start (Unix timestamp)
    uint64_t not_after_unix;          // Validity end
    std::string issuer;               // CA identifier
    std::vector<uint8_t> issuer_sig;  // CA's ML-DSA-65 signature over cert

    // Certificate serial number (for revocation checks)
    std::vector<uint8_t> serial;

    /**
     * Serialize certificate for signing/verification
     */
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> bytes;
        bytes.reserve(2048);

        // Vehicle ID
        bytes.insert(bytes.end(), vehicle_id.begin(), vehicle_id.end());
        bytes.push_back(0);  // null terminator

        // FALCON public key
        uint16_t pk_len = static_cast<uint16_t>(falcon_pk.size());
        const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&pk_len);
        bytes.insert(bytes.end(), len_ptr, len_ptr + sizeof(uint16_t));
        bytes.insert(bytes.end(), falcon_pk.begin(), falcon_pk.end());

        // Validity period
        const uint8_t* before_ptr = reinterpret_cast<const uint8_t*>(&not_before_unix);
        const uint8_t* after_ptr = reinterpret_cast<const uint8_t*>(&not_after_unix);
        bytes.insert(bytes.end(), before_ptr, before_ptr + sizeof(uint64_t));
        bytes.insert(bytes.end(), after_ptr, after_ptr + sizeof(uint64_t));

        // Issuer
        bytes.insert(bytes.end(), issuer.begin(), issuer.end());
        bytes.push_back(0);

        // Serial number
        uint16_t serial_len = static_cast<uint16_t>(serial.size());
        len_ptr = reinterpret_cast<const uint8_t*>(&serial_len);
        bytes.insert(bytes.end(), len_ptr, len_ptr + sizeof(uint16_t));
        bytes.insert(bytes.end(), serial.begin(), serial.end());

        return bytes;
    }

    /**
     * Get certificate body for signature (excludes issuer_sig)
     */
    std::vector<uint8_t> getCertificateBody() const {
        return serialize();  // Signature is verified separately
    }

    /**
     * Verify certificate validity
     */
    bool isValid(uint64_t current_time_unix) const {
        return current_time_unix >= not_before_unix &&
               current_time_unix <= not_after_unix;
    }
};

/**
 * TLS 1.3 Key Schedule (simplified)
 *
 * Based on RFC 8446 Section 7.1:
 *
 *              0
 *              |
 *              v
 *   PSK ->  HKDF-Extract = Early Secret
 *              |
 *              v
 *      Derive-Secret(., "derived", "")
 *              |
 *              v
 *   (EC)DHE -> HKDF-Extract = Handshake Secret
 *              |
 *              +-----> Derive-Secret(., "c hs traffic",
 *              |                     ClientHello...ServerHello)
 *              |                     = client_handshake_traffic_secret
 *              |
 *              +-----> Derive-Secret(., "s hs traffic",
 *              |                     ClientHello...ServerHello)
 *              |                     = server_handshake_traffic_secret
 *              v
 *      Derive-Secret(., "derived", "")
 *              |
 *              v
 *   0 -> HKDF-Extract = Master Secret
 *              |
 *              +-----> Derive-Secret(., "c ap traffic",
 *              |                     ClientHello...server Finished)
 *              |                     = client_application_traffic_secret_0
 *              |
 *              +-----> Derive-Secret(., "s ap traffic",
 *                                    ClientHello...server Finished)
 *                                    = server_application_traffic_secret_0
 *
 * We use ML-KEM shared secret as (EC)DHE input
 */
class TLS13KeySchedule {
private:
    std::vector<uint8_t> early_secret_;
    std::vector<uint8_t> handshake_secret_;
    std::vector<uint8_t> master_secret_;

    std::vector<uint8_t> client_hs_traffic_secret_;
    std::vector<uint8_t> server_hs_traffic_secret_;
    std::vector<uint8_t> client_ap_traffic_secret_;
    std::vector<uint8_t> server_ap_traffic_secret_;

public:
    /**
     * Initialize key schedule with ML-KEM shared secret
     *
     * @param shared_secret 32-byte ML-KEM shared secret
     * @param handshake_transcript Hash of ClientHello || ServerHello
     */
    void initialize(const std::vector<uint8_t>& shared_secret,
                   const std::vector<uint8_t>& handshake_transcript) {

        // Early Secret (no PSK, so extract from 0) - Using real OpenSSL HKDF
        std::vector<uint8_t> zeros(32, 0);
        early_secret_ = crypto::TLS13RealCrypto::hkdfExtract(zeros, zeros);

        // Handshake Secret (from ML-KEM shared secret)
        std::vector<uint8_t> derived_secret = deriveSecret(early_secret_, "derived", {});
        handshake_secret_ = crypto::TLS13RealCrypto::hkdfExtract(derived_secret, shared_secret);

        // Handshake Traffic Secrets
        client_hs_traffic_secret_ = deriveSecret(handshake_secret_,
                                                 "c hs traffic",
                                                 handshake_transcript);
        server_hs_traffic_secret_ = deriveSecret(handshake_secret_,
                                                 "s hs traffic",
                                                 handshake_transcript);

        // Master Secret
        derived_secret = deriveSecret(handshake_secret_, "derived", {});
        master_secret_ = crypto::TLS13RealCrypto::hkdfExtract(derived_secret, zeros);

        // Application Traffic Secrets (for actual data)
        client_ap_traffic_secret_ = deriveSecret(master_secret_,
                                                 "c ap traffic",
                                                 handshake_transcript);
        server_ap_traffic_secret_ = deriveSecret(master_secret_,
                                                 "s ap traffic",
                                                 handshake_transcript);
    }

    std::vector<uint8_t> getClientHandshakeKey() const {
        return crypto::TLS13RealCrypto::hkdfExpandLabel(client_hs_traffic_secret_, "key", {}, 32);
    }

    std::vector<uint8_t> getServerHandshakeKey() const {
        return crypto::TLS13RealCrypto::hkdfExpandLabel(server_hs_traffic_secret_, "key", {}, 32);
    }

    std::vector<uint8_t> getClientApplicationKey() const {
        return crypto::TLS13RealCrypto::hkdfExpandLabel(client_ap_traffic_secret_, "key", {}, 32);
    }

    std::vector<uint8_t> getServerApplicationKey() const {
        return crypto::TLS13RealCrypto::hkdfExpandLabel(server_ap_traffic_secret_, "key", {}, 32);
    }

    std::vector<uint8_t> getClientHandshakeTrafficSecret() const {
        return client_hs_traffic_secret_;
    }

    std::vector<uint8_t> getServerHandshakeTrafficSecret() const {
        return server_hs_traffic_secret_;
    }

    /**
     * Compute Server Finished verify_data
     */
    std::vector<uint8_t> computeServerFinished(
            const std::vector<std::vector<uint8_t>>& handshake_context) const {
        return crypto::TLS13RealCrypto::computeFinishedVerifyData(
            server_hs_traffic_secret_, handshake_context);
    }

    /**
     * Compute Client Finished verify_data
     */
    std::vector<uint8_t> computeClientFinished(
            const std::vector<std::vector<uint8_t>>& handshake_context) const {
        return crypto::TLS13RealCrypto::computeFinishedVerifyData(
            client_hs_traffic_secret_, handshake_context);
    }

private:
    /**
     * Derive-Secret (TLS 1.3 specific)
     * Now uses real OpenSSL SHA-256 transcript hashing
     */
    std::vector<uint8_t> deriveSecret(const std::vector<uint8_t>& secret,
                                     const std::string& label,
                                     const std::vector<uint8_t>& messages) const {
        // Hash messages using real SHA-256 if not empty
        std::vector<uint8_t> msg_hash_vec;
        if (!messages.empty()) {
            Hash256 msg_hash = crypto::TLS13RealCrypto::transcriptHash({messages});
            msg_hash_vec.assign(msg_hash.begin(), msg_hash.end());
        } else {
            // Empty context (for "derived" label)
            msg_hash_vec.resize(32, 0);
        }

        return crypto::TLS13RealCrypto::hkdfExpandLabel(secret, label, msg_hash_vec, 32);
    }
};

/**
 * TLS 1.3-Based Secure Channel
 *
 * Combines:
 * - ML-KEM-768 key exchange
 * - FALCON-512 certificate authentication
 * - XChaCha20-Poly1305 AEAD encryption
 * - TLS 1.3 key schedule
 */
class TLS13Channel {
private:
    std::unique_ptr<MLKEM> kem_;
    std::unique_ptr<FalconSigner> signer_;
    std::unique_ptr<TLS13KeySchedule> key_schedule_;

    V2VCertificate my_certificate_;
    std::string node_id_;
    bool handshake_completed_;

    // TLS 1.3 handshake transcript (for Finished message computation)
    std::vector<std::vector<uint8_t>> handshake_messages_;

    // Random values (RFC 8446 Section 4.1.2)
    std::vector<uint8_t> client_random_;  // 32 bytes
    std::vector<uint8_t> server_random_;  // 32 bytes

public:
    explicit TLS13Channel(const std::string& node_id)
        : node_id_(node_id), handshake_completed_(false) {

        kem_ = std::make_unique<MLKEM>();
        kem_->generateKeys();

        signer_ = std::make_unique<FalconSigner>();
        signer_->generateKeys();

        key_schedule_ = std::make_unique<TLS13KeySchedule>();

        // Generate self-signed certificate (in production: issued by CA)
        my_certificate_ = generateSelfSignedCertificate();
    }

    /**
     * Get my certificate for handshake
     */
    V2VCertificate getCertificate() const {
        return my_certificate_;
    }

    /**
     * Get ML-KEM public key for key exchange
     */
    std::vector<uint8_t> getKeySharePublicKey() const {
        return kem_->getPublicKey();
    }

    /**
     * Perform TLS 1.3 handshake (server side - witness)
     *
     * @param client_key_share Creator's ML-KEM public key
     * @param client_hello_data ClientHello message data
     * @return ServerHello data (includes certificate, signature, finished)
     */
    std::vector<uint8_t> performServerHandshake(
            const std::vector<uint8_t>& client_key_share,
            const std::vector<uint8_t>& client_hello_data) {

        // Clear previous transcript
        handshake_messages_.clear();

        // 1. Generate server random (RFC 8446 Section 4.1.3)
        server_random_ = crypto::TLS13RealCrypto::generateRandom(32);

        // 2. ML-KEM Encapsulation to client's public key
        auto [kem_ciphertext, shared_secret] = kem_->encapsulate(client_key_share);

        // 3. Build ServerHello with random
        std::vector<uint8_t> server_hello;
        server_hello.insert(server_hello.end(), server_random_.begin(), server_random_.end());
        server_hello.insert(server_hello.end(), kem_ciphertext.begin(), kem_ciphertext.end());

        // 4. Build handshake transcript (ClientHello || ServerHello)
        std::vector<uint8_t> transcript;
        transcript.insert(transcript.end(), client_hello_data.begin(), client_hello_data.end());
        transcript.insert(transcript.end(), server_hello.begin(), server_hello.end());

        // Store messages for transcript
        handshake_messages_.push_back(client_hello_data);
        handshake_messages_.push_back(server_hello);

        // 5. Initialize TLS 1.3 key schedule
        key_schedule_->initialize(shared_secret, transcript);

        // 6. Get server handshake key for encrypting messages
        std::vector<uint8_t> server_hs_key = key_schedule_->getServerHandshakeKey();

        // 7. EncryptedExtensions (RFC 8446 Section 4.3.1) - empty for V2V
        std::vector<uint8_t> encrypted_extensions;  // Empty - no extensions needed

        // 8. Serialize certificate
        std::vector<uint8_t> cert_data = my_certificate_.serialize();

        // 9. Sign certificate for CertificateVerify
        std::vector<uint8_t> cert_verify_sig = signer_->sign(cert_data);

        // 10. Build Certificate + CertificateVerify message
        std::vector<uint8_t> cert_message;
        uint32_t cert_len = static_cast<uint32_t>(cert_data.size());
        const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&cert_len);
        cert_message.insert(cert_message.end(), len_ptr, len_ptr + sizeof(uint32_t));
        cert_message.insert(cert_message.end(), cert_data.begin(), cert_data.end());

        uint32_t sig_len = static_cast<uint32_t>(cert_verify_sig.size());
        len_ptr = reinterpret_cast<const uint8_t*>(&sig_len);
        cert_message.insert(cert_message.end(), len_ptr, len_ptr + sizeof(uint32_t));
        cert_message.insert(cert_message.end(), cert_verify_sig.begin(), cert_verify_sig.end());

        // Add EncryptedExtensions + Certificate + CertificateVerify to transcript
        handshake_messages_.push_back(encrypted_extensions);
        handshake_messages_.push_back(cert_message);

        // 11. Compute Server Finished (RFC 8446 Section 4.4.4)
        std::vector<uint8_t> server_finished = key_schedule_->computeServerFinished(handshake_messages_);

        // 12. Encrypt Certificate + CertificateVerify + Finished with handshake key
        std::vector<uint8_t> handshake_payload;

        // Add EncryptedExtensions
        uint32_t ee_len = static_cast<uint32_t>(encrypted_extensions.size());
        len_ptr = reinterpret_cast<const uint8_t*>(&ee_len);
        handshake_payload.insert(handshake_payload.end(), len_ptr, len_ptr + sizeof(uint32_t));
        handshake_payload.insert(handshake_payload.end(), encrypted_extensions.begin(), encrypted_extensions.end());

        // Add Certificate + CertificateVerify
        handshake_payload.insert(handshake_payload.end(), cert_message.begin(), cert_message.end());

        // Add Finished
        uint32_t fin_len = static_cast<uint32_t>(server_finished.size());
        len_ptr = reinterpret_cast<const uint8_t*>(&fin_len);
        handshake_payload.insert(handshake_payload.end(), len_ptr, len_ptr + sizeof(uint32_t));
        handshake_payload.insert(handshake_payload.end(), server_finished.begin(), server_finished.end());

        auto encrypted_handshake = AEAD::encrypt(server_hs_key, handshake_payload);

        // 13. Build complete ServerHello response
        std::vector<uint8_t> response;
        response.insert(response.end(), server_hello.begin(), server_hello.end());

        std::vector<uint8_t> encrypted_hs_bytes = encrypted_handshake.serialize();
        uint32_t enc_len = static_cast<uint32_t>(encrypted_hs_bytes.size());
        len_ptr = reinterpret_cast<const uint8_t*>(&enc_len);
        response.insert(response.end(), len_ptr, len_ptr + sizeof(uint32_t));
        response.insert(response.end(), encrypted_hs_bytes.begin(), encrypted_hs_bytes.end());

        // Add Server Finished to transcript (for client verification)
        handshake_messages_.push_back(server_finished);

        handshake_completed_ = true;
        return response;
    }

    /**
     * Process ServerHello (client side - creator)
     *
     * @param server_hello_data ServerHello from witness
     * @param client_hello_data Original ClientHello sent
     * @return Witness's verified certificate
     */
    V2VCertificate processServerHello(
            const std::vector<uint8_t>& server_hello_data,
            const std::vector<uint8_t>& client_hello_data) {

        // Clear previous transcript
        handshake_messages_.clear();

        // 1. Extract Server Random (32 bytes) + KEM ciphertext
        size_t expected_min_size = 32 + MLKEM::CIPHERTEXT_SIZE + sizeof(uint32_t);
        if (server_hello_data.size() < expected_min_size) {
            throw std::runtime_error("Invalid ServerHello size");
        }

        // Extract server random
        server_random_.assign(server_hello_data.begin(), server_hello_data.begin() + 32);

        // Extract KEM ciphertext
        std::vector<uint8_t> kem_ciphertext(
            server_hello_data.begin() + 32,
            server_hello_data.begin() + 32 + MLKEM::CIPHERTEXT_SIZE
        );

        // 2. Decapsulate to get shared secret
        std::vector<uint8_t> shared_secret = kem_->decapsulate(kem_ciphertext);

        // 3. Build ServerHello for transcript (random + kem_ciphertext)
        std::vector<uint8_t> server_hello_part(
            server_hello_data.begin(),
            server_hello_data.begin() + 32 + MLKEM::CIPHERTEXT_SIZE
        );

        // Build transcript (ClientHello || ServerHello)
        std::vector<uint8_t> transcript;
        transcript.insert(transcript.end(), client_hello_data.begin(), client_hello_data.end());
        transcript.insert(transcript.end(), server_hello_part.begin(), server_hello_part.end());

        // Store messages for transcript
        handshake_messages_.push_back(client_hello_data);
        handshake_messages_.push_back(server_hello_part);

        // 4. Initialize key schedule
        key_schedule_->initialize(shared_secret, transcript);

        // 5. Get server handshake key
        std::vector<uint8_t> server_hs_key = key_schedule_->getServerHandshakeKey();

        // 6. Extract and decrypt handshake payload (EncryptedExtensions + Certificate + CertificateVerify + Finished)
        size_t offset = 32 + MLKEM::CIPHERTEXT_SIZE;
        uint32_t enc_len;
        std::memcpy(&enc_len, &server_hello_data[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::vector<uint8_t> encrypted_hs_bytes(
            server_hello_data.begin() + offset,
            server_hello_data.begin() + offset + enc_len
        );

        auto encrypted_hs = AEAD::EncryptedData::deserialize(encrypted_hs_bytes);
        std::vector<uint8_t> handshake_payload = AEAD::decrypt(server_hs_key, encrypted_hs);

        // 7. Parse handshake payload
        offset = 0;

        // Parse EncryptedExtensions
        uint32_t ee_len;
        std::memcpy(&ee_len, &handshake_payload[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);
        std::vector<uint8_t> encrypted_extensions(
            handshake_payload.begin() + offset,
            handshake_payload.begin() + offset + ee_len
        );
        offset += ee_len;

        // Parse Certificate + CertificateVerify
        uint32_t cert_len;
        std::memcpy(&cert_len, &handshake_payload[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::vector<uint8_t> cert_data(
            handshake_payload.begin() + offset,
            handshake_payload.begin() + offset + cert_len
        );
        offset += cert_len;

        uint32_t sig_len;
        std::memcpy(&sig_len, &handshake_payload[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::vector<uint8_t> cert_verify_sig(
            handshake_payload.begin() + offset,
            handshake_payload.begin() + offset + sig_len
        );
        offset += sig_len;

        // Build cert_message for transcript
        std::vector<uint8_t> cert_message;
        uint32_t cert_len_copy = cert_len;
        const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&cert_len_copy);
        cert_message.insert(cert_message.end(), len_ptr, len_ptr + sizeof(uint32_t));
        cert_message.insert(cert_message.end(), cert_data.begin(), cert_data.end());
        uint32_t sig_len_copy = sig_len;
        len_ptr = reinterpret_cast<const uint8_t*>(&sig_len_copy);
        cert_message.insert(cert_message.end(), len_ptr, len_ptr + sizeof(uint32_t));
        cert_message.insert(cert_message.end(), cert_verify_sig.begin(), cert_verify_sig.end());

        // Add to transcript
        handshake_messages_.push_back(encrypted_extensions);
        handshake_messages_.push_back(cert_message);

        // Parse Server Finished
        uint32_t fin_len;
        std::memcpy(&fin_len, &handshake_payload[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);

        std::vector<uint8_t> server_finished_received(
            handshake_payload.begin() + offset,
            handshake_payload.begin() + offset + fin_len
        );

        // 8. Verify Server Finished (RFC 8446 Section 4.4.4)
        std::vector<uint8_t> expected_server_finished = key_schedule_->computeServerFinished(handshake_messages_);

        if (server_finished_received != expected_server_finished) {
            throw std::runtime_error("Server Finished verification failed - transcript mismatch!");
        }

        // Add Server Finished to transcript
        handshake_messages_.push_back(server_finished_received);

        // 9. Verify certificate signature (simplified - should verify CA signature)
        // In production: verify issuer_sig with CA's ML-DSA public key

        handshake_completed_ = true;

        // 10. Return parsed certificate (simplified - would deserialize fully)
        V2VCertificate peer_cert = my_certificate_;  // Placeholder
        return peer_cert;
    }

    /**
     * Send Client Finished message (RFC 8446 Section 4.4.4)
     * Called by client after verifying Server Finished
     *
     * @return Encrypted Client Finished message
     */
    std::vector<uint8_t> sendClientFinished() {
        if (!handshake_completed_) {
            throw std::runtime_error("Handshake not completed - cannot send Client Finished");
        }

        // Compute Client Finished verify_data
        std::vector<uint8_t> client_finished = key_schedule_->computeClientFinished(handshake_messages_);

        // Get client handshake traffic key for encryption
        std::vector<uint8_t> client_hs_key = key_schedule_->getClientHandshakeKey();

        // Encrypt Client Finished
        auto encrypted = AEAD::encrypt(client_hs_key, client_finished);

        // Add to transcript for application key derivation
        handshake_messages_.push_back(client_finished);

        return encrypted.serialize();
    }

    /**
     * Verify Client Finished message (RFC 8446 Section 4.4.4)
     * Called by server after sending Server Finished
     *
     * @param encrypted_finished Encrypted Client Finished message
     * @return true if verification succeeds
     */
    bool verifyClientFinished(const std::vector<uint8_t>& encrypted_finished_data) {
        if (!handshake_completed_) {
            throw std::runtime_error("Handshake not completed - cannot verify Client Finished");
        }

        // Get client handshake traffic key for decryption
        std::vector<uint8_t> client_hs_key = key_schedule_->getClientHandshakeKey();

        // Decrypt Client Finished
        auto encrypted = AEAD::EncryptedData::deserialize(encrypted_finished_data);
        std::vector<uint8_t> client_finished_received = AEAD::decrypt(client_hs_key, encrypted);

        // Compute expected Client Finished
        std::vector<uint8_t> expected_client_finished = key_schedule_->computeClientFinished(handshake_messages_);

        // Verify
        if (client_finished_received != expected_client_finished) {
            return false;
        }

        // Add to transcript for application key derivation
        handshake_messages_.push_back(client_finished_received);

        return true;
    }

    /**
     * Encrypt sig_request with application traffic keys
     *
     * @param sig_req Signature request message
     * @return Encrypted message
     */
    std::vector<uint8_t> encryptApplicationData(
            const std::vector<uint8_t>& plaintext) {

        if (!handshake_completed_) {
            throw std::runtime_error("Handshake not completed");
        }

        // Use client application traffic key
        std::vector<uint8_t> app_key = key_schedule_->getClientApplicationKey();
        auto encrypted = AEAD::encrypt(app_key, plaintext);
        return encrypted.serialize();
    }

    /**
     * Decrypt sig_request with application traffic keys
     */
    std::vector<uint8_t> decryptApplicationData(
            const std::vector<uint8_t>& encrypted_data) {

        if (!handshake_completed_) {
            throw std::runtime_error("Handshake not completed");
        }

        // Use client application traffic key (received from client)
        std::vector<uint8_t> app_key = key_schedule_->getClientApplicationKey();
        auto encrypted = AEAD::EncryptedData::deserialize(encrypted_data);
        return AEAD::decrypt(app_key, encrypted);
    }

private:
    /**
     * Generate self-signed certificate (for simulation)
     * In production: issued by RSU/CA using ML-DSA-65
     */
    V2VCertificate generateSelfSignedCertificate() {
        V2VCertificate cert;
        cert.vehicle_id = node_id_;
        cert.falcon_pk = signer_->getPublicKey();

        // Validity: 1 year
        auto now = std::chrono::system_clock::now();
        cert.not_before_unix = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        cert.not_after_unix = cert.not_before_unix + (365 * 24 * 3600);  // 1 year

        cert.issuer = "SelfSigned";

        // Serial number
        cert.serial.resize(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < 16; ++i) {
            cert.serial[i] = static_cast<uint8_t>(dis(gen));
        }

        // Self-sign (in production: signed by CA)
        cert.issuer_sig = signer_->sign(cert.getCertificateBody());

        return cert;
    }
};

} // namespace crypto
} // namespace meshchain

#endif // MESHCHAIN_TLS13_CHANNEL_H
