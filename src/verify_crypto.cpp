/**
 * Crypto Implementation Verification
 *
 * Verifies that real cryptographic libraries are being used:
 * - liboqs for ML-KEM, FALCON, ML-DSA
 * - libsodium for XChaCha20-Poly1305 AEAD
 * - NOT simulation mode
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

// Include headers based on compile flags
#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

#ifdef USE_LIBSODIUM
#include <sodium.h>
#endif

// Check compile-time flags
void checkCompileFlags() {
    std::cout << "\n=== Compile-Time Flags ===\n";

#ifdef USE_LIBOQS
    std::cout << "✅ USE_LIBOQS: DEFINED\n";
    std::cout << "   → Using real liboqs for PQC algorithms\n";
#else
    std::cout << "❌ USE_LIBOQS: NOT DEFINED\n";
    std::cout << "   → Using SIMULATION MODE for PQC\n";
#endif

#ifdef USE_LIBSODIUM
    std::cout << "✅ USE_LIBSODIUM: DEFINED\n";
    std::cout << "   → Using real libsodium for AEAD\n";
#else
    std::cout << "❌ USE_LIBSODIUM: NOT DEFINED\n";
    std::cout << "   → Using SIMULATION MODE for AEAD\n";
#endif

#ifdef USE_TRACI
    std::cout << "✅ USE_TRACI: DEFINED\n";
    std::cout << "   → Using real SUMO/TraCI\n";
#else
    std::cout << "⚠️  USE_TRACI: NOT DEFINED\n";
    std::cout << "   → Using mock vehicle data\n";
#endif
}

// Check runtime library availability
void checkRuntimeLibraries() {
    std::cout << "\n=== Runtime Library Check ===\n";

#ifdef USE_LIBOQS
    // Check liboqs version
    std::cout << "liboqs version: " << OQS_VERSION_TEXT << "\n";

    // Check ML-KEM (Kyber) availability
    if (OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768)) {
        std::cout << "✅ ML-KEM-768 (Kyber768): AVAILABLE\n";
    } else {
        std::cout << "❌ ML-KEM-768 (Kyber768): NOT AVAILABLE\n";
    }

    // Check FALCON availability
    if (OQS_SIG_alg_is_enabled(OQS_SIG_alg_falcon_512)) {
        std::cout << "✅ FALCON-512: AVAILABLE\n";
    } else {
        std::cout << "❌ FALCON-512: NOT AVAILABLE\n";
    }

    // Check ML-DSA (Dilithium) availability
    #if defined(OQS_SIG_alg_dilithium_3)
    if (OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        std::cout << "✅ ML-DSA-65 (Dilithium3): AVAILABLE\n";
    } else {
        std::cout << "❌ ML-DSA-65 (Dilithium3): NOT AVAILABLE\n";
    }
    #elif defined(OQS_SIG_alg_ml_dsa_65)
    if (OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_65)) {
        std::cout << "✅ ML-DSA-65: AVAILABLE\n";
    } else {
        std::cout << "❌ ML-DSA-65: NOT AVAILABLE\n";
    }
    #else
    std::cout << "⚠️  ML-DSA-65: Using fallback name\n";
    #endif

#else
    std::cout << "⚠️  liboqs not compiled in - using simulation mode\n";
#endif

#ifdef USE_LIBSODIUM
    if (sodium_init() >= 0) {
        std::cout << "✅ libsodium: INITIALIZED\n";
        std::cout << "   Version: " << sodium_version_string() << "\n";
        std::cout << "   → XChaCha20-Poly1305 AEAD available\n";
    } else {
        std::cout << "❌ libsodium: INITIALIZATION FAILED\n";
    }
#else
    std::cout << "⚠️  libsodium not compiled in - using simulation mode\n";
#endif
}

// Test actual ML-KEM key exchange
void testMLKEM() {
    std::cout << "\n=== ML-KEM-768 Key Exchange Test ===\n";

#ifdef USE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == nullptr) {
        std::cout << "❌ Failed to initialize ML-KEM-768\n";
        return;
    }

    std::cout << "Algorithm: " << kem->method_name << "\n";
    std::cout << "  Public key size: " << kem->length_public_key << " bytes\n";
    std::cout << "  Secret key size: " << kem->length_secret_key << " bytes\n";
    std::cout << "  Ciphertext size: " << kem->length_ciphertext << " bytes\n";
    std::cout << "  Shared secret size: " << kem->length_shared_secret << " bytes\n";

    // Generate keypair
    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cout << "❌ Key generation failed\n";
        OQS_KEM_free(kem);
        return;
    }

    std::cout << "✅ Keypair generated\n";

    // Encapsulation
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_enc(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_enc.data(), public_key.data()) != OQS_SUCCESS) {
        std::cout << "❌ Encapsulation failed\n";
        OQS_KEM_free(kem);
        return;
    }

    std::cout << "✅ Encapsulation successful\n";

    // Decapsulation
    std::vector<uint8_t> shared_secret_dec(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, shared_secret_dec.data(), ciphertext.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cout << "❌ Decapsulation failed\n";
        OQS_KEM_free(kem);
        return;
    }

    std::cout << "✅ Decapsulation successful\n";

    // Verify shared secrets match
    if (std::memcmp(shared_secret_enc.data(), shared_secret_dec.data(), kem->length_shared_secret) == 0) {
        std::cout << "✅ Shared secrets MATCH - ML-KEM working correctly!\n";

        // Print first 16 bytes of shared secret
        std::cout << "   Shared secret (first 16 bytes): ";
        for (size_t i = 0; i < 16 && i < kem->length_shared_secret; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(shared_secret_enc[i]);
        }
        std::cout << std::dec << "\n";
    } else {
        std::cout << "❌ Shared secrets DO NOT MATCH - ML-KEM failure!\n";
    }

    OQS_KEM_free(kem);
#else
    std::cout << "⚠️  liboqs not available - cannot test real ML-KEM\n";
    std::cout << "   Running in SIMULATION MODE\n";
#endif
}

// Test actual FALCON-512 signature
void testFALCON() {
    std::cout << "\n=== FALCON-512 Signature Test ===\n";

#ifdef USE_LIBOQS
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == nullptr) {
        std::cout << "❌ Failed to initialize FALCON-512\n";
        return;
    }

    std::cout << "Algorithm: " << sig->method_name << "\n";
    std::cout << "  Public key size: " << sig->length_public_key << " bytes\n";
    std::cout << "  Secret key size: " << sig->length_secret_key << " bytes\n";
    std::cout << "  Signature size: " << sig->length_signature << " bytes\n";

    // Generate keypair
    std::vector<uint8_t> public_key_vec(sig->length_public_key);
    std::vector<uint8_t> secret_key_vec(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key_vec.data(), secret_key_vec.data()) != OQS_SUCCESS) {
        std::cout << "❌ Key generation failed\n";
        OQS_SIG_free(sig);
        return;
    }

    std::cout << "✅ Keypair generated\n";

    // Sign a message
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'F', 'A', 'L', 'C', 'O', 'N'};
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;

    if (OQS_SIG_sign(sig, signature.data(), &sig_len, message.data(), message.size(), secret_key_vec.data()) != OQS_SUCCESS) {
        std::cout << "❌ Signing failed\n";
        OQS_SIG_free(sig);
        return;
    }

    std::cout << "✅ Message signed (signature: " << sig_len << " bytes)\n";

    // Verify signature
    if (OQS_SIG_verify(sig, message.data(), message.size(), signature.data(), sig_len, public_key_vec.data()) == OQS_SUCCESS) {
        std::cout << "✅ Signature VERIFIED - FALCON-512 working correctly!\n";

        // Print first 16 bytes of signature
        std::cout << "   Signature (first 16 bytes): ";
        for (size_t i = 0; i < 16 && i < sig_len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(signature[i]);
        }
        std::cout << std::dec << "\n";
    } else {
        std::cout << "❌ Signature verification FAILED - FALCON-512 failure!\n";
    }

    // Test with wrong message (should fail)
    std::vector<uint8_t> wrong_message = {'W', 'r', 'o', 'n', 'g'};
    if (OQS_SIG_verify(sig, wrong_message.data(), wrong_message.size(), signature.data(), sig_len, public_key_vec.data()) == OQS_SUCCESS) {
        std::cout << "❌ ERROR: Wrong message verified - security breach!\n";
    } else {
        std::cout << "✅ Wrong message correctly rejected\n";
    }

    OQS_SIG_free(sig);
#else
    std::cout << "⚠️  liboqs not available - cannot test real FALCON\n";
    std::cout << "   Running in SIMULATION MODE\n";
#endif
}

// Test actual XChaCha20-Poly1305 AEAD
void testAEAD() {
    std::cout << "\n=== XChaCha20-Poly1305 AEAD Test ===\n";

#ifdef USE_LIBSODIUM
    if (sodium_init() < 0) {
        std::cout << "❌ libsodium initialization failed\n";
        return;
    }

    std::cout << "Algorithm: XChaCha20-Poly1305-IETF\n";
    std::cout << "  Key size: " << crypto_aead_xchacha20poly1305_ietf_KEYBYTES << " bytes\n";
    std::cout << "  Nonce size: " << crypto_aead_xchacha20poly1305_ietf_NPUBBYTES << " bytes\n";
    std::cout << "  Tag size: " << crypto_aead_xchacha20poly1305_ietf_ABYTES << " bytes\n";

    // Generate random key
    std::vector<uint8_t> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto_aead_xchacha20poly1305_ietf_keygen(key.data());

    std::cout << "✅ Key generated\n";

    // Plaintext
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'A', 'E', 'A', 'D', '!', '!', '!'};

    // Nonce
    std::vector<uint8_t> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // Additional data
    std::vector<uint8_t> ad = {'m', 'e', 't', 'a', 'd', 'a', 't', 'a'};

    // Ciphertext buffer
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    // Encrypt
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            ad.data(), ad.size(),
            nullptr,  // nsec (not used)
            nonce.data(), key.data()) != 0) {
        std::cout << "❌ Encryption failed\n";
        return;
    }

    std::cout << "✅ Encryption successful (" << ciphertext_len << " bytes)\n";
    std::cout << "   Plaintext: " << plaintext.size() << " bytes\n";
    std::cout << "   Ciphertext: " << ciphertext_len << " bytes\n";
    std::cout << "   Overhead: " << (ciphertext_len - plaintext.size()) << " bytes (tag)\n";

    // Decrypt
    std::vector<uint8_t> decrypted(plaintext.size());
    unsigned long long decrypted_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,  // nsec (not used)
            ciphertext.data(), ciphertext_len,
            ad.data(), ad.size(),
            nonce.data(), key.data()) != 0) {
        std::cout << "❌ Decryption failed\n";
        return;
    }

    std::cout << "✅ Decryption successful\n";

    // Verify
    if (decrypted_len == plaintext.size() &&
        std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0) {
        std::cout << "✅ Plaintext MATCHES - XChaCha20-Poly1305 working correctly!\n";

        // Print ciphertext (first 16 bytes)
        std::cout << "   Ciphertext (first 16 bytes): ";
        for (size_t i = 0; i < 16 && i < ciphertext_len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(ciphertext[i]);
        }
        std::cout << std::dec << "\n";
    } else {
        std::cout << "❌ Plaintext DOES NOT MATCH - AEAD failure!\n";
    }

    // Test tampering detection
    ciphertext[0] ^= 0x01;  // Flip one bit
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            ad.data(), ad.size(),
            nonce.data(), key.data()) != 0) {
        std::cout << "✅ Tampered ciphertext correctly rejected\n";
    } else {
        std::cout << "❌ ERROR: Tampered ciphertext accepted - security breach!\n";
    }

#else
    std::cout << "⚠️  libsodium not available - cannot test real AEAD\n";
    std::cout << "   Running in SIMULATION MODE\n";
    std::cout << "   Using simplified XOR-based encryption\n";
#endif
}

int main() {
    std::cout << "==================================================\n";
    std::cout << "  Cryptographic Implementation Verification\n";
    std::cout << "  Real Crypto vs Simulation Mode Check\n";
    std::cout << "==================================================\n";

    checkCompileFlags();
    checkRuntimeLibraries();

    std::cout << "\n==================================================\n";
    std::cout << "  Algorithm-Specific Tests\n";
    std::cout << "==================================================\n";

    testMLKEM();
    testFALCON();
    testAEAD();

    std::cout << "\n==================================================\n";
    std::cout << "  Verification Complete\n";
    std::cout << "==================================================\n";

#if defined(USE_LIBOQS) && defined(USE_LIBSODIUM)
    std::cout << "\n✅ ALL REAL CRYPTO LIBRARIES ENABLED\n";
    std::cout << "   → ML-KEM-768, FALCON-512, XChaCha20-Poly1305\n";
    std::cout << "   → Production-ready cryptography\n";
#elif defined(USE_LIBOQS)
    std::cout << "\n⚠️  PARTIAL CRYPTO ENABLED\n";
    std::cout << "   ✅ liboqs: ML-KEM, FALCON, ML-DSA\n";
    std::cout << "   ❌ libsodium: Using simulation AEAD\n";
    std::cout << "   → Install libsodium for production AEAD\n";
#elif defined(USE_LIBSODIUM)
    std::cout << "\n⚠️  PARTIAL CRYPTO ENABLED\n";
    std::cout << "   ❌ liboqs: Using simulation PQC\n";
    std::cout << "   ✅ libsodium: XChaCha20-Poly1305\n";
    std::cout << "   → Install liboqs for production PQC\n";
#else
    std::cout << "\n❌ SIMULATION MODE ONLY\n";
    std::cout << "   → No real cryptography libraries\n";
    std::cout << "   → Install liboqs and libsodium for production\n";
#endif

    std::cout << "\nInstallation instructions:\n";
    std::cout << "  liboqs:    https://github.com/open-quantum-safe/liboqs\n";
    std::cout << "              sudo apt install liboqs-dev (Ubuntu/Debian)\n";
    std::cout << "  libsodium: https://libsodium.org\n";
    std::cout << "              sudo apt install libsodium-dev (Ubuntu/Debian)\n";

    return 0;
}
