/**
 * @file crypto_test.cpp
 * @brief Unit test for the SST C++ crypto API (cpp/src/crypto.{hpp,cpp}).
 *
 * Like the API itself, the test performs NO dynamic allocation: every output
 * buffer is a stack std::array sized via the get_expected_* helpers.
 *
 * It tests:
 * 1. Crypto::encrypt_aes() / Crypto::decrypt_aes()
 *    with CBC, CTR, and GCM encryption modes.
 * 2. Crypto::symmetric_encrypt_authenticate() /
 *    Crypto::symmetric_decrypt_authenticate()
 *    with CBC, CTR, GCM modes, and with HMAC / no HMAC.
 * 3. Crypto::digest_message_sha256() and
 *    Crypto::sha256_sign() / Crypto::sha256_verify() round-trip,
 *    using a freshly generated RSA key pair.
 */

#include "../src/crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

using sst::Crypto;

namespace {

void print_buf(const unsigned char* buf, size_t size) {
    for (size_t i = 0; i < size; i++) {
        std::printf(" %.2x", buf[i]);
    }
    std::printf("\n");
}

void AES_test_common(sst::AES_encryption_mode_t mode) {
    // 16-byte random IV.
    unsigned char iv[sst::AES_128_CBC_IV_SIZE];
    Crypto::generate_nonce(sst::AES_128_CBC_IV_SIZE, iv);

    // 16-byte random key.
    unsigned char key[sst::AES_128_KEY_SIZE_IN_BYTES];
    Crypto::generate_nonce(sst::AES_128_KEY_SIZE_IN_BYTES, key);

    const std::string plaintext = "Hello World!";
    std::printf("Plaintext Length: %zu, Plaintext: %s\n", plaintext.size(),
                plaintext.c_str());

    unsigned char cipher[100];
    unsigned int length;
    std::memset(cipher, 0, sizeof(cipher));
    if (Crypto::encrypt_aes(
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size(), key, iv, mode, cipher, &length) < 0) {
        std::fprintf(stderr, "Failed encrypt_aes().\n");
        std::exit(1);
    }

    std::printf("Cipher Length: %u, Cipher Text:", length);
    print_buf(cipher, length);

    unsigned char decrypted[100];
    std::memset(decrypted, 0, sizeof(decrypted));
    unsigned int decrypted_length;
    if (Crypto::decrypt_aes(cipher, length, key, iv, mode, decrypted,
                            &decrypted_length) < 0) {
        std::fprintf(stderr, "Failed decrypt_aes().\n");
        std::exit(1);
    }
    std::printf("Decrypted Length: %u, Decrypted: %s\n", decrypted_length,
                decrypted);
    assert(decrypted_length == plaintext.size());
    assert(std::strncmp(reinterpret_cast<const char*>(decrypted),
                        plaintext.c_str(), decrypted_length) == 0);
    std::printf("\n");
}

void AES_test() {
    std::printf("**** STARTING AES_CBC_TEST.\n");
    AES_test_common(sst::AES_128_CBC);
    std::printf("**** STARTING AES_CTR_TEST.\n");
    AES_test_common(sst::AES_128_CTR);
    std::printf("**** STARTING AES_GCM_TEST.\n");
    AES_test_common(sst::AES_128_GCM);
}

// A stack buffer comfortably large enough for the short test payloads, used for
// both the ciphertext and the recovered plaintext (no heap allocation).
constexpr unsigned int TEST_BUF_SIZE = 128;

void symmetric_encrypt_decrypt_authenticate_common(
    sst::AES_encryption_mode_t enc_mode, sst::hmac_mode_t hmac_mode) {
    unsigned char cipher_key[sst::AES_128_KEY_SIZE_IN_BYTES];
    Crypto::generate_nonce(sst::AES_128_KEY_SIZE_IN_BYTES, cipher_key);

    unsigned char mac_key[sst::MAC_KEY_SHA256_SIZE];
    Crypto::generate_nonce(sst::MAC_KEY_SHA256_SIZE, mac_key);

    const std::string plaintext = "Hello World!";
    std::printf("Plaintext Length: %zu, Plaintext: %s\n", plaintext.size(),
                plaintext.c_str());

    // Size check: the expected lengths must fit in our stack buffers.
    unsigned int estimate_encrypted_length =
        Crypto::get_expected_encrypted_total_length(
            plaintext.size(), sst::AES_128_IV_SIZE, sst::MAC_KEY_SHA256_SIZE,
            enc_mode, hmac_mode);
    assert(estimate_encrypted_length <= TEST_BUF_SIZE);

    std::array<unsigned char, TEST_BUF_SIZE> encrypted{};
    unsigned int encrypted_length = 0;
    int s = Crypto::symmetric_encrypt_authenticate(
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.size(), mac_key, sst::MAC_KEY_SHA256_SIZE, cipher_key,
        sst::AES_128_KEY_SIZE_IN_BYTES, sst::AES_128_IV_SIZE, enc_mode,
        hmac_mode, encrypted.data(), &encrypted_length);
    assert(s == 0);
    std::printf("Cipher Length: %u, Cipher Text:", encrypted_length);
    print_buf(encrypted.data(), encrypted_length);

    unsigned int estimate_decrypted_length =
        Crypto::get_expected_decrypted_maximum_length(
            encrypted_length, sst::AES_128_IV_SIZE, sst::MAC_KEY_SHA256_SIZE,
            enc_mode, hmac_mode);
    assert(estimate_decrypted_length <= TEST_BUF_SIZE);

    std::array<unsigned char, TEST_BUF_SIZE> decrypted{};
    unsigned int decrypted_length = 0;
    s = Crypto::symmetric_decrypt_authenticate(
        encrypted.data(), encrypted_length, mac_key, sst::MAC_KEY_SHA256_SIZE,
        cipher_key, sst::AES_128_KEY_SIZE_IN_BYTES, sst::AES_128_IV_SIZE,
        enc_mode, hmac_mode, decrypted.data(), &decrypted_length);
    assert(s == 0);
    std::printf("Decrypted Length: %u, Decrypted: %.*s\n", decrypted_length,
                static_cast<int>(decrypted_length), decrypted.data());
    assert(decrypted_length == plaintext.size());
    assert(std::strncmp(reinterpret_cast<const char*>(decrypted.data()),
                        plaintext.c_str(), decrypted_length) == 0);
    std::printf("\n");
}

void symmetric_encrypt_decrypt_authenticate_test() {
    const sst::AES_encryption_mode_t modes[] = {
        sst::AES_128_CBC, sst::AES_128_CTR, sst::AES_128_GCM};
    const sst::hmac_mode_t hmac_modes[] = {sst::USE_HMAC, sst::NO_HMAC};

    std::printf("**** STARTING symmetric_encrypt_authenticate tests.\n");
    for (auto hmac_mode : hmac_modes) {
        for (auto mode : modes) {
            symmetric_encrypt_decrypt_authenticate_common(mode, hmac_mode);
        }
    }
}

// Generates an in-memory 2048-bit RSA key pair for the sign/verify test.
EVP_PKEY* generate_rsa_key_pair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    assert(ctx != nullptr);
    assert(EVP_PKEY_keygen_init(ctx) > 0);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0);
    EVP_PKEY* pkey = nullptr;
    assert(EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void digest_and_sign_verify_test() {
    std::printf("**** STARTING digest_and_sign_verify_test.\n");
    const std::string message = "Sign and verify me!";
    const auto* msg = reinterpret_cast<const unsigned char*>(message.data());
    unsigned int msg_len = message.size();

    // SHA-256 digest is deterministic: same input -> same digest.
    unsigned char md1[sst::SHA256_DIGEST_SIZE];
    unsigned char md2[sst::SHA256_DIGEST_SIZE];
    unsigned int md1_len = 0, md2_len = 0;
    assert(Crypto::digest_message_sha256(msg, msg_len, md1, &md1_len) == 0);
    assert(Crypto::digest_message_sha256(msg, msg_len, md2, &md2_len) == 0);
    assert(md1_len == sst::SHA256_DIGEST_SIZE);
    assert(std::memcmp(md1, md2, md1_len) == 0);

    EVP_PKEY* pkey = generate_rsa_key_pair();

    // Signature fits in an RSA-key-sized stack buffer (no allocation).
    // sig_len is in/out: set it to the buffer capacity before calling.
    std::array<unsigned char, sst::RSA_KEY_SIZE> sig{};
    size_t sig_len = sig.size();
    assert(Crypto::sha256_sign(msg, msg_len, pkey, sig.data(), &sig_len) == 0);
    std::printf("Signature Length: %zu\n", sig_len);

    // Correct signature verifies.
    assert(Crypto::sha256_verify(msg, msg_len, sig.data(), sig_len, pkey) == 0);

    // Tampered message must fail verification.
    const std::string tampered = "Sign and verify me?";
    assert(Crypto::sha256_verify(
               reinterpret_cast<const unsigned char*>(tampered.data()),
               tampered.size(), sig.data(), sig_len, pkey) == -1);

    EVP_PKEY_free(pkey);
    std::printf("Sign/verify round-trip passed.\n\n");
}

}  // namespace

int main() {
    AES_test();
    symmetric_encrypt_decrypt_authenticate_test();
    digest_and_sign_verify_test();
    std::printf("All C++ crypto tests passed.\n");
    return 0;
}
