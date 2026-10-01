/**
 * @file api_test.cpp
 * @brief Unit tests for the SST C++ API (src/api.{hpp,cpp}) that do not need
 * a running Auth server.
 *
 * Tests cover:
 * 1. SST_API construction: invalid paths, unknown config keys, missing key
 *    files, and a successful load from a generated config with generated keys.
 * 2. SessionKeyList: add/find/append/circular overwrite and expiration
 *    handling.
 * 3. Session key buffer encryption/decryption round trips.
 * 4. Key ID conversion.
 *
 * The full Auth handshake and entity-to-entity sessions are covered by the
 * examples in cpp/examples/server_client_example, which run in the
 * integration test workflow.
 */

#include "../src/api.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// CHECK() is compiled out in Release builds (NDEBUG), so use a check that is
// always active.
#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            std::fprintf(stderr, "CHECK failed: %s at %s:%d\n", #cond, \
                         __FILE__, __LINE__);                          \
            std::abort();                                              \
        }                                                              \
    } while (0)

using sst::session_key_t;
using sst::SessionKeyList;
using sst::SST_API;
using sst::SST_Exception;

namespace {

const std::filesystem::path kTmpDir =
    std::filesystem::temp_directory_path() / "sst_cpp_api_test";

// Writes a self-signed X.509 certificate (for the "Auth public key") and a
// private key, both PEM, so that SST_API can be constructed offline.
void generate_test_credentials(const std::string& cert_path,
                               const std::string& key_path) {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    CHECK(pkey != nullptr);

    X509* cert = X509_new();
    CHECK(cert != nullptr);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, pkey);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("SST test"), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    CHECK(X509_sign(cert, pkey, EVP_sha256()) > 0);

    FILE* cert_fp = std::fopen(cert_path.c_str(), "wb");
    CHECK(cert_fp != nullptr);
    CHECK(PEM_write_X509(cert_fp, cert) == 1);
    std::fclose(cert_fp);

    FILE* key_fp = std::fopen(key_path.c_str(), "wb");
    CHECK(key_fp != nullptr);
    CHECK(PEM_write_PrivateKey(key_fp, pkey, nullptr, nullptr, 0, nullptr,
                               nullptr) == 1);
    std::fclose(key_fp);

    X509_free(cert);
    EVP_PKEY_free(pkey);
}

std::string write_config(const std::string& path, const std::string& cert_path,
                         const std::string& key_path,
                         const std::string& extra_lines = "") {
    std::ofstream ofs(path);
    ofs << "entityInfo.name=net1.client\n";
    ofs << "entityInfo.purpose={\"group\":\"Servers\"}\n";
    ofs << "entityInfo.number_key=3\n";
    ofs << "authInfo.id=101\n";
    ofs << "sessionKey.encryptionMode=AES_128_CBC\n";
    ofs << "authInfo.pubkey.path=" << cert_path << "\n";
    ofs << "entityInfo.privkey.path=" << key_path << "\n";
    ofs << "auth.ip.address=127.0.0.1\n";
    ofs << "auth.port.number=21900\n";
    ofs << "entity.server.ip.address=127.0.0.1\n";
    ofs << "entity.server.port.number=21100\n";
    ofs << "network.protocol=TCP\n";
    ofs << extra_lines;
    return path;
}

session_key_t make_session_key(uint64_t id, uint64_t abs_validity_ms) {
    session_key_t key{};
    for (unsigned int i = 0; i < sst::SESSION_KEY_ID_SIZE; i++) {
        key.key_id[i] = static_cast<unsigned char>(
            id >> (8 * (sst::SESSION_KEY_ID_SIZE - 1 - i)));
    }
    key.abs_validity = abs_validity_ms;
    key.rel_validity = 60000;
    key.mac_key_size = sst::MAC_KEY_SIZE;
    key.cipher_key_size = sst::CIPHER_KEY_SIZE;
    sst::Crypto::generate_nonce(sst::MAC_KEY_SIZE, key.mac_key);
    sst::Crypto::generate_nonce(sst::CIPHER_KEY_SIZE, key.cipher_key);
    key.enc_mode = sst::AES_128_CBC;
    key.hmac_mode = sst::USE_HMAC;
    key.perm_dist_key_mode = sst::NO_PERMANENT_DIST_KEY;
    return key;
}

}  // namespace

// ---------------------------------------------------------------------------
// SST_API construction
// ---------------------------------------------------------------------------

void test_api_init_nonexistent_path() {
    std::printf("**** STARTING test_api_init_nonexistent_path.\n");
    bool caught = false;
    try {
        SST_API api((kTmpDir / "does_not_exist.config").string());
    } catch (const SST_Exception& e) {
        caught = true;
        std::printf("  Caught expected SST_Exception: %s\n", e.what());
    }
    CHECK(caught);
    std::printf("**** PASSED: test_api_init_nonexistent_path.\n");
}

void test_api_init_unknown_config_key() {
    std::printf("**** STARTING test_api_init_unknown_config_key.\n");
    std::string cert = (kTmpDir / "auth_cert.pem").string();
    std::string key = (kTmpDir / "entity_key.pem").string();
    std::string config = write_config((kTmpDir / "unknown.config").string(),
                                      cert, key, "no.such.key=1\n");
    bool caught = false;
    try {
        SST_API api(config);
    } catch (const SST_Exception& e) {
        caught = true;
        std::printf("  Caught expected SST_Exception: %s\n", e.what());
    }
    CHECK(caught);
    std::printf("**** PASSED: test_api_init_unknown_config_key.\n");
}

void test_api_init_invalid_purpose_index() {
    std::printf("**** STARTING test_api_init_invalid_purpose_index.\n");
    std::string cert = (kTmpDir / "auth_cert.pem").string();
    std::string key = (kTmpDir / "entity_key.pem").string();
    std::string config = write_config((kTmpDir / "bad_index.config").string(),
                                      cert, key, "purpose_index=2\n");
    bool caught = false;
    try {
        SST_API api(config);
    } catch (const SST_Exception& e) {
        caught = true;
        std::printf("  Caught expected SST_Exception: %s\n", e.what());
    }
    CHECK(caught);
    std::printf("**** PASSED: test_api_init_invalid_purpose_index.\n");
}

void test_api_init_permanent_dist_key_requires_both_paths() {
    std::printf(
        "**** STARTING "
        "test_api_init_permanent_dist_key_requires_both_paths.\n");
    std::string cert = (kTmpDir / "auth_cert.pem").string();
    std::string key = (kTmpDir / "entity_key.pem").string();
    std::string cipher_key_path = (kTmpDir / "dist_cipher.key").string();
    {
        std::ofstream ofs(cipher_key_path, std::ios::binary);
        ofs << std::string(sst::CIPHER_KEY_SIZE, 'k');
    }
    std::string config = write_config(
        (kTmpDir / "perm_dist.config").string(), cert, key,
        "PermanentDistKeyMode=on\ndistKey.cipherkey.path=" + cipher_key_path +
            "\n");
    bool caught = false;
    try {
        SST_API api(config);
    } catch (const SST_Exception& e) {
        caught = true;
        std::printf("  Caught expected SST_Exception: %s\n", e.what());
    }
    CHECK(caught);
    std::printf(
        "**** PASSED: test_api_init_permanent_dist_key_requires_both_paths.\n");
}

void test_api_init_missing_key_files() {
    std::printf("**** STARTING test_api_init_missing_key_files.\n");
    std::string config =
        write_config((kTmpDir / "missing_keys.config").string(),
                     (kTmpDir / "missing_cert.pem").string(),
                     (kTmpDir / "missing_key.pem").string());
    bool caught = false;
    try {
        SST_API api(config);
    } catch (const SST_Exception& e) {
        caught = true;
        std::printf("  Caught expected SST_Exception: %s\n", e.what());
    }
    CHECK(caught);
    std::printf("**** PASSED: test_api_init_missing_key_files.\n");
}

void test_api_init_success() {
    std::printf("**** STARTING test_api_init_success.\n");
    std::string cert = (kTmpDir / "auth_cert.pem").string();
    std::string key = (kTmpDir / "entity_key.pem").string();
    std::string config =
        write_config((kTmpDir / "valid.config").string(), cert, key);

    SST_API api(config);
    const sst::config_t& c = api.get_config();
    CHECK(std::strcmp(c.name, "net1.client") == 0);
    CHECK(std::strcmp(c.purpose[0], "{\"group\":\"Servers\"}") == 0);
    CHECK(c.purpose_index == 0);
    CHECK(c.numkey == 3);
    CHECK(c.auth_id == 101);
    CHECK(c.session_key_enc_mode == sst::AES_128_CBC);
    CHECK(c.hmac_mode == sst::USE_HMAC);
    CHECK(c.perm_dist_key_mode == sst::NO_PERMANENT_DIST_KEY);
    CHECK(std::strcmp(c.auth_ip_addr, "127.0.0.1") == 0);
    CHECK(c.auth_port_num == 21900);
    CHECK(std::strcmp(c.entity_server_ip_addr, "127.0.0.1") == 0);
    CHECK(c.entity_server_port_num == 21100);
    CHECK(std::strcmp(c.network_protocol, "TCP") == 0);
    // No distribution key yet: abs_validity 0 means "expired", so the first
    // request to Auth goes out with public key encryption.
    CHECK(api.get_dist_key().abs_validity == 0);
    std::printf("**** PASSED: test_api_init_success.\n");
}

void test_api_init_two_purposes() {
    std::printf("**** STARTING test_api_init_two_purposes.\n");
    std::string cert = (kTmpDir / "auth_cert.pem").string();
    std::string key = (kTmpDir / "entity_key.pem").string();
    std::string config = write_config(
        (kTmpDir / "two_purposes.config").string(), cert, key,
        "entityInfo.purpose={\"group\":\"Readers\"}\nHmacMode=off\n");
    SST_API api(config);
    const sst::config_t& c = api.get_config();
    CHECK(std::strcmp(c.purpose[0], "{\"group\":\"Servers\"}") == 0);
    CHECK(std::strcmp(c.purpose[1], "{\"group\":\"Readers\"}") == 0);
    CHECK(c.purpose_index == 1);
    CHECK(c.hmac_mode == sst::NO_HMAC);
    std::printf("**** PASSED: test_api_init_two_purposes.\n");
}

// ---------------------------------------------------------------------------
// SessionKeyList
// ---------------------------------------------------------------------------

void test_session_key_list_add_find() {
    std::printf("**** STARTING test_session_key_list_add_find.\n");
    const uint64_t far_future = UINT64_MAX;
    SessionKeyList list;
    CHECK(list.empty());
    CHECK(list.find(7) == -1);

    int idx = list.add(make_session_key(7, far_future));
    CHECK(idx == 0);
    CHECK(list.size() == 1);
    CHECK(list.rear_idx == 1);
    CHECK(list.find(7) == 0);
    CHECK(list.find(8) == -1);
    CHECK(sst::convert_skid_buf_to_int(list.s_key[0].key_id,
                                       sst::SESSION_KEY_ID_SIZE) == 7);

    // Fill the list past its capacity: the oldest key is overwritten.
    for (uint64_t id = 100; id < 100 + sst::MAX_SESSION_KEY; id++) {
        list.add(make_session_key(id, far_future));
    }
    CHECK(list.size() == static_cast<int>(sst::MAX_SESSION_KEY));
    CHECK(list.find(7) == -1);
    CHECK(list.find(100) >= 0);
    CHECK(list.find(100 + sst::MAX_SESSION_KEY - 1) >= 0);
    std::printf("**** PASSED: test_session_key_list_add_find.\n");
}

void test_session_key_list_append() {
    std::printf("**** STARTING test_session_key_list_append.\n");
    const uint64_t far_future = UINT64_MAX;
    SessionKeyList src;
    src.add(make_session_key(1, far_future));
    src.add(make_session_key(2, far_future));

    SessionKeyList dest;
    dest.add(make_session_key(10, far_future));
    dest.append(src);
    CHECK(dest.size() == 3);
    CHECK(dest.find(10) == 0);
    CHECK(dest.find(1) == 1);
    CHECK(dest.find(2) == 2);
    std::printf("**** PASSED: test_session_key_list_append.\n");
}

void test_session_key_list_addable() {
    std::printf("**** STARTING test_session_key_list_addable.\n");
    const uint64_t far_future = UINT64_MAX;
    SessionKeyList list;
    CHECK(list.addable(3));

    // Fill with valid keys: no room for 3 more, and none are expired.
    for (uint64_t id = 0; id < sst::MAX_SESSION_KEY; id++) {
        list.add(make_session_key(id, far_future));
    }
    CHECK(!list.addable(3));

    // Fill with expired keys: the oldest ones can be dropped.
    SessionKeyList expired;
    for (uint64_t id = 0; id < sst::MAX_SESSION_KEY; id++) {
        expired.add(make_session_key(id, /*abs_validity_ms=*/1));
    }
    CHECK(expired.addable(3));
    CHECK(expired.size() == static_cast<int>(sst::MAX_SESSION_KEY) - 3);

    // Only the single oldest key is expired: room for one more key, but a
    // request for two must fail without touching the list.
    SessionKeyList mixed;
    mixed.add(make_session_key(0, /*abs_validity_ms=*/1));
    for (uint64_t id = 1; id < sst::MAX_SESSION_KEY; id++) {
        mixed.add(make_session_key(id, far_future));
    }
    CHECK(!mixed.addable(2));
    CHECK(mixed.size() == static_cast<int>(sst::MAX_SESSION_KEY));
    CHECK(mixed.addable(1));
    CHECK(mixed.size() == static_cast<int>(sst::MAX_SESSION_KEY) - 1);
    CHECK(mixed.find(0) == -1);
    CHECK(mixed.find(1) >= 0);
    std::printf("**** PASSED: test_session_key_list_addable.\n");
}

// ---------------------------------------------------------------------------
// Buffer encryption with a session key
// ---------------------------------------------------------------------------

void test_encrypt_decrypt_buf_with_session_key() {
    std::printf("**** STARTING test_encrypt_decrypt_buf_with_session_key.\n");
    session_key_t key = make_session_key(42, UINT64_MAX);
    const char msg[] = "Hello from the SST C++ API";
    const unsigned int msg_len = static_cast<unsigned int>(std::strlen(msg));

    unsigned int enc_cap = sst::Crypto::get_expected_encrypted_total_length(
        msg_len, sst::AES_128_IV_SIZE, sst::MAC_KEY_SHA256_SIZE, key.enc_mode,
        key.hmac_mode);
    std::vector<unsigned char> encrypted(enc_cap);
    unsigned int enc_len = 0;
    CHECK(SST_API::encrypt_buf_with_session_key(
              key, reinterpret_cast<const unsigned char*>(msg), msg_len,
              encrypted.data(), &enc_len) == 0);
    CHECK(enc_len == enc_cap);

    std::vector<unsigned char> decrypted(enc_len);
    unsigned int dec_len = 0;
    CHECK(SST_API::decrypt_buf_with_session_key(
              key, encrypted.data(), enc_len, decrypted.data(), &dec_len) == 0);
    CHECK(dec_len == msg_len);
    CHECK(std::memcmp(decrypted.data(), msg, msg_len) == 0);

    // Tampering with the ciphertext must fail HMAC verification.
    encrypted[sst::AES_128_IV_SIZE] ^= 0x01;
    CHECK(SST_API::decrypt_buf_with_session_key(
              key, encrypted.data(), enc_len, decrypted.data(), &dec_len) < 0);

    // Truncated input (shorter than IV + HMAC + tag) must be rejected before
    // reaching the crypto layer, for every mode.
    unsigned char short_buf[sst::AES_128_IV_SIZE + sst::MAC_KEY_SIZE] = {0};
    for (sst::AES_encryption_mode_t mode :
         {sst::AES_128_CBC, sst::AES_128_CTR, sst::AES_128_GCM}) {
        session_key_t k = make_session_key(44, UINT64_MAX);
        k.enc_mode = mode;
        CHECK(SST_API::decrypt_buf_with_session_key(
                  k, short_buf, sizeof(short_buf), decrypted.data(), &dec_len) <
              0);
        CHECK(SST_API::decrypt_buf_with_session_key(
                  k, short_buf, sst::AES_128_IV_SIZE, decrypted.data(),
                  &dec_len) < 0);
    }

    // An expired key must be rejected.
    session_key_t expired = make_session_key(43, /*abs_validity_ms=*/1);
    CHECK(SST_API::encrypt_buf_with_session_key(
              expired, reinterpret_cast<const unsigned char*>(msg), msg_len,
              encrypted.data(), &enc_len) < 0);
    std::printf("**** PASSED: test_encrypt_decrypt_buf_with_session_key.\n");
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

void test_convert_skid_buf_to_int() {
    std::printf("**** STARTING test_convert_skid_buf_to_int.\n");
    unsigned char id[sst::SESSION_KEY_ID_SIZE] = {0, 0, 0, 0, 0, 0, 0x01, 0x02};
    CHECK(sst::convert_skid_buf_to_int(id, sst::SESSION_KEY_ID_SIZE) == 0x0102);
    unsigned char big[sst::SESSION_KEY_ID_SIZE] = {0x01, 0, 0, 0, 0, 0, 0, 0};
    CHECK(sst::convert_skid_buf_to_int(big, sst::SESSION_KEY_ID_SIZE) ==
          (1ULL << 56));
    std::printf("**** PASSED: test_convert_skid_buf_to_int.\n");
}

void test_update_validity() {
    std::printf("**** STARTING test_update_validity.\n");
    session_key_t key = make_session_key(1, /*abs_validity_ms=*/1);
    CHECK(!sst::is_session_key_valid(key));
    sst::update_validity(key);
    CHECK(sst::is_session_key_valid(key));
    std::printf("**** PASSED: test_update_validity.\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    std::printf("===== Running SST C++ API tests =====\n\n");
    std::filesystem::create_directories(kTmpDir);
    generate_test_credentials((kTmpDir / "auth_cert.pem").string(),
                              (kTmpDir / "entity_key.pem").string());

    test_api_init_nonexistent_path();
    test_api_init_unknown_config_key();
    test_api_init_missing_key_files();
    test_api_init_invalid_purpose_index();
    test_api_init_permanent_dist_key_requires_both_paths();
    test_api_init_success();
    test_api_init_two_purposes();
    test_session_key_list_add_find();
    test_session_key_list_append();
    test_session_key_list_addable();
    test_encrypt_decrypt_buf_with_session_key();
    test_convert_skid_buf_to_int();
    test_update_validity();

    std::filesystem::remove_all(kTmpDir);
    std::printf("\n===== All SST C++ API tests passed. =====\n");
    return 0;
}
