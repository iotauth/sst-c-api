/**
 * @file message_test.cpp
 * @brief Unit tests for the SST C++ message classes (src/message/), checked
 * against the wire formats of org.iot.auth.message in the Auth server.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../src/message/add_reader_req_message.hpp"
#include "../src/message/add_reader_resp_message.hpp"
#include "../src/message/auth_alert_message.hpp"
#include "../src/message/auth_hello_message.hpp"
#include "../src/message/iotsp_message.hpp"
#include "../src/message/session_key_req_message.hpp"
#include "../src/message/session_key_resp_message.hpp"

// assert() is compiled out in Release builds, so use an always-on check.
#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            std::fprintf(stderr, "CHECK failed: %s at %s:%d\n", #cond, \
                         __FILE__, __LINE__);                          \
            std::abort();                                              \
        }                                                              \
    } while (0)

using sst::SST_Exception;
using sst::internal::Bytes;
using sst::message::AddReaderReqMessage;
using sst::message::AddReaderRespMessage;
using sst::message::AuthAlertCode;
using sst::message::AuthAlertMessage;
using sst::message::AuthHelloMessage;
using sst::message::IoTSPMessage;
using sst::message::MessageType;
using sst::message::SessionKeyReqMessage;
using sst::message::SessionKeyRespMessage;

namespace {

template <class F>
bool throws(F f) {
    try {
        f();
    } catch (const SST_Exception&) {
        return true;
    }
    return false;
}

sst::distribution_key_t make_dist_key() {
    sst::distribution_key_t key{};
    key.mac_key_size = sst::MAC_KEY_SIZE;
    key.cipher_key_size = sst::CIPHER_KEY_SIZE;
    sst::Crypto::generate_nonce(sst::MAC_KEY_SIZE, key.mac_key);
    sst::Crypto::generate_nonce(sst::CIPHER_KEY_SIZE, key.cipher_key);
    key.abs_validity = UINT64_MAX;
    key.enc_mode = sst::AES_128_CBC;
    return key;
}

Bytes decrypt_with(const sst::distribution_key_t& key, const unsigned char* buf,
                   size_t len) {
    Bytes plain;
    CHECK(sst::internal::symmetric_decrypt_authenticate(
              buf, static_cast<unsigned int>(len), key.mac_key,
              key.mac_key_size, key.cipher_key, key.cipher_key_size,
              key.enc_mode, sst::USE_HMAC, plain) == 0);
    return plain;
}

Bytes encrypt_with(const sst::distribution_key_t& key, const Bytes& plain) {
    Bytes enc;
    CHECK(sst::internal::symmetric_encrypt_authenticate(
              plain.data(), static_cast<unsigned int>(plain.size()),
              key.mac_key, key.mac_key_size, key.cipher_key,
              key.cipher_key_size, key.enc_mode, sst::USE_HMAC, enc) == 0);
    return enc;
}

// Reads a BufferedString ([varint size][bytes]) like the Auth server does.
std::string read_buffered_string(const Bytes& buf, size_t& idx) {
    unsigned int len;
    int len_size;
    sst::internal::var_length_int_to_num(
        buf.data() + idx, static_cast<unsigned int>(buf.size() - idx), &len,
        &len_size);
    CHECK(len_size > 0);
    idx += static_cast<size_t>(len_size);
    std::string str(reinterpret_cast<const char*>(buf.data() + idx), len);
    idx += len;
    return str;
}

void append_buffered_string(Bytes& buf, const std::string& str) {
    unsigned char len_buf[sst::internal::MAX_PAYLOAD_BUF_SIZE];
    unsigned int len_size;
    sst::internal::num_to_var_length_int(static_cast<unsigned int>(str.size()),
                                         len_buf, &len_size);
    buf.insert(buf.end(), len_buf, len_buf + len_size);
    buf.insert(buf.end(), str.begin(), str.end());
}

const unsigned char kEntityNonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
const unsigned char kAuthNonce[8] = {9, 10, 11, 12, 13, 14, 15, 16};

}  // namespace

void test_iotsp_message_serialize_and_read() {
    std::printf("**** STARTING test_iotsp_message_serialize_and_read.\n");
    Bytes small = IoTSPMessage(MessageType::AUTH_ALERT, Bytes{2}).serialize();
    CHECK((small == Bytes{100, 1, 2}));

    // A 200-byte payload needs a two-byte length: 200 = 0x48 | (1 << 7).
    Bytes payload(200, 0xAB);
    Bytes wire =
        IoTSPMessage(MessageType::SECURE_COMM_MSG, payload).serialize();
    CHECK(wire.size() == 203);
    CHECK(wire[0] == 33 && wire[1] == 0xC8 && wire[2] == 0x01);

    int fds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    CHECK(sst::internal::sst_write_to_socket(
              fds[0], wire.data(), static_cast<unsigned int>(wire.size())) ==
          203);
    MessageType type;
    Bytes received;
    CHECK(IoTSPMessage::read(fds[1], 1024, type, received) == 200);
    CHECK(type == MessageType::SECURE_COMM_MSG && received == payload);

    // Oversized payloads are rejected.
    sst::internal::sst_write_to_socket(fds[0], wire.data(),
                                       static_cast<unsigned int>(wire.size()));
    CHECK(IoTSPMessage::read(fds[1], 100, type, received) == -1);
    ::close(fds[0]);
    ::close(fds[1]);

    // A closed peer: read() returns 0, receive() throws.
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    ::close(fds[0]);
    CHECK(IoTSPMessage::read(fds[1], 1024, type, received) == 0);
    CHECK(throws([&] { IoTSPMessage::receive(fds[1], 1024); }));
    ::close(fds[1]);
    std::printf("**** PASSED: test_iotsp_message_serialize_and_read.\n");
}

void test_auth_hello_message() {
    std::printf("**** STARTING test_auth_hello_message.\n");
    Bytes payload = {0, 0, 0, 101};
    payload.insert(payload.end(), kAuthNonce, kAuthNonce + 8);
    AuthHelloMessage hello(IoTSPMessage(MessageType::AUTH_HELLO, payload));
    CHECK(hello.get_auth_id() == 101);
    CHECK(std::memcmp(hello.get_auth_nonce().data(), kAuthNonce, 8) == 0);

    CHECK(throws([&] {
        AuthHelloMessage(IoTSPMessage(MessageType::AUTH_ALERT, payload));
    }));
    CHECK(throws([] {
        AuthHelloMessage(IoTSPMessage(MessageType::AUTH_HELLO, Bytes(11)));
    }));
    std::printf("**** PASSED: test_auth_hello_message.\n");
}

void test_auth_alert_message() {
    std::printf("**** STARTING test_auth_alert_message.\n");
    AuthAlertMessage alert(IoTSPMessage(MessageType::AUTH_ALERT, Bytes{0}));
    CHECK(alert.get_auth_alert_code() ==
          AuthAlertCode::INVALID_DISTRIBUTION_KEY);
    CHECK(alert.describe() ==
          "AUTH_ALERT received from Auth: Invalid Distribution Key. (code 0)");

    AuthAlertMessage unknown(IoTSPMessage(MessageType::AUTH_ALERT, Bytes{7}));
    CHECK(unknown.describe() ==
          "AUTH_ALERT received from Auth: Unknown Code. (code 7)");

    CHECK(throws(
        [] { AuthAlertMessage(IoTSPMessage(MessageType::AUTH_ALERT)); }));
    std::printf("**** PASSED: test_auth_alert_message.\n");
}

void test_session_key_req_message() {
    std::printf("**** STARTING test_session_key_req_message.\n");
    sst::distribution_key_t dist_key = make_dist_key();
    SessionKeyReqMessage req(kEntityNonce, kAuthNonce, 3, "net1.client",
                             "{\"group\":\"Servers\"}");
    Bytes wire = req.serialize_and_encrypt(dist_key, nullptr, nullptr);
    CHECK(req.get_type() == MessageType::SESSION_KEY_REQ);
    CHECK(wire[0] == 22);

    // Payload: [senderLen][sender][Enc_distKey(SessionKeyReq)].
    const Bytes& payload = req.get_payload();
    CHECK(payload[0] == 11);
    CHECK(std::string(reinterpret_cast<const char*>(payload.data() + 1), 11) ==
          "net1.client");
    Bytes plain =
        decrypt_with(dist_key, payload.data() + 12, payload.size() - 12);

    // Parse in the order SessionKeyReqMessage does in the Auth server.
    size_t idx = 0;
    CHECK(std::memcmp(plain.data(), kEntityNonce, 8) == 0);
    CHECK(std::memcmp(plain.data() + 8, kAuthNonce, 8) == 0);
    idx = 16;
    CHECK(sst::internal::read_unsigned_int_BE(plain.data() + idx, 4) == 3);
    idx += 4;
    CHECK(read_buffered_string(plain, idx) == "net1.client");
    CHECK(read_buffered_string(plain, idx) == "{\"group\":\"Servers\"}");
    CHECK(idx == plain.size());

    // Expired distribution key without public/private keys.
    sst::distribution_key_t expired = dist_key;
    expired.abs_validity = 0;
    CHECK(
        throws([&] { req.serialize_and_encrypt(expired, nullptr, nullptr); }));

    // Expired distribution key: public key encryption plus signature.
    EVP_PKEY* rsa = EVP_RSA_gen(2048);
    CHECK(rsa != nullptr);
    req.serialize_and_encrypt(expired, rsa, rsa);
    CHECK(req.get_type() == MessageType::SESSION_KEY_REQ_IN_PUB_ENC);
    CHECK(req.get_payload().size() == 512);
    CHECK(sst::Crypto::sha256_verify(req.get_payload().data(), 256,
                                     req.get_payload().data() + 256, 256,
                                     rsa) == 0);
    Bytes decrypted(256);
    size_t decrypted_len = decrypted.size();
    CHECK(sst::Crypto::private_decrypt(req.get_payload().data(), 256,
                                       RSA_PKCS1_OAEP_PADDING, rsa,
                                       decrypted.data(), &decrypted_len) == 0);
    decrypted.resize(decrypted_len);
    CHECK(decrypted == plain);
    EVP_PKEY_free(rsa);
    std::printf("**** PASSED: test_session_key_req_message.\n");
}

void test_add_reader_req_message() {
    std::printf("**** STARTING test_add_reader_req_message.\n");
    sst::distribution_key_t dist_key = make_dist_key();
    AddReaderReqMessage req(kEntityNonce, kAuthNonce, "net1.uploader",
                            "{\"AddReader\":\"net1.Bob\"}");
    req.serialize_and_encrypt(dist_key, nullptr, nullptr);
    CHECK(req.get_type() == MessageType::ADD_READER_REQ);
    const Bytes& payload = req.get_payload();
    size_t name_len = payload[0];
    Bytes plain = decrypt_with(dist_key, payload.data() + 1 + name_len,
                               payload.size() - 1 - name_len);

    // Parse in the order AddReaderReqMessage does: no key count.
    size_t idx = 16;
    CHECK(std::memcmp(plain.data(), kEntityNonce, 8) == 0);
    CHECK(read_buffered_string(plain, idx) == "net1.uploader");
    CHECK(read_buffered_string(plain, idx) == "{\"AddReader\":\"net1.Bob\"}");
    CHECK(idx == plain.size());
    std::printf("**** PASSED: test_add_reader_req_message.\n");
}

void test_session_key_resp_message() {
    std::printf("**** STARTING test_session_key_resp_message.\n");
    sst::distribution_key_t dist_key = make_dist_key();

    // Serialize like SessionKeyRespMessage.serializeAndEncrypt in Auth.
    Bytes plain(kEntityNonce, kEntityNonce + 8);
    append_buffered_string(plain, "{\"cipher\":\"AES-128-CBC\"}");
    plain.insert(plain.end(), {0, 0, 0, 1});
    plain.insert(plain.end(), {0, 0, 0, 0, 0, 0, 0, 42});  // key id
    plain.insert(plain.end(), {0, 0, 0, 0, 0, 5});         // abs validity
    plain.insert(plain.end(), {0, 0, 0, 0, 0, 7});         // rel validity
    plain.push_back(16);
    plain.insert(plain.end(), 16, 0x11);  // cipher key
    plain.push_back(32);
    plain.insert(plain.end(), 32, 0x22);  // mac key
    Bytes enc = encrypt_with(dist_key, plain);

    SessionKeyRespMessage resp(IoTSPMessage(MessageType::SESSION_KEY_RESP, enc),
                               0);
    CHECK(!resp.has_distribution_key());
    resp.decrypt_and_parse(dist_key, sst::AES_128_CBC);
    CHECK(std::memcmp(resp.get_entity_nonce().data(), kEntityNonce, 8) == 0);
    CHECK(resp.get_crypto_spec() == "{\"cipher\":\"AES-128-CBC\"}");
    const sst::SessionKeyList& keys = resp.get_session_keys();
    CHECK(keys.size() == 1);
    CHECK(sst::convert_skid_buf_to_int(keys.s_key[0].key_id, 8) == 42);
    CHECK(keys.s_key[0].abs_validity == 5 && keys.s_key[0].rel_validity == 7);
    CHECK(keys.s_key[0].cipher_key_size == 16 &&
          keys.s_key[0].cipher_key[0] == 0x11);
    CHECK(keys.s_key[0].mac_key_size == 32 && keys.s_key[0].mac_key[0] == 0x22);

    // WITH_DIST_KEY: the encrypted distribution key comes first.
    Bytes with_dist(512, 0x33);
    with_dist.insert(with_dist.end(), enc.begin(), enc.end());
    SessionKeyRespMessage resp2(
        IoTSPMessage(MessageType::SESSION_KEY_RESP_WITH_DIST_KEY, with_dist),
        256);
    CHECK(resp2.has_distribution_key());
    CHECK(resp2.get_encrypted_distribution_key() == Bytes(512, 0x33));
    resp2.decrypt_and_parse(dist_key, sst::AES_128_CBC);
    CHECK(resp2.get_session_keys().size() == 1);

    // No private key, wrong type, wrong key, truncated crypto spec.
    CHECK(throws([&] {
        SessionKeyRespMessage(
            IoTSPMessage(MessageType::SESSION_KEY_RESP_WITH_DIST_KEY,
                         with_dist),
            0);
    }));
    CHECK(throws([&] {
        SessionKeyRespMessage(IoTSPMessage(MessageType::ADD_READER_RESP, enc),
                              0);
    }));
    CHECK(throws([&] {
        SessionKeyRespMessage r(
            IoTSPMessage(MessageType::SESSION_KEY_RESP, enc), 0);
        r.decrypt_and_parse(make_dist_key(), sst::AES_128_CBC);
    }));
    Bytes bad(kEntityNonce, kEntityNonce + 8);
    bad.insert(bad.end(), {0x7F, 'x'});  // claims 127 bytes, has 1
    CHECK(throws([&] {
        SessionKeyRespMessage r(IoTSPMessage(MessageType::SESSION_KEY_RESP,
                                             encrypt_with(dist_key, bad)),
                                0);
        r.decrypt_and_parse(dist_key, sst::AES_128_CBC);
    }));
    std::printf("**** PASSED: test_session_key_resp_message.\n");
}

void test_add_reader_resp_message() {
    std::printf("**** STARTING test_add_reader_resp_message.\n");
    sst::distribution_key_t dist_key = make_dist_key();
    Bytes enc = encrypt_with(dist_key, Bytes(kEntityNonce, kEntityNonce + 8));
    AddReaderRespMessage resp(IoTSPMessage(MessageType::ADD_READER_RESP, enc),
                              0);
    resp.decrypt_and_parse(dist_key, sst::AES_128_CBC);
    CHECK(std::memcmp(resp.get_entity_nonce().data(), kEntityNonce, 8) == 0);
    std::printf("**** PASSED: test_add_reader_resp_message.\n");
}

int main() {
    std::printf("===== Running SST C++ message tests =====\n\n");
    test_iotsp_message_serialize_and_read();
    test_auth_hello_message();
    test_auth_alert_message();
    test_session_key_req_message();
    test_add_reader_req_message();
    test_session_key_resp_message();
    test_add_reader_resp_message();
    std::printf("\n===== All SST C++ message tests passed. =====\n");
    return 0;
}
