/**
 * @brief Wire-level regression tests for Auth exchanges and handshake framing.
 * Uses a local Auth stand-in; response fields are constructed independently of
 * the production response classes. No installed Auth service is required.
 */
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>

#include "api.hpp"
#include "api_internal.hpp"
#include "message/iotsp_message.hpp"
#include "net/sockets.hpp"

#define CHECK(condition)                                            \
    do {                                                            \
        if (!(condition)) {                                         \
            std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, \
                         #condition);                               \
            std::abort();                                           \
        }                                                           \
    } while (0)

using sst::internal::Bytes;
using sst::message::IoTSPMessage;
using sst::message::MessageType;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

namespace {

struct SocketOwner {
    int fd;
    ~SocketOwner() { ::close(fd); }
};

void number(Bytes& bytes, uint64_t value, int length) {
    for (int i = length - 1; i >= 0; --i) {
        bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void string(Bytes& bytes, const std::string& value) {
    size_t length = value.size();
    do {
        unsigned char next = length & 0x7f;
        length >>= 7;
        bytes.push_back(next | (length ? 0x80 : 0));
    } while (length);
    bytes.insert(bytes.end(), value.begin(), value.end());
}

void send_frame(int fd, unsigned char msg_type, const Bytes& payload) {
    Bytes wire{msg_type};
    size_t length = payload.size();
    do {
        unsigned char next = length & 0x7f;
        length >>= 7;
        wire.push_back(next | (length ? 0x80 : 0));
    } while (length);
    wire.insert(wire.end(), payload.begin(), payload.end());
    CHECK(sst::internal::sst_write_to_socket(fd, wire.data(), wire.size()) ==
          static_cast<int>(wire.size()));
}

Bytes encrypt(const sst::distribution_key_t& key, const Bytes& plain) {
    Bytes encrypted;
    CHECK(sst::internal::symmetric_encrypt_authenticate(
              plain.data(), plain.size(), key.mac_key, key.mac_key_size,
              key.cipher_key, key.cipher_key_size, key.enc_mode, sst::USE_HMAC,
              encrypted) == 0);
    return encrypted;
}

Bytes decrypt(const sst::distribution_key_t& key, const Bytes& encrypted) {
    Bytes plain;
    CHECK(sst::internal::symmetric_decrypt_authenticate(
              encrypted.data(), encrypted.size(), key.mac_key, key.mac_key_size,
              key.cipher_key, key.cipher_key_size, key.enc_mode, sst::USE_HMAC,
              plain) == 0);
    return plain;
}

struct Credentials {
    Key auth{EVP_RSA_gen(2048), EVP_PKEY_free};
    Key entity{EVP_RSA_gen(2048), EVP_PKEY_free};
    sst::distribution_key_t dist{};
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() /
        ("sst_protocol_test_" + std::to_string(::getpid()));

    Credentials() {
        CHECK(auth && entity);
        std::filesystem::create_directories(dir);
        dist.mac_key_size = sst::MAC_KEY_SIZE;
        dist.cipher_key_size = sst::CIPHER_KEY_SIZE;
        dist.enc_mode = sst::AES_128_CBC;
        std::memset(dist.cipher_key, 0x11, dist.cipher_key_size);
        std::memset(dist.mac_key, 0x22, dist.mac_key_size);
        dist.abs_validity = 0xffffffffffffULL;
        X509* cert = X509_new();
        CHECK(cert);
        CHECK(X509_set_version(cert, 2) == 1);
        CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
        CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), 0));
        CHECK(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
        CHECK(X509_set_pubkey(cert, auth.get()) == 1);
        X509_NAME* name = X509_get_subject_name(cert);
        CHECK(X509_NAME_add_entry_by_txt(
                  name, "CN", MBSTRING_ASC,
                  reinterpret_cast<const unsigned char*>("Auth test"), -1, -1,
                  0) == 1);
        CHECK(X509_set_issuer_name(cert, name) == 1);
        CHECK(X509_sign(cert, auth.get(), EVP_sha256()) > 0);
        FILE* file = std::fopen((dir / "auth.pem").c_str(), "wb");
        CHECK(file && PEM_write_X509(file, cert) == 1);
        std::fclose(file);
        X509_free(cert);
        file = std::fopen((dir / "entity.pem").c_str(), "wb");
        CHECK(file && PEM_write_PrivateKey(file, entity.get(), nullptr, nullptr,
                                           0, nullptr, nullptr) == 1);
        std::fclose(file);
    }
    ~Credentials() { std::filesystem::remove_all(dir); }

    std::string config(int port) const {
        const auto path = dir / "entity.config";
        std::ofstream out(path);
        out << "entityInfo.name=net1.client\nentityInfo.number_key=10\n"
            << "authInfo.id=101\nauth.ip.address=127.0.0.1\nauth.port.number="
            << port
            << "\nentityInfo.purpose=default\nentityInfo.purpose="
               "other\npurpose_index=0\n"
            << "authInfo.pubkey.path=" << (dir / "auth.pem").string()
            << "\nentityInfo.privkey.path=" << (dir / "entity.pem").string()
            << '\n';
        return path.string();
    }

    Bytes distribution_prefix() const {
        Bytes plain;
        number(plain, dist.abs_validity, 6);
        plain.push_back(dist.cipher_key_size);
        plain.insert(plain.end(), dist.cipher_key,
                     dist.cipher_key + dist.cipher_key_size);
        plain.push_back(dist.mac_key_size);
        plain.insert(plain.end(), dist.mac_key,
                     dist.mac_key + dist.mac_key_size);
        Bytes encrypted(EVP_PKEY_size(entity.get()));
        size_t size = encrypted.size();
        CHECK(sst::Crypto::public_encrypt(plain.data(), plain.size(),
                                          RSA_PKCS1_OAEP_PADDING, entity.get(),
                                          encrypted.data(), &size) == 0);
        encrypted.resize(size);
        Bytes signature(EVP_PKEY_size(auth.get()));
        size = signature.size();
        CHECK(sst::Crypto::sha256_sign(encrypted.data(), encrypted.size(),
                                       auth.get(), signature.data(),
                                       &size) == 0);
        encrypted.insert(encrypted.end(), signature.begin(),
                         signature.begin() + size);
        return encrypted;
    }
};

struct Exchange {
    unsigned char request_type;
    std::string purpose;
    uint64_t key_id = 42;
    unsigned int key_count = 1;
    bool wrong_nonce = false;
    bool alert = false;
};

void serve_exchange(int listener, const Credentials& credentials,
                    const Exchange& expected) {
    SocketOwner peer{::accept(listener, nullptr, nullptr)};
    CHECK(peer.fd >= 0);
    const std::array<unsigned char, 8> auth_nonce{1, 2, 3, 4, 5, 6, 7, 8};
    Bytes hello;
    number(hello, 101, 4);
    hello.insert(hello.end(), auth_nonce.begin(), auth_nonce.end());
    send_frame(peer.fd, 0, hello);
    IoTSPMessage request = IoTSPMessage::receive(peer.fd, 4096);
    CHECK(static_cast<unsigned char>(request.get_type()) ==
          expected.request_type);
    bool public_key =
        expected.request_type == 20 || expected.request_type == 60;
    Bytes plain;
    const Bytes& payload = request.get_payload();
    if (public_key) {
        size_t rsa_size = EVP_PKEY_size(credentials.auth.get());
        CHECK(payload.size() ==
              rsa_size + EVP_PKEY_size(credentials.entity.get()));
        CHECK(sst::Crypto::sha256_verify(
                  payload.data(), rsa_size, payload.data() + rsa_size,
                  payload.size() - rsa_size, credentials.entity.get()) == 0);
        plain.resize(rsa_size);
        size_t length = plain.size();
        CHECK(sst::Crypto::private_decrypt(
                  payload.data(), rsa_size, RSA_PKCS1_OAEP_PADDING,
                  credentials.auth.get(), plain.data(), &length) == 0);
        plain.resize(length);
    } else {
        CHECK(payload.size() > 12 && payload[0] == 11);
        CHECK(std::memcmp(payload.data() + 1, "net1.client", 11) == 0);
        plain = decrypt(credentials.dist,
                        Bytes(payload.begin() + 12, payload.end()));
    }
    CHECK(plain.size() >= 16);
    CHECK(std::memcmp(plain.data() + 8, auth_nonce.data(), 8) == 0);
    Bytes expected_body(plain.begin(), plain.begin() + 8);
    expected_body.insert(expected_body.end(), auth_nonce.begin(),
                         auth_nonce.end());
    bool key_request =
        expected.request_type == 20 || expected.request_type == 22;
    if (key_request) number(expected_body, 10, 4);
    string(expected_body, "net1.client");
    string(expected_body, expected.purpose);
    CHECK(plain == expected_body);
    if (expected.alert) {
        send_frame(peer.fd, 100, Bytes{1});
        return;
    }
    Bytes response(plain.begin(), plain.begin() + 8);
    if (expected.wrong_nonce) response[0] ^= 0xff;
    if (key_request) {
        string(response, "{\"cipher\":\"AES-128-CBC\"}");
        number(response, expected.key_count, 4);
        for (unsigned int i = 0; i < expected.key_count; ++i) {
            number(response, expected.key_id + i, 8);
            number(response, credentials.dist.abs_validity, 6);
            number(response, 60000, 6);
            response.push_back(16);
            response.insert(response.end(), 16, 0x33);
            response.push_back(32);
            response.insert(response.end(), 32, 0x44);
        }
    }
    Bytes encrypted = encrypt(credentials.dist, response);
    Bytes wire_payload =
        public_key ? credentials.distribution_prefix() : Bytes{};
    wire_payload.insert(wire_payload.end(), encrypted.begin(), encrypted.end());
    if (expected.key_count == 10 && public_key)
        CHECK(wire_payload.size() > 1024);
    send_frame(peer.fd,
               key_request ? (public_key ? 21 : 23) : (public_key ? 61 : 63),
               wire_payload);
}

template <class F>
void expect_error(sst::SST_ErrorCode code, F call) {
    bool caught = false;
    try {
        call();
    } catch (const sst::SST_Exception& error) {
        caught = true;
        CHECK(error.code() == code);
    }
    CHECK(caught);
}

void test_auth_exchanges() {
    Credentials credentials;
    sst::ServerSocket listener(sst::SST_SOCK_INET, "127.0.0.1", 0);
    CHECK(listener.get_fd() >= 0);
    sockaddr_in address{};
    socklen_t length = sizeof(address);
    CHECK(::getsockname(listener.get_fd(),
                        reinterpret_cast<sockaddr*>(&address), &length) == 0);
    const std::string config = credentials.config(ntohs(address.sin_port));
    std::thread auth([&] {
        for (const Exchange& exchange :
             {Exchange{20, "default", 42, 10}, Exchange{22, "other"},
              Exchange{22, "default"}, Exchange{22, "other"},
              Exchange{22, "{\"keyId\":99}", 99}, Exchange{62, "reader"},
              Exchange{22, "{\"keyId\":100}", 101}, Exchange{22, "default"},
              Exchange{62, "bad-nonce", 42, 1, true},
              Exchange{62, "alert", 42, 1, false, true},
              Exchange{60, "first-reader"}, Exchange{22, "default"}}) {
            serve_exchange(listener.get_fd(), credentials, exchange);
        }
    });
    sst::SST_API api(config);
    CHECK(api.get_session_key().size() == 10);
    CHECK(api.get_session_key_with_index(1).size() == 1);
    sst::SessionKeyList list;
    api.get_session_key(list);
    sst::SessionKeyList other_list;
    api.get_session_key_with_index(1, other_list);
    CHECK(list.size() == 1 && other_list.size() == 1);
    api.get_session_key(list);  // no room for ten more valid keys: no request
    CHECK(list.size() == 1);
    unsigned char id[8] = {0, 0, 0, 0, 0, 0, 0, 99};
    CHECK(api.get_session_key_by_ID(id, list)->key_id[7] == 99);
    CHECK(api.get_session_key_by_ID(id, list)->key_id[7] == 99);  // cache hit
    api.send_add_reader_req_via_TCP("reader");
    id[7] = 100;
    expect_error(sst::SST_ErrorCode::Protocol,
                 [&] { api.get_session_key_by_ID(id, list); });
    CHECK(api.get_session_key().size() ==
          1);  // failed ID request leaves no sticky purpose
    expect_error(sst::SST_ErrorCode::Protocol,
                 [&] { api.send_add_reader_req_via_TCP("bad-nonce"); });
    expect_error(sst::SST_ErrorCode::AuthRejected,
                 [&] { api.send_add_reader_req_via_TCP("alert"); });
    sst::SST_API reader_first(config);
    reader_first.send_add_reader_req_via_TCP("first-reader");
    CHECK(reader_first.get_session_key().size() == 1);
    auth.join();
}

void test_handshake_msg_type_and_flags() {
    sst::session_key_t key{};
    key.key_id[7] = 42;
    key.abs_validity = UINT64_MAX;
    key.rel_validity = 60000;
    key.cipher_key_size = 16;
    key.mac_key_size = 32;
    key.enc_mode = sst::AES_128_CBC;
    key.hmac_mode = sst::USE_HMAC;
    sst::distribution_key_t crypto{};
    crypto.cipher_key_size = key.cipher_key_size;
    crypto.mac_key_size = key.mac_key_size;
    crypto.enc_mode = key.enc_mode;
    int sockets[2];
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    std::thread server([&] {
        SocketOwner peer{sockets[1]};
        auto first = IoTSPMessage::receive(peer.fd, 256);
        CHECK(static_cast<unsigned char>(first.get_type()) ==
              30);  // outer msgType
        CHECK(std::memcmp(first.get_payload().data(), key.key_id, 8) == 0);
        Bytes body = decrypt(crypto, Bytes(first.get_payload().begin() + 8,
                                           first.get_payload().end()));
        CHECK(body.size() == 9 && body[0] == 0x01);  // inner nonce-present flag
        Bytes reply{0x03};
        reply.insert(reply.end(), 8, 0x55);
        reply.insert(reply.end(), body.begin() + 1, body.end());
        send_frame(peer.fd, 31, encrypt(crypto, reply));
        auto third = IoTSPMessage::receive(peer.fd, 256);
        CHECK(static_cast<unsigned char>(third.get_type()) == 32);
        Bytes final_body = decrypt(crypto, third.get_payload());
        // Preserve C's two-nonce handshake 3 body (Node sends replyNonce only).
        CHECK(final_body.size() == 17 && final_body[0] == 0x03);
        CHECK(std::memcmp(final_body.data() + 1, body.data() + 1, 8) == 0);
        CHECK(std::memcmp(final_body.data() + 9, reply.data() + 1, 8) == 0);
    });
    auto session =
        sst::SST_API::secure_connect_to_server_with_socket(key, sockets[0]);
    CHECK(session && sst::is_session_key_valid(session->get_session_key()));
    server.join();
}

}  // namespace

int main() {
    test_auth_exchanges();
    test_handshake_msg_type_and_flags();
    std::puts("All protocol regression tests passed.");
}
