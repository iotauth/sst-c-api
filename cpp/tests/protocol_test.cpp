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

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "api.hpp"
#include "api_internal.hpp"
#include "message/iotsp_message.hpp"
#include "net/sockets.hpp"
#include "temporary_directory.hpp"

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

using SocketOwner = sst::internal::FdGuard;

void number(Bytes& bytes, uint64_t value, int length) {
    for (int i = length - 1; i >= 0; --i) {
        bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void string(Bytes& bytes, std::string_view value) {
    size_t length = value.size();
    do {
        const auto next = static_cast<std::byte>(length & 0x7f);
        length >>= 7;
        bytes.push_back(std::to_integer<unsigned char>(
            next | (length ? std::byte{0x80} : std::byte{0})));
    } while (length);
    bytes.insert(bytes.end(), value.begin(), value.end());
}

void send_frame(int fd, unsigned char msg_type, const Bytes& payload) {
    Bytes wire{msg_type};
    size_t length = payload.size();
    do {
        const auto next = static_cast<std::byte>(length & 0x7f);
        length >>= 7;
        wire.push_back(std::to_integer<unsigned char>(
            next | (length ? std::byte{0x80} : std::byte{0})));
    } while (length);
    wire.insert(wire.end(), payload.begin(), payload.end());
    CHECK(sst::internal::sst_write_to_socket(fd, wire.data(), wire.size()) ==
          static_cast<int>(wire.size()));
}

Bytes encrypt(const sst::distribution_key_t& key, const Bytes& plain) {
    Bytes encrypted;
    CHECK(sst::internal::symmetric_encrypt_authenticate(
              plain.data(), plain.size(),
              {key.mac_key, key.mac_key_size, key.cipher_key,
               key.cipher_key_size, key.enc_mode, sst::USE_HMAC},
              encrypted) == 0);
    return encrypted;
}

Bytes decrypt(const sst::distribution_key_t& key, const Bytes& encrypted) {
    Bytes plain;
    CHECK(sst::internal::symmetric_decrypt_authenticate(
              encrypted.data(), encrypted.size(),
              {key.mac_key, key.mac_key_size, key.cipher_key,
               key.cipher_key_size, key.enc_mode, sst::USE_HMAC},
              plain) == 0);
    return plain;
}

struct Credentials {
    sst::test::TemporaryDirectory temporary{"sst_protocol_test_"};
    Key auth{EVP_RSA_gen(2048), &EVP_PKEY_free};
    Key entity{EVP_RSA_gen(2048), &EVP_PKEY_free};
    sst::distribution_key_t dist{};
    const std::filesystem::path dir = temporary.path();

    Credentials() {
        CHECK(auth && entity);
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

void test_private_credential_directories() {
    std::filesystem::path first_dir;
    std::filesystem::path second_dir;
    {
        Credentials first;
        Credentials second;
        first_dir = first.dir;
        second_dir = second.dir;
        CHECK(first_dir != second_dir);
        for (const auto& dir : {first_dir, second_dir}) {
            const auto status = std::filesystem::symlink_status(dir);
            CHECK(std::filesystem::is_directory(status));
            using Perms = std::filesystem::perms;
            CHECK((status.permissions() &
                   (Perms::group_all | Perms::others_all)) == Perms::none);
        }
    }
    CHECK(!std::filesystem::exists(first_dir));
    CHECK(!std::filesystem::exists(second_dir));
}

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
    CHECK(peer.get() >= 0);
    const std::array<unsigned char, 8> auth_nonce{1, 2, 3, 4, 5, 6, 7, 8};
    Bytes hello;
    number(hello, 101, 4);
    hello.insert(hello.end(), auth_nonce.begin(), auth_nonce.end());
    send_frame(peer.get(), 0, hello);
    IoTSPMessage request = IoTSPMessage::receive(peer.get(), 4096);
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
    Bytes expected_body(16);
    std::copy_n(plain.begin(), 8, expected_body.begin());
    std::copy(auth_nonce.begin(), auth_nonce.end(), expected_body.begin() + 8);
    bool key_request =
        expected.request_type == 20 || expected.request_type == 22;
    if (key_request) number(expected_body, 10, 4);
    string(expected_body, "net1.client");
    string(expected_body, expected.purpose);
    CHECK(plain == expected_body);
    if (expected.alert) {
        send_frame(peer.get(), 100, Bytes{1});
        return;
    }
    Bytes response(plain.begin(), plain.begin() + 8);
    if (expected.wrong_nonce)
        response[0] = std::to_integer<unsigned char>(
            static_cast<std::byte>(response[0]) ^ std::byte{0xff});
    if (key_request) {
        string(response, R"({"cipher":"AES-128-CBC"})");
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
    const unsigned char key_response_type = public_key ? 21 : 23;
    const unsigned char reader_response_type = public_key ? 61 : 63;
    send_frame(peer.get(),
               key_request ? key_response_type : reader_response_type,
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
    std::thread auth([&listener, &credentials] {
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
    std::array<unsigned char, 8> id{0, 0, 0, 0, 0, 0, 0, 99};
    CHECK(api.get_session_key_by_ID(id.data(), list)->key_id[7] == 99);
    CHECK(api.get_session_key_by_ID(id.data(), list)->key_id[7] ==
          99);  // cache hit
    api.send_add_reader_req_via_TCP("reader");
    id[7] = 100;
    expect_error(sst::SST_ErrorCode::Protocol, [&api, &id, &list] {
        api.get_session_key_by_ID(id.data(), list);
    });
    CHECK(api.get_session_key().size() ==
          1);  // failed ID request leaves no sticky purpose
    expect_error(sst::SST_ErrorCode::Protocol,
                 [&api] { api.send_add_reader_req_via_TCP("bad-nonce"); });
    expect_error(sst::SST_ErrorCode::AuthRejected,
                 [&api] { api.send_add_reader_req_via_TCP("alert"); });
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
    std::array<int, 2> sockets{};
    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
    std::thread server([&sockets, &key, &crypto] {
        SocketOwner peer{sockets[1]};
        auto first = IoTSPMessage::receive(peer.get(), 256);
        CHECK(static_cast<unsigned char>(first.get_type()) ==
              30);  // outer msgType
        CHECK(std::memcmp(first.get_payload().data(), key.key_id, 8) == 0);
        Bytes body = decrypt(crypto, Bytes(first.get_payload().begin() + 8,
                                           first.get_payload().end()));
        CHECK(body.size() == 9 && body[0] == 0x01);  // inner nonce-present flag
        Bytes reply(17, 0x55);
        reply[0] = 0x03;
        std::copy(body.begin() + 1, body.end(), reply.begin() + 9);
        send_frame(peer.get(), 31, encrypt(crypto, reply));
        auto third = IoTSPMessage::receive(peer.get(), 256);
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

void test_empty_handshake_frames() {
    Credentials credentials;
    sst::SST_API api(credentials.config(0));
    sst::SessionKeyList keys;
    std::array<int, 2> sockets{};

    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
    send_frame(sockets[1], 30, {});
    expect_error(sst::SST_ErrorCode::Protocol, [&api, &sockets, &keys] {
        api.server_secure_comm_setup(sockets[0], keys);
    });
    ::close(sockets[1]);

    sst::session_key_t key{};
    key.key_id[7] = 42;
    key.abs_validity = UINT64_MAX;
    key.cipher_key_size = 16;
    key.mac_key_size = 32;
    key.enc_mode = sst::AES_128_CBC;
    key.hmac_mode = sst::USE_HMAC;
    sst::distribution_key_t crypto{};
    crypto.cipher_key_size = key.cipher_key_size;
    crypto.mac_key_size = key.mac_key_size;
    crypto.enc_mode = key.enc_mode;

    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
    std::thread empty_handshake2([&sockets] {
        SocketOwner peer{sockets[1]};
        IoTSPMessage::receive(peer.get(), 256);
        send_frame(peer.get(), 31, {});
    });
    expect_error(sst::SST_ErrorCode::Protocol, [&key, &sockets] {
        sst::SST_API::secure_connect_to_server_with_socket(key, sockets[0]);
    });
    empty_handshake2.join();

    keys.add(key);
    Bytes handshake1(key.key_id, key.key_id + sst::SESSION_KEY_ID_SIZE);
    Bytes body(9, 0x55);
    body[0] = 0x01;
    Bytes encrypted = encrypt(crypto, body);
    handshake1.insert(handshake1.end(), encrypted.begin(), encrypted.end());

    CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
    std::thread empty_handshake3([&sockets, &handshake1] {
        SocketOwner peer{sockets[1]};
        send_frame(peer.get(), 30, handshake1);
        auto response = IoTSPMessage::receive(peer.get(), 256);
        CHECK(response.get_type() == MessageType::SKEY_HANDSHAKE_2);
        send_frame(peer.get(), 32, {});
    });
    expect_error(sst::SST_ErrorCode::Protocol, [&api, &sockets, &keys] {
        api.server_secure_comm_setup(sockets[0], keys);
    });
    empty_handshake3.join();
}

void test_handshake_body_validation() {
    Credentials credentials;
    sst::SST_API api(credentials.config(0));
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
    sst::SessionKeyList keys;
    // Server retrieves the key locally, without contacting Auth.
    keys.add(key);

    const auto first_payload = [&key, &crypto](const Bytes& body) {
        Bytes payload(key.key_id, key.key_id + sst::SESSION_KEY_ID_SIZE);
        const auto encrypted = encrypt(crypto, body);
        payload.insert(payload.end(), encrypted.begin(), encrypted.end());
        return payload;
    };
    const auto reject_first = [&api, &keys, &first_payload](const Bytes& body) {
        std::array<int, 2> sockets{};
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
        SocketOwner peer{sockets[1]};
        send_frame(peer.get(), 30, first_payload(body));
        CHECK(::shutdown(peer.get(), SHUT_WR) == 0);
        expect_error(sst::SST_ErrorCode::Protocol, [&api, &keys, &sockets] {
            api.server_secure_comm_setup(sockets[0], keys);
        });
    };
    const auto reject_second = [&key, &crypto](const Bytes& body) {
        std::array<int, 2> sockets{};
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
        std::thread server([&sockets, &crypto, &body] {
            SocketOwner peer{sockets[1]};
            IoTSPMessage::receive(peer.get(), 256);
            send_frame(peer.get(), 31, encrypt(crypto, body));
        });
        expect_error(sst::SST_ErrorCode::Protocol, [&key, &sockets] {
            sst::SST_API::secure_connect_to_server_with_socket(key, sockets[0]);
        });
        server.join();
    };
    const auto exchange_with_server = [&api, &keys, &crypto, &first_payload](
                                          size_t first_size,
                                          const Bytes& last_body, bool valid) {
        std::array<int, 2> sockets{};
        CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
        std::thread client(
            [&sockets, &crypto, &first_payload, first_size, &last_body] {
                SocketOwner peer{sockets[1]};
                Bytes first(first_size, 0x55);
                first[0] = 0x01;
                send_frame(peer.get(), 30, first_payload(first));
                const auto frame = IoTSPMessage::receive(peer.get(), 256);
                CHECK(frame.get_type() == MessageType::SKEY_HANDSHAKE_2);
                const auto second = decrypt(crypto, frame.get_payload());
                CHECK(second.size() == 17 && second[0] == 0x03);
                CHECK(std::memcmp(second.data() + 9, first.data() + 1, 8) == 0);
                Bytes third = last_body;
                if (third.size() >= 17) {
                    // replyNonce occupies bytes 9..16 even with flag 0x02
                    // alone.
                    std::memcpy(third.data() + 9, second.data() + 1, 8);
                }
                send_frame(peer.get(), 32, encrypt(crypto, third));
            });
        if (valid) {
            const auto session = api.server_secure_comm_setup(sockets[0], keys);
            CHECK(session &&
                  sst::is_session_key_valid(session->get_session_key()));
        } else {
            expect_error(sst::SST_ErrorCode::Protocol, [&api, &keys, &sockets] {
                api.server_secure_comm_setup(sockets[0], keys);
            });
        }
        client.join();
    };

    // These malformed plaintexts are encrypted and correctly MACed so they
    // reach the parser; rejecting an invalid MAC would not exercise this bug.
    for (size_t length = 0; length < 17; ++length) {
        Bytes body(length, 0x55);
        if (!body.empty()) body[0] = 0x03;
        reject_first(body);
        reject_second(body);
        exchange_with_server(9, body, false);
        if (!body.empty()) body[0] = 0x02;
        reject_first(body);
        exchange_with_server(9, body, false);
        if (length < 9) {
            if (!body.empty()) body[0] = 0x01;
            reject_first(body);
        }
    }
    reject_first(Bytes(17, 0));
    Bytes missing_reply(17, 0);
    missing_reply[0] = 0x01;
    reject_second(missing_reply);
    exchange_with_server(9, missing_reply, false);

    // Preserve both C's compact handshake 1 and Node's full-sized one, and
    // both the two-nonce (C) and reply-only (Node) forms of handshake 3.
    for (size_t first_size : {9, 17}) {
        Bytes third(17, 0x55);
        third[0] = 0x03;
        exchange_with_server(first_size, third, true);
        third[0] = 0x02;
        exchange_with_server(first_size, third, true);
    }
}

}  // namespace

int main() {
    test_private_credential_directories();
    test_auth_exchanges();
    test_handshake_msg_type_and_flags();
    test_empty_handshake_frames();
    test_handshake_body_validation();
    std::puts("All protocol regression tests passed.");
}
