/**
 * @file api.cpp
 * @brief Implementation of the SST C++ API (see api.hpp).
 *
 * Uses the SST C API wire formats. Variable-length protocol buffers use
 * std::vector; cryptographic operations write into caller-provided buffers.
 */

#include "api.hpp"

#include <errno.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

#include "api_internal.hpp"
#include "log/log_manager.hpp"
#include "message/add_reader_req_message.hpp"
#include "message/add_reader_resp_message.hpp"
#include "message/auth_alert_message.hpp"
#include "message/auth_hello_message.hpp"
#include "message/iotsp_message.hpp"
#include "message/session_key_req_message.hpp"
#include "message/session_key_resp_message.hpp"

namespace sst {

using internal::Bytes;
using message::IoTSPMessage;
using message::MessageType;

namespace {

// ---------------------------------------------------------------------------
// Protocol constants (mirror src/c_common.h and src/c_secure_comm.h)
// ---------------------------------------------------------------------------

constexpr unsigned int HS_NONCE_SIZE = 8;
constexpr unsigned int HS_NONCE_FIELDS_SIZE = 1 + HS_NONCE_SIZE * 2;
constexpr unsigned char HS_NONCE_PRESENT = 0x01;
constexpr unsigned char HS_REPLY_NONCE_PRESENT = 0x02;
constexpr unsigned int MAX_HS_BUF_LENGTH = 256;
constexpr unsigned int NONCE_SIZE = 8;
// Payload limit for Auth responses, excluding msgType and payloadLen.
// Keep 4096 rather than the C API's 1024: ten keys plus an RSA-encrypted
// distribution key/signature, cryptoSpec, IV, padding and MAC can exceed 1 KiB.
constexpr unsigned int MAX_AUTH_COMM_LENGTH = 4096;

// Each peer sends a fresh nonce and proves key possession by echoing the other.
struct HS_nonce_t {
    unsigned char nonce[HS_NONCE_SIZE];
    unsigned char reply_nonce[HS_NONCE_SIZE];
};

// Closes a raw socket when leaving scope unless released.
class FdGuard {
   public:
    explicit FdGuard(int fd) : fd_(fd) {}
    ~FdGuard() {
        if (fd_ >= 0) ::close(fd_);
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    int get() const { return fd_; }
    int release() {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

   private:
    int fd_;
};

// ---------------------------------------------------------------------------
// Byte helpers (c_common.c)
// ---------------------------------------------------------------------------

std::string to_hex(const unsigned char* buf, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; i++) {
        if (i != 0) oss << ' ';
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(buf[i]);
    }
    return oss.str();
}

}  // namespace

// ---------------------------------------------------------------------------
// Byte and socket helpers (c_common.c), shared via api_internal.hpp
// ---------------------------------------------------------------------------

namespace internal {

void write_in_n_bytes(uint64_t num, int n, unsigned char* buf) {
    for (int i = 0; i < n; i++) {
        buf[i] = static_cast<unsigned char>(num >> (8 * (n - 1 - i)));
    }
}

uint64_t read_unsigned_long_int_BE(const unsigned char* buf, int byte_length) {
    uint64_t num = 0;
    for (int i = 0; i < byte_length; i++) {
        num = (num << 8) | buf[i];
    }
    return num;
}

unsigned int read_unsigned_int_BE(const unsigned char* buf, int byte_length) {
    return static_cast<unsigned int>(
        read_unsigned_long_int_BE(buf, byte_length));
}

void var_length_int_to_num(const unsigned char* buf, unsigned int buf_length,
                           unsigned int* num, int* var_len_int_buf_size) {
    *num = 0;
    *var_len_int_buf_size = 0;
    // A variable length integer never spans more than MAX_PAYLOAD_BUF_SIZE
    // bytes; anything longer is malformed and leaves the size at 0.
    unsigned int limit = std::min(buf_length, MAX_PAYLOAD_BUF_SIZE);
    for (unsigned int i = 0; i < limit; i++) {
        *num |= static_cast<unsigned int>(buf[i] & 127) << (7 * i);
        if ((buf[i] & 128) == 0) {
            *var_len_int_buf_size = static_cast<int>(i + 1);
            break;
        }
    }
}

void num_to_var_length_int(unsigned int num, unsigned char* var_len_int_buf,
                           unsigned int* var_len_int_buf_size) {
    *var_len_int_buf_size = 1;
    while (num > 127) {
        var_len_int_buf[*var_len_int_buf_size - 1] =
            static_cast<unsigned char>(128 | (num & 127));
        *var_len_int_buf_size += 1;
        num >>= 7;
    }
    var_len_int_buf[*var_len_int_buf_size - 1] =
        static_cast<unsigned char>(num);
}

int sst_read_from_socket(int sock, unsigned char* buf,
                         unsigned int buf_length) {
    if (sock < 0) {
        errno = EBADF;
        return -1;
    }
    ssize_t length_read = ::read(sock, buf, buf_length);
    if (length_read < 0) {
        LOG_ERR << "Reading from socket " << sock
                << " failed: " << std::strerror(errno);
    } else if (length_read == 0) {
        LOG_DBG << "Connection closed from socket " << sock << ".";
    }
    return static_cast<int>(length_read);
}

int sst_write_to_socket(int sock, const unsigned char* buf,
                        unsigned int buf_length) {
    if (sock < 0) {
        errno = EBADF;
        return -1;
    }
    // Never raise SIGPIPE when the peer has gone away: report -1 instead.
#ifdef MSG_NOSIGNAL
    const int send_flags = MSG_NOSIGNAL;
#else
    const int send_flags = 0;
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                 sizeof(no_sigpipe));
#endif
#endif
    unsigned int total_written = 0;
    while (total_written < buf_length) {
        ssize_t length_written = ::send(sock, buf + total_written,
                                        buf_length - total_written, send_flags);
        if (length_written < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            continue;
        }
        if (length_written < 0) {
            LOG_ERR << "Writing to socket " << sock
                    << " failed: " << std::strerror(errno);
            return -1;
        } else if (length_written == 0) {
            LOG_ERR << "Connection from socket " << sock
                    << " closed while writing.";
            return -1;
        }
        total_written += static_cast<unsigned int>(length_written);
    }
    return static_cast<int>(total_written);
}

int read_exact(int sock, unsigned char* buf, unsigned int length) {
    unsigned int total_read = 0;
    while (total_read < length) {
        int bytes_read =
            sst_read_from_socket(sock, buf + total_read, length - total_read);
        if (bytes_read < 0) {
            return -1;
        }
        if (bytes_read == 0) {
            return total_read == 0 ? 0 : -1;
        }
        total_read += static_cast<unsigned int>(bytes_read);
    }
    return static_cast<int>(total_read);
}

int connect_as_client(const char* ip_addr, int port_num) {
    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr) != 1) {
        LOG_ERR << "Invalid IPv4 address: " << ip_addr;
        return -1;
    }
    serv_addr.sin_port = htons(static_cast<uint16_t>(port_num));

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        LOG_ERR << "socket() error: " << std::strerror(errno);
        return -1;
    }
    int count_retries = 0;
    int ret = -1;
    // FIXME: Make the maximum number of retries configurable.
    while (count_retries++ < 10) {
        ret = ::connect(sock, reinterpret_cast<struct sockaddr*>(&serv_addr),
                        sizeof(serv_addr));
        if (ret == 0) {
            LOG_DBG << "Successfully connected to " << ip_addr << ":"
                    << port_num << " on attempt " << count_retries << ".";
            break;
        }
        if (errno == EINTR) {
            LOG_ERR << "connect interrupted (EINTR). Retrying...";
            continue;
        }
        LOG_ERR << "Connection attempt " << count_retries << " to " << ip_addr
                << ":" << port_num << " failed: " << std::strerror(errno)
                << ". Retrying...";
        ::close(sock);
        sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            LOG_ERR << "socket() error during retry";
            return -1;
        }
        ::usleep(50000);
    }
    if (ret < 0) {
        LOG_ERR << "Failed to connect to " << ip_addr << ":" << port_num
                << " after " << (count_retries - 1) << " attempts.";
        ::close(sock);
        return -1;
    }
    return sock;
}

}  // namespace internal

using internal::connect_as_client;
using internal::read_unsigned_int_BE;
using internal::read_unsigned_long_int_BE;
using internal::sst_write_to_socket;
using internal::write_in_n_bytes;

namespace {

// Writes a whole byte vector.
int write_bytes_to_socket(int sock, const Bytes& buf) {
    return sst_write_to_socket(sock, buf.data(),
                               static_cast<unsigned int>(buf.size()));
}

// ---------------------------------------------------------------------------
// Handshake helpers (c_common.c)
// ---------------------------------------------------------------------------

// Decrypted handshake body: handshake_flags (1) + nonce (8) + replyNonce (8).
// These flags are the protocol's inner "indicator" bitmask. The outer frame
// starts with msgType, added separately by IoTSPMessage::serialize().
int serialize_handshake_body(const unsigned char* nonce,
                             const unsigned char* reply_nonce,
                             unsigned char* ret) {
    if (nonce == nullptr && reply_nonce == nullptr) {
        LOG_ERR << "Handshake should include at least one nonce.";
        return -1;
    }
    unsigned char handshake_flags = 0;
    if (nonce != nullptr) {
        handshake_flags |= HS_NONCE_PRESENT;
        std::memcpy(ret + 1, nonce, HS_NONCE_SIZE);
    }
    if (reply_nonce != nullptr) {
        handshake_flags |= HS_REPLY_NONCE_PRESENT;
        std::memcpy(ret + 1 + HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    ret[0] = handshake_flags;
    return 0;
}

void parse_handshake_body(const unsigned char* buf, HS_nonce_t& ret) {
    std::memset(&ret, 0, sizeof(ret));
    if ((buf[0] & HS_NONCE_PRESENT) != 0) {
        std::memcpy(ret.nonce, buf + 1, HS_NONCE_SIZE);
    }
    if ((buf[0] & HS_REPLY_NONCE_PRESENT) != 0) {
        std::memcpy(ret.reply_nonce, buf + 1 + HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers with vector outputs
// ---------------------------------------------------------------------------

uint64_t current_time_ms() {
    // Auth encodes expiration as Unix-epoch milliseconds. A steady_clock
    // timestamp has a different epoch and cannot be compared with these values.
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// @return true when abs_validity_ms is still in the future.
bool check_validity(uint64_t abs_validity_ms) {
    return current_time_ms() < abs_validity_ms;
}

}  // namespace

namespace internal {

bool is_distribution_key_valid(const distribution_key_t& dist_key) {
    return check_validity(dist_key.abs_validity);
}

int symmetric_encrypt_authenticate(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode, Bytes& ret) {
    unsigned int expected = Crypto::get_expected_encrypted_total_length(
        buf_length, AES_128_CBC_IV_SIZE, mac_key_size, enc_mode, hmac_mode);
    ret.assign(expected, 0);
    unsigned int ret_length = 0;
    if (Crypto::symmetric_encrypt_authenticate(
            buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
            AES_128_CBC_IV_SIZE, enc_mode, hmac_mode, ret.data(),
            &ret_length) < 0) {
        return -1;
    }
    ret.resize(ret_length);
    return 0;
}

bool check_encrypted_length(unsigned int buf_length, unsigned int mac_key_size,
                            AES_encryption_mode_t enc_mode,
                            hmac_mode_t hmac_mode) {
    unsigned int overhead = AES_128_CBC_IV_SIZE;
    if (hmac_mode == USE_HMAC) {
        overhead += mac_key_size;
    }
    if (enc_mode == AES_128_GCM) {
        overhead += AES_GCM_TAG_SIZE;
    }
    if (buf_length < overhead) {
        LOG_ERR << "Encrypted buffer too short: " << buf_length;
        return false;
    }
    unsigned int ciphertext_length = buf_length - overhead;
    if (enc_mode == AES_128_CBC &&
        (ciphertext_length == 0 ||
         ciphertext_length % AES_128_CBC_IV_SIZE != 0)) {
        LOG_ERR << "CBC ciphertext length is not a whole number of blocks: "
                << ciphertext_length;
        return false;
    }
    return true;
}

int symmetric_decrypt_authenticate(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode, Bytes& ret) {
    if (!check_encrypted_length(buf_length, mac_key_size, enc_mode,
                                hmac_mode)) {
        return -1;
    }
    unsigned int expected = Crypto::get_expected_decrypted_maximum_length(
        buf_length, AES_128_CBC_IV_SIZE, mac_key_size, enc_mode, hmac_mode);
    // One extra block: EVP_DecryptUpdate may emit a full block before the
    // padding is stripped by EVP_DecryptFinal_ex.
    ret.assign(expected + AES_128_CBC_IV_SIZE, 0);
    unsigned int ret_length = 0;
    if (Crypto::symmetric_decrypt_authenticate(
            buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
            AES_128_CBC_IV_SIZE, enc_mode, hmac_mode, ret.data(),
            &ret_length) < 0) {
        return -1;
    }
    ret.resize(ret_length);
    return 0;
}

}  // namespace internal

using internal::check_encrypted_length;
using internal::symmetric_decrypt_authenticate;
using internal::symmetric_encrypt_authenticate;

namespace {

// Session key handshake messages are always encrypted with CBC-sized IV and
// HMAC (hmac_mode 0 == USE_HMAC in the C API).
int handshake_encrypt(const unsigned char* buf, unsigned int buf_length,
                      const session_key_t& s_key, Bytes& ret) {
    return symmetric_encrypt_authenticate(
        buf, buf_length, s_key.mac_key, MAC_KEY_SIZE, s_key.cipher_key,
        CIPHER_KEY_SIZE, s_key.enc_mode, USE_HMAC, ret);
}

int handshake_decrypt(const unsigned char* buf, unsigned int buf_length,
                      const session_key_t& s_key, Bytes& ret) {
    return symmetric_decrypt_authenticate(
        buf, buf_length, s_key.mac_key, MAC_KEY_SIZE, s_key.cipher_key,
        CIPHER_KEY_SIZE, s_key.enc_mode, USE_HMAC, ret);
}

// SKEY_HANDSHAKE_1 payload: sessionKeyId (8) + Enc(handshake_flags + nonce).
// Preserve the C API's compact 9-byte body; no replyNonce slot is sent here.
Bytes make_handshake_1_payload(const session_key_t& s_key,
                               unsigned char* entity_nonce) {
    if (Crypto::generate_nonce(HS_NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.",
                            SST_ErrorCode::Crypto);
    }
    unsigned char handshake_body[1 + HS_NONCE_SIZE];
    handshake_body[0] = HS_NONCE_PRESENT;
    std::memcpy(handshake_body + 1, entity_nonce, HS_NONCE_SIZE);

    Bytes encrypted;
    if (handshake_encrypt(handshake_body, 1 + HS_NONCE_SIZE, s_key, encrypted) <
        0) {
        throw SST_Exception("Failed to encrypt handshake 1.",
                            SST_ErrorCode::Crypto);
    }
    Bytes ret;
    ret.reserve(SESSION_KEY_ID_SIZE + encrypted.size());
    ret.insert(ret.end(), s_key.key_id, s_key.key_id + SESSION_KEY_ID_SIZE);
    ret.insert(ret.end(), encrypted.begin(), encrypted.end());
    return ret;
}

// Client: verifies SKEY_HANDSHAKE_2 and builds SKEY_HANDSHAKE_3.
Bytes check_handshake_2_send_handshake_3(const unsigned char* data_buf,
                                         unsigned int data_buf_length,
                                         const unsigned char* entity_nonce,
                                         const session_key_t& s_key) {
    LOG_DBG << "Received session key handshake2!";
    Bytes decrypted;
    if (handshake_decrypt(data_buf, data_buf_length, s_key, decrypted) < 0 ||
        decrypted.size() < HS_NONCE_FIELDS_SIZE) {
        throw SST_Exception("Error during decryption in checking handshake2.",
                            SST_ErrorCode::Crypto);
    }
    HS_nonce_t hs;
    parse_handshake_body(decrypted.data(), hs);

    if (std::memcmp(hs.reply_nonce, entity_nonce, HS_NONCE_SIZE) != 0) {
        throw SST_Exception(
            "Comm init failed: server NOT verified, nonce NOT matched, "
            "disconnecting...",
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Server authenticated/authorized by solving nonce!";

    unsigned char buf[HS_NONCE_FIELDS_SIZE];
    std::memset(buf, 0, HS_NONCE_FIELDS_SIZE);
    if (serialize_handshake_body(entity_nonce, hs.nonce, buf) < 0) {
        throw SST_Exception("Failed serialize_handshake_body().",
                            SST_ErrorCode::Protocol);
    }
    Bytes ret;
    if (handshake_encrypt(buf, HS_NONCE_FIELDS_SIZE, s_key, ret) < 0) {
        throw SST_Exception("Error during encryption while send_handshake_3.",
                            SST_ErrorCode::Crypto);
    }
    return ret;
}

// Server: verifies SKEY_HANDSHAKE_1 and builds SKEY_HANDSHAKE_2.
Bytes check_handshake1_send_handshake2(const unsigned char* received_buf,
                                       unsigned int received_buf_length,
                                       unsigned char* server_nonce,
                                       const session_key_t& s_key) {
    if (received_buf_length <= SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.", SST_ErrorCode::Protocol);
    }
    Bytes decrypted;
    if (handshake_decrypt(received_buf + SESSION_KEY_ID_SIZE,
                          received_buf_length - SESSION_KEY_ID_SIZE, s_key,
                          decrypted) < 0 ||
        decrypted.size() < 1 + HS_NONCE_SIZE) {
        throw SST_Exception("Error during decrypting handshake1.",
                            SST_ErrorCode::Crypto);
    }
    HS_nonce_t hs;
    parse_handshake_body(decrypted.data(), hs);
    LOG_DBG << "Client's nonce: " << to_hex(hs.nonce, HS_NONCE_SIZE);

    if (Crypto::generate_nonce(HS_NONCE_SIZE, server_nonce) < 0) {
        throw SST_Exception("Failed to generate server nonce.",
                            SST_ErrorCode::Crypto);
    }
    LOG_DBG << "Server's nonce: " << to_hex(server_nonce, HS_NONCE_SIZE);

    unsigned char buf[HS_NONCE_FIELDS_SIZE];
    std::memset(buf, 0, HS_NONCE_FIELDS_SIZE);
    if (serialize_handshake_body(server_nonce, hs.nonce, buf) < 0) {
        throw SST_Exception("Failed serialize_handshake_body().",
                            SST_ErrorCode::Protocol);
    }
    Bytes ret;
    if (handshake_encrypt(buf, HS_NONCE_FIELDS_SIZE, s_key, ret) < 0) {
        throw SST_Exception("Error during encryption while sending handshake2.",
                            SST_ErrorCode::Crypto);
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Distribution key parsing (c_secure_comm.c)
// ---------------------------------------------------------------------------

// abs_validity (6) + cipher_key_size (1) + cipher_key + mac_key_size (1) +
// mac_key.
void parse_distribution_key(distribution_key_t& parsed,
                            const unsigned char* buf, size_t buf_length) {
    size_t cur_index = 0;
    if (buf_length < DIST_KEY_EXPIRATION_TIME_SIZE + 1) {
        throw SST_Exception("Distribution key buffer too short.",
                            SST_ErrorCode::Protocol);
    }
    parsed.abs_validity =
        read_unsigned_long_int_BE(buf, DIST_KEY_EXPIRATION_TIME_SIZE);
    cur_index += DIST_KEY_EXPIRATION_TIME_SIZE;

    unsigned int cipher_key_size = buf[cur_index];
    cur_index += 1;
    if (cipher_key_size > MAX_CIPHER_KEY_SIZE ||
        cur_index + cipher_key_size + 1 > buf_length) {
        throw SST_Exception("Invalid distribution cipher key size.",
                            SST_ErrorCode::Protocol);
    }
    parsed.cipher_key_size = cipher_key_size;
    std::memcpy(parsed.cipher_key, buf + cur_index, cipher_key_size);
    cur_index += cipher_key_size;

    unsigned int mac_key_size = buf[cur_index];
    cur_index += 1;
    if (mac_key_size > MAC_KEY_SIZE || cur_index + mac_key_size > buf_length) {
        throw SST_Exception("Invalid distribution MAC key size.",
                            SST_ErrorCode::Protocol);
    }
    parsed.mac_key_size = mac_key_size;
    std::memcpy(parsed.mac_key, buf + cur_index, mac_key_size);
}

// ---------------------------------------------------------------------------
// Auth connection helpers
// ---------------------------------------------------------------------------

int connect_to_auth(const config_t& config) {
    int sock = connect_as_client(config.auth_ip_addr, config.auth_port_num);
    if (sock < 0) {
        throw SST_Exception(std::string("Failed to connect to Auth at ") +
                                config.auth_ip_addr + ":" +
                                std::to_string(config.auth_port_num),
                            SST_ErrorCode::Network);
    }
    return sock;
}

// Reads the next message from Auth. An AUTH_ALERT is turned into an
// SST_Exception here, so every request flow handles alerts the same way.
IoTSPMessage receive_from_auth(int sock) {
    IoTSPMessage msg = IoTSPMessage::receive(sock, MAX_AUTH_COMM_LENGTH);
    if (msg.get_type() == MessageType::AUTH_ALERT) {
        throw SST_Exception(message::AuthAlertMessage(msg).describe(),
                            SST_ErrorCode::AuthRejected);
    }
    return msg;
}

// Reads AUTH_HELLO and checks that it comes from the configured Auth.
message::AuthHelloMessage receive_auth_hello(int sock, int expected_auth_id) {
    message::AuthHelloMessage hello(receive_from_auth(sock));
    if (hello.get_auth_id() != static_cast<uint32_t>(expected_auth_id)) {
        throw SST_Exception("Auth ID NOT matched. Received " +
                                std::to_string(hello.get_auth_id()) +
                                ", expected " +
                                std::to_string(expected_auth_id),
                            SST_ErrorCode::Protocol);
    }
    return hello;
}

void send_to_auth(int sock, const Bytes& wire) {
    if (write_bytes_to_socket(sock, wire) < 0) {
        throw SST_Exception("Failed to send request to Auth.",
                            SST_ErrorCode::Network);
    }
}

// ---------------------------------------------------------------------------
// Config file parsing (load_config.c)
// ---------------------------------------------------------------------------

void copy_config_value(char* dest, size_t dest_size, const std::string& value,
                       const std::string& key) {
    if (value.size() + 1 > dest_size) {
        throw SST_Exception("Config value too long for " + key + ": " + value,
                            SST_ErrorCode::Configuration);
    }
    std::memcpy(dest, value.c_str(), value.size() + 1);
}

AES_encryption_mode_t parse_enc_mode(const std::string& v,
                                     const std::string& key) {
    if (v == "AES_128_CBC") return AES_128_CBC;
    if (v == "AES_128_CTR") return AES_128_CTR;
    if (v == "AES_128_GCM") return AES_128_GCM;
    // Numeric form used by the earlier C++ config style.
    if (v == "0") return AES_128_CBC;
    if (v == "1") return AES_128_CTR;
    if (v == "2") return AES_128_GCM;
    throw SST_Exception("Wrong input for " + key +
                            ". Please type \"AES_128_CBC\", \"AES_128_CTR\" or "
                            "\"AES_128_GCM\".",
                        SST_ErrorCode::Configuration);
}

bool parse_on_off(const std::string& v, const std::string& key) {
    if (v == "on" || v == "1") return true;
    if (v == "off" || v == "0") return false;
    throw SST_Exception("Wrong input for " + key +
                            ". Please type \"on\"/\"1\" or \"off\"/\"0\".",
                        SST_ErrorCode::Configuration);
}

int parse_int(const std::string& v, const std::string& key) {
    try {
        size_t consumed = 0;
        int parsed = std::stoi(v, &consumed);
        if (consumed != v.size())
            throw std::invalid_argument("trailing characters");
        return parsed;
    } catch (const std::exception&) {
        throw SST_Exception("Invalid integer for " + key + ": " + v,
                            SST_ErrorCode::Configuration);
    }
}

int parse_port(const std::string& v, const std::string& key) {
    int port = parse_int(v, key);
    if (port < 0 || port > 65535) {
        throw SST_Exception("Invalid port number for " + key + ": " + v,
                            SST_ErrorCode::Configuration);
    }
    return port;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

template <auto Field, auto Parse>
void set_config_value(config_t& config, const std::string& value,
                      const std::string& key) {
    config.*Field = Parse(value, key);
}

template <auto Field>
void set_config_string(config_t& config, const std::string& value,
                       const std::string& key) {
    auto& destination = config.*Field;
    copy_config_value(destination, sizeof(destination), value, key);
}

template <int Index>
void set_config_purpose(config_t& config, const std::string& value,
                        const std::string& key) {
    copy_config_value(config.purpose[Index], sizeof(config.purpose[Index]),
                      value, key);
}

unsigned short parse_purpose_index(const std::string& value,
                                   const std::string& key) {
    int index = parse_int(value, key);
    if (index < 0 || index > 1) {
        throw SST_Exception("purpose_index must be 0 or 1, got " + value,
                            SST_ErrorCode::Configuration);
    }
    return static_cast<unsigned short>(index);
}

hmac_mode_t parse_hmac_mode(const std::string& value, const std::string& key) {
    return parse_on_off(value, key) ? USE_HMAC : NO_HMAC;
}

perm_dist_key_mode_t parse_perm_dist_key_mode(const std::string& value,
                                              const std::string& key) {
    return parse_on_off(value, key) ? USE_PERMANENT_DIST_KEY
                                    : NO_PERMANENT_DIST_KEY;
}

struct ConfigField {
    const char* name;
    const char* alias;
    void (*set)(config_t&, const std::string&, const std::string&);
};

// Each alias uses the same destination and validator as its canonical name.
const ConfigField config_fields[] = {
    {"entityInfo.name", "name", set_config_string<&config_t::name>},
    {"purpose[0]", nullptr, set_config_purpose<0>},
    {"purpose[1]", nullptr, set_config_purpose<1>},
    {"purpose_index", nullptr,
     set_config_value<&config_t::purpose_index, parse_purpose_index>},
    {"entityInfo.number_key", "numkey",
     set_config_value<&config_t::numkey, parse_int>},
    {"sessionKey.encryptionMode", "session_key_enc_mode",
     set_config_value<&config_t::session_key_enc_mode, parse_enc_mode>},
    {"distKey.encryptionMode", "dist_key_enc_mode",
     set_config_value<&config_t::dist_key_enc_mode, parse_enc_mode>},
    {"HmacMode", "hmac_mode",
     set_config_value<&config_t::hmac_mode, parse_hmac_mode>},
    {"PermanentDistKeyMode", "perm_dist_key_mode",
     set_config_value<&config_t::perm_dist_key_mode, parse_perm_dist_key_mode>},
    {"authInfo.id", "auth_id", set_config_value<&config_t::auth_id, parse_int>},
    {"authInfo.pubkey.path", "auth_pubkey_path",
     set_config_string<&config_t::auth_pubkey_path>},
    {"entityInfo.privkey.path", "entity_privkey_path",
     set_config_string<&config_t::entity_privkey_path>},
    {"auth.ip.address", "auth_ip_addr",
     set_config_string<&config_t::auth_ip_addr>},
    {"auth.port.number", "auth_port_num",
     set_config_value<&config_t::auth_port_num, parse_port>},
    {"entity.server.ip.address", "entity_server_ip_addr",
     set_config_string<&config_t::entity_server_ip_addr>},
    {"entity.server.port.number", "entity_server_port_num",
     set_config_value<&config_t::entity_server_port_num, parse_port>},
    {"network.protocol", nullptr,
     set_config_string<&config_t::network_protocol>},
    {"fileSystemManager.ip.address", nullptr,
     set_config_string<&config_t::file_system_manager_ip_addr>},
    {"fileSystemManager.port.number", nullptr,
     set_config_value<&config_t::file_system_manager_port_num, parse_port>},
    {"distKey.cipherkey.path", nullptr,
     set_config_string<&config_t::dist_cipher_key_path>},
    {"distkey.mackey.path", nullptr,
     set_config_string<&config_t::dist_mac_key_path>},
};

// Parses the SST config file. Accepts the C API key names
// (entityInfo.name=...) and, for compatibility, the earlier C++ key names
// (name = ...).
void load_config(config_t& c, const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (errno == ENOENT) {
            throw SST_Exception("SST Config file not found on path " + path,
                                SST_ErrorCode::Configuration);
        } else if (errno == EACCES) {
            throw SST_Exception(
                "SST Config file permission denied on path " + path,
                SST_ErrorCode::Configuration);
        }
        throw SST_Exception("SST Config file open failed on path " + path,
                            SST_ErrorCode::Configuration);
    }
    c = config_t{};
    unsigned short purpose_count = 0;
    c.purpose_index = 0;
    c.hmac_mode = USE_HMAC;
    c.perm_dist_key_mode = NO_PERMANENT_DIST_KEY;
    c.session_key_enc_mode = AES_128_CBC;
    c.dist_key_enc_mode = AES_128_CBC;
    copy_config_value(c.network_protocol, sizeof(c.network_protocol), "TCP",
                      "network.protocol");

    LOG_DBG << "-----SST configuration of " << path << ".-----";
    std::string line;
    while (std::getline(file, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        size_t eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) {
            throw SST_Exception("Config line without '=': " + trimmed,
                                SST_ErrorCode::Configuration);
        }
        std::string key = trim(trimmed.substr(0, eq_pos));
        std::string value = trim(trimmed.substr(eq_pos + 1));
        if (value.empty()) {
            throw SST_Exception("Config value does not exist for " + key,
                                SST_ErrorCode::Configuration);
        }

        // Repeated purpose entries are ordered; all other fields are
        // table-driven.
        if (key == "entityInfo.purpose") {
            if (purpose_count >= 2) {
                throw SST_Exception(
                    "At most two entityInfo.purpose entries are supported.",
                    SST_ErrorCode::Configuration);
            }
            copy_config_value(c.purpose[purpose_count],
                              sizeof(c.purpose[purpose_count]), value, key);
            c.purpose_index = purpose_count++;
            continue;
        }
        const auto* field = std::find_if(
            std::begin(config_fields), std::end(config_fields),
            [&key](const ConfigField& entry) {
                return key == entry.name || (entry.alias && key == entry.alias);
            });
        if (field == std::end(config_fields)) {
            throw SST_Exception("Unknown config type " + key + ".",
                                SST_ErrorCode::Configuration);
        }
        field->set(c, value, key);
    }

    if (c.perm_dist_key_mode == NO_PERMANENT_DIST_KEY) {
        if (std::strlen(c.dist_cipher_key_path) > 0 ||
            std::strlen(c.dist_mac_key_path) > 0) {
            throw SST_Exception(
                "PermanentDistKeyMode is turned off, but dist_key path(s) are "
                "provided.",
                SST_ErrorCode::Configuration);
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

uint64_t convert_skid_buf_to_int(const unsigned char* buf, int byte_length) {
    return read_unsigned_long_int_BE(buf, byte_length);
}

void update_validity(session_key_t& session_key) {
    session_key.abs_validity = current_time_ms() + session_key.rel_validity;
}

bool is_session_key_valid(const session_key_t& session_key) {
    return check_validity(session_key.abs_validity);
}

// ---------------------------------------------------------------------------
// SessionKeyList
// ---------------------------------------------------------------------------

int SessionKeyList::find(uint64_t key_id) const {
    // Walk the ring from the oldest key so that slots left behind by dropped
    // or overwritten keys are never matched.
    const int max = static_cast<int>(MAX_SESSION_KEY);
    for (int i = 0; i < num_key; i++) {
        int idx = (i + rear_idx - num_key) % max;
        if (idx < 0) idx += max;
        if (convert_skid_buf_to_int(s_key[static_cast<size_t>(idx)].key_id,
                                    SESSION_KEY_ID_SIZE) == key_id) {
            return idx;
        }
    }
    return -1;
}

const session_key_t& SessionKeyList::at(size_t index) const {
    if (index >= static_cast<size_t>(num_key)) {
        throw SST_Exception("Session key index out of range.",
                            SST_ErrorCode::InvalidArgument);
    }
    int slot = (rear_idx - num_key + static_cast<int>(MAX_SESSION_KEY) +
                static_cast<int>(index)) %
               static_cast<int>(MAX_SESSION_KEY);
    return s_key[static_cast<size_t>(slot)];
}

session_key_t& SessionKeyList::at(size_t index) {
    return const_cast<session_key_t&>(std::as_const(*this).at(index));
}

const session_key_t& SessionKeyList::at_slot(int slot) const {
    const int max = static_cast<int>(MAX_SESSION_KEY);
    if (slot < 0 || slot >= max ||
        (slot - rear_idx + num_key + max) % max >= num_key) {
        throw SST_Exception("Session key slot is not active.",
                            SST_ErrorCode::InvalidArgument);
    }
    return s_key[static_cast<size_t>(slot)];
}

session_key_t& SessionKeyList::at_slot(int slot) {
    return const_cast<session_key_t&>(std::as_const(*this).at_slot(slot));
}

int SessionKeyList::add(const session_key_t& key) {
    num_key++;
    if (num_key > static_cast<int>(MAX_SESSION_KEY)) {
        LOG_DBG << "Warning: Session_key_list is full. Deleting oldest key, "
                   "and adding new key.";
        num_key = MAX_SESSION_KEY;
    }
    int index = rear_idx;
    s_key[static_cast<size_t>(index)] = key;
    rear_idx = (rear_idx + 1) % static_cast<int>(MAX_SESSION_KEY);
    return index;
}

void SessionKeyList::append(const SessionKeyList& src) {
    if (this == &src) {
        const SessionKeyList snapshot = src;
        append(snapshot);
        return;
    }
    const int max = static_cast<int>(MAX_SESSION_KEY);
    if (num_key + src.num_key > max) {
        int lost = num_key + src.num_key - max;
        LOG_DBG << "Warning: Losing " << lost
                << " keys from original list. Overwriting " << lost
                << " more keys.";
    }
    for (int i = 0; i < src.num_key; i++) {
        int idx = (i + src.rear_idx - src.num_key) % max;
        if (idx < 0) idx += max;
        add(src.s_key[static_cast<size_t>(idx)]);
    }
}

bool SessionKeyList::addable(int requested_num_key) {
    if (requested_num_key < 0 ||
        requested_num_key > static_cast<int>(MAX_SESSION_KEY)) {
        return false;
    }
    const int max = static_cast<int>(MAX_SESSION_KEY);
    int deficit = requested_num_key - (max - num_key);
    if (deficit <= 0) {
        return true;
    }
    if (deficit > num_key) {
        return false;
    }
    // Only the oldest keys can be dropped without disturbing the ring order,
    // so exactly `deficit` of them must all be expired. Nothing is modified
    // unless the request can be satisfied.
    for (int i = 0; i < deficit; i++) {
        int idx = (i + rear_idx - num_key) % max;
        if (idx < 0) idx += max;
        if (is_session_key_valid(s_key[static_cast<size_t>(idx)])) {
            return false;
        }
    }
    num_key -= deficit;
    return true;
}

// ---------------------------------------------------------------------------
// SST_Session
// ---------------------------------------------------------------------------

SST_Session::SST_Session(int sock, const session_key_t& s_key)
    : sock_(sock), s_key_(s_key) {}

SST_Session::~SST_Session() {
    if (sock_ >= 0) {
        ::close(sock_);
    }
}

void SST_Session::shutdown() {
    if (sock_ >= 0) {
        ::shutdown(sock_, SHUT_RDWR);
    }
}

int SST_Session::send_secure_message(const std::string& msg) {
    return send_secure_message_result(msg).legacy_value();
}

int SST_Session::send_secure_message(const unsigned char* msg,
                                     unsigned int length) {
    return send_secure_message_result(msg, length).legacy_value();
}

int SST_Session::read_secure_message(unsigned char* plaintext,
                                     unsigned int capacity) {
    return read_secure_message_result(plaintext, capacity).legacy_value();
}

SST_IOResult SST_Session::send_secure_message_result(const std::string& msg) {
    if (msg.size() > MAX_PAYLOAD_LENGTH) {
        return SST_IOResult::failure(SST_ErrorCode::InvalidArgument);
    }
    return send_secure_message_result(
        reinterpret_cast<const unsigned char*>(msg.data()),
        static_cast<unsigned int>(msg.size()));
}

SST_IOResult SST_Session::send_secure_message_result(const unsigned char* msg,
                                                     unsigned int msg_length) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    if (msg_length > MAX_PAYLOAD_LENGTH || (!msg && msg_length != 0)) {
        LOG_ERR << "Invalid message buffer or length: " << msg_length;
        return SST_IOResult::failure(SST_ErrorCode::InvalidArgument);
    }
    if (!is_session_key_valid(s_key_)) {
        LOG_ERR << "Session key expired!";
        return SST_IOResult::failure(SST_ErrorCode::KeyExpired);
    }
    // Encrypt the sequence number with the payload so authentication also
    // protects message ordering. Each direction has its own counter.
    Bytes buf(SEQ_NUM_SIZE + msg_length, 0);
    write_in_n_bytes(sent_seq_num_, SEQ_NUM_SIZE, buf.data());
    if (msg_length != 0)
        std::memcpy(buf.data() + SEQ_NUM_SIZE, msg, msg_length);

    unsigned int expected_length = Crypto::get_expected_encrypted_total_length(
        static_cast<unsigned int>(buf.size()), AES_128_IV_SIZE,
        MAC_KEY_SHA256_SIZE, s_key_.enc_mode, s_key_.hmac_mode);
    Bytes encrypted(expected_length, 0);
    unsigned int encrypted_length = 0;
    if (SST_API::encrypt_buf_with_session_key(
            s_key_, buf.data(), static_cast<unsigned int>(buf.size()),
            encrypted.data(), &encrypted_length) < 0) {
        LOG_ERR << "Failed to encrypt_buf_with_session_key().";
        return SST_IOResult::failure(SST_ErrorCode::Crypto);
    }
    sent_seq_num_++;
    encrypted.resize(encrypted_length);
    Bytes sender =
        IoTSPMessage(MessageType::SECURE_COMM_MSG, std::move(encrypted))
            .serialize();
    int bytes_written = write_bytes_to_socket(sock_, sender);
    if (bytes_written < 0) {
        LOG_ERR << "Failed sst_write_to_socket().";
        return SST_IOResult::failure(SST_ErrorCode::Network);
    }
    return SST_IOResult::success(static_cast<unsigned int>(bytes_written));
}

SST_IOResult SST_Session::read_secure_message_result(
    unsigned char* plaintext, unsigned int plaintext_capacity) {
    std::lock_guard<std::mutex> lock(recv_mutex_);
    if (!plaintext && plaintext_capacity != 0) {
        return SST_IOResult::failure(SST_ErrorCode::InvalidArgument);
    }
    MessageType message_type;
    Bytes received;
    SST_IOResult frame = IoTSPMessage::read_result(
        sock_, MAX_SECURE_COMM_MSG_LENGTH, message_type, received);
    if (!frame.ok()) return frame;
    if (message_type != MessageType::SECURE_COMM_MSG) {
        LOG_ERR << "Wrong message type " << message::to_string(message_type)
                << ", expected SECURE_COMM_MSG.";
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    Bytes decrypted;
    if (symmetric_decrypt_authenticate(
            received.data(), static_cast<unsigned int>(received.size()),
            s_key_.mac_key, MAC_KEY_SIZE, s_key_.cipher_key, CIPHER_KEY_SIZE,
            s_key_.enc_mode, s_key_.hmac_mode, decrypted) < 0) {
        LOG_ERR << "Failed to decrypt received message.";
        return SST_IOResult::failure(SST_ErrorCode::Crypto);
    }
    if (decrypted.size() < SEQ_NUM_SIZE) {
        LOG_ERR << "Decrypted message shorter than the sequence number.";
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    unsigned int received_seq_num =
        read_unsigned_int_BE(decrypted.data(), SEQ_NUM_SIZE);
    if (received_seq_num != received_seq_num_) {
        LOG_ERR << "Wrong sequence number expected. Got " << received_seq_num
                << ", expected " << received_seq_num_;
        return SST_IOResult::failure(SST_ErrorCode::Protocol);
    }
    if (!is_session_key_valid(s_key_)) {
        LOG_ERR << "Session key expired!";
        return SST_IOResult::failure(SST_ErrorCode::KeyExpired);
    }
    received_seq_num_++;
    LOG_DBG << "Received seq_num: " << received_seq_num << ".";

    unsigned int plaintext_length =
        static_cast<unsigned int>(decrypted.size()) - SEQ_NUM_SIZE;
    if (plaintext_length > plaintext_capacity) {
        LOG_ERR << "Plaintext buffer too small: need " << plaintext_length
                << ", have " << plaintext_capacity;
        return SST_IOResult::failure(SST_ErrorCode::BufferTooSmall);
    }
    if (plaintext_length != 0) {
        std::memcpy(plaintext, decrypted.data() + SEQ_NUM_SIZE,
                    plaintext_length);
    }
    return SST_IOResult::success(plaintext_length);
}

void SST_Session::receive_loop() {
    unsigned char data_buf[MAX_SECURE_COMM_MSG_LENGTH];
    while (true) {
        int data_buf_length = read_secure_message(data_buf, sizeof(data_buf));
        if (data_buf_length < 0) {
            LOG_ERR << "Failed to read_secure_message().";
            return;
        }
        if (data_buf_length == 0) {
            return;
        }
        LOG_INF << "Received: "
                << std::string(reinterpret_cast<const char*>(data_buf),
                               static_cast<size_t>(data_buf_length));
    }
}

// ---------------------------------------------------------------------------
// SST_API: construction
// ---------------------------------------------------------------------------

SST_API::SST_API(const std::string& config_path)
    : pub_key_(nullptr, &EVP_PKEY_free), priv_key_(nullptr, &EVP_PKEY_free) {
    // Suppress OpenSSL's atexit cleanup, as the C API does, so that messages
    // can still be sent from other atexit handlers.
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, nullptr);

    load_config(config_, config_path);

    if (config_.perm_dist_key_mode == NO_PERMANENT_DIST_KEY) {
        pub_key_.reset(Crypto::load_auth_public_key(config_.auth_pubkey_path));
        if (!pub_key_) {
            throw SST_Exception(
                std::string("Failed load_auth_public_key(). Given path: ") +
                    config_.auth_pubkey_path + ", config_path: " + config_path,
                SST_ErrorCode::KeyLoad);
        }
        priv_key_.reset(
            Crypto::load_entity_private_key(config_.entity_privkey_path));
        if (!priv_key_) {
            throw SST_Exception(
                std::string("Failed load_entity_private_key(). Given path: ") +
                    config_.entity_privkey_path +
                    ", config_path: " + config_path,
                SST_ErrorCode::KeyLoad);
        }
        // abs_validity 0 makes the distribution key invalid until Auth sends
        // one.
        dist_key_ = distribution_key_t{};
    } else {
        dist_key_ = distribution_key_t{};
        dist_key_.abs_validity = UINT64_MAX;
        dist_key_.enc_mode = config_.dist_key_enc_mode;
        load_permanent_distribution_key();
    }
    if (config_.numkey > static_cast<int>(MAX_SESSION_KEY)) {
        LOG_WRN << "Too much requests of session keys. The max number of "
                   "requestable session keys are "
                << MAX_SESSION_KEY;
    }
}

void SST_API::load_permanent_distribution_key() {
    if (std::strlen(config_.dist_cipher_key_path) == 0 ||
        std::strlen(config_.dist_mac_key_path) == 0) {
        throw SST_Exception(
            "PermanentDistKeyMode is on, so both distKey.cipherkey.path and "
            "distkey.mackey.path must be set.",
            SST_ErrorCode::Configuration);
    }
    {
        std::ifstream fp(config_.dist_cipher_key_path, std::ios::binary);
        if (!fp.is_open()) {
            throw SST_Exception(
                std::string("Failed to open dist_cipher_key_path: ") +
                    config_.dist_cipher_key_path,
                SST_ErrorCode::KeyLoad);
        }
        fp.read(reinterpret_cast<char*>(dist_key_.cipher_key), CIPHER_KEY_SIZE);
        if (static_cast<unsigned int>(fp.gcount()) != CIPHER_KEY_SIZE) {
            throw SST_Exception(
                std::string("Failed to read CIPHER_KEY_SIZE bytes from "
                            "dist_cipher_key_path: ") +
                    config_.dist_cipher_key_path,
                SST_ErrorCode::KeyLoad);
        }
        dist_key_.cipher_key_size = CIPHER_KEY_SIZE;
    }
    {
        std::ifstream fp(config_.dist_mac_key_path, std::ios::binary);
        if (!fp.is_open()) {
            throw SST_Exception(
                std::string("Failed to open dist_mac_key_path: ") +
                    config_.dist_mac_key_path,
                SST_ErrorCode::KeyLoad);
        }
        fp.read(reinterpret_cast<char*>(dist_key_.mac_key), MAC_KEY_SIZE);
        if (static_cast<unsigned int>(fp.gcount()) != MAC_KEY_SIZE) {
            throw SST_Exception(
                std::string("Failed to read MAC_KEY_SIZE bytes from "
                            "dist_mac_key_path: ") +
                    config_.dist_mac_key_path,
                SST_ErrorCode::KeyLoad);
        }
        dist_key_.mac_key_size = MAC_KEY_SIZE;
    }
}

// ---------------------------------------------------------------------------
// SST_API: session key requests
// ---------------------------------------------------------------------------

namespace {

const char* configured_purpose(const config_t& config, int purpose_index) {
    if (purpose_index < 0 || purpose_index > 1) {
        throw SST_Exception("Purpose index out of range.",
                            SST_ErrorCode::InvalidArgument);
    }
    return config.purpose[purpose_index];
}

}  // namespace

SessionKeyList SST_API::get_session_key_with_index(int purpose_index) {
    std::lock_guard<std::mutex> lock(mutex_);
    return request_session_keys_locked(
        configured_purpose(config_, purpose_index));
}

void SST_API::get_session_key_with_index(int purpose_index,
                                         SessionKeyList& existing_s_key_list) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* purpose = configured_purpose(config_, purpose_index);
    if (!existing_s_key_list.addable(config_.numkey)) {
        LOG_WRN << "The session key list is not addable.";
        return;
    }
    existing_s_key_list.append(request_session_keys_locked(purpose));
}

SessionKeyList SST_API::get_session_key() {
    return get_session_key_with_index(config_.purpose_index);
}

void SST_API::get_session_key(SessionKeyList& existing_s_key_list) {
    get_session_key_with_index(config_.purpose_index, existing_s_key_list);
}

session_key_t* SST_API::get_session_key_by_ID(
    const unsigned char* target_session_key_id,
    SessionKeyList& existing_s_key_list) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t target_id =
        convert_skid_buf_to_int(target_session_key_id, SESSION_KEY_ID_SIZE);
    int session_key_idx = existing_s_key_list.find(target_id);
    if (session_key_idx >= 0) {
        return &existing_s_key_list.at_slot(session_key_idx);
    }

    // Purpose is local to this request, including when Auth rejects it.
    SessionKeyList keys = request_session_keys_locked(
        "{\"keyId\":" + std::to_string(target_id) + "}", target_session_key_id);
    int index = existing_s_key_list.add(keys.at(0));
    return &existing_s_key_list.at_slot(index);
}

void SST_API::save_distribution_key(const Bytes& encrypted_dist_key) {
    // Enc_entityPubKey(dist key) (key_size) + Sign_authPrivKey(...)
    // (key_size).
    size_t key_size = encrypted_dist_key.size() / 2;
    const unsigned char* data_buf = encrypted_dist_key.data();
    if (Crypto::sha256_verify(data_buf, static_cast<unsigned int>(key_size),
                              data_buf + key_size, key_size,
                              pub_key_.get()) < 0) {
        throw SST_Exception("Failed sha256_verify() of distribution key.",
                            SST_ErrorCode::Crypto);
    }
    LOG_DBG << "Auth signature verified.";

    Bytes decrypted(key_size);
    size_t decrypted_length = decrypted.size();
    if (Crypto::private_decrypt(data_buf, key_size, RSA_PKCS1_OAEP_PADDING,
                                priv_key_.get(), decrypted.data(),
                                &decrypted_length) < 0) {
        throw SST_Exception("Failed private_decrypt() of distribution key.",
                            SST_ErrorCode::Crypto);
    }
    parse_distribution_key(dist_key_, decrypted.data(), decrypted_length);
    dist_key_.enc_mode = config_.dist_key_enc_mode;
}

size_t SST_API::entity_rsa_key_size() const {
    return priv_key_ ? static_cast<size_t>(EVP_PKEY_size(priv_key_.get())) : 0;
}

void SST_API::decrypt_auth_response(message::EntityRespMessage& resp,
                                    const unsigned char* entity_nonce) {
    if (resp.has_distribution_key()) {
        save_distribution_key(resp.get_encrypted_distribution_key());
    }
    resp.decrypt_and_parse(dist_key_, config_.session_key_enc_mode);
    LOG_DBG << "Reply nonce in response: "
            << to_hex(resp.get_entity_nonce().data(), NONCE_SIZE);
    if (std::memcmp(resp.get_entity_nonce().data(), entity_nonce, NONCE_SIZE) !=
        0) {
        throw SST_Exception(
            "Entity nonce in Auth response does not match the request.",
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Entity nonce in Auth response verified.";
}

template <class Request, class Response, class... Args>
Response SST_API::request_auth_locked(Args&&... args) {
    if (std::strcmp(config_.network_protocol, "TCP") != 0) {
        throw SST_Exception(std::string("Unsupported network protocol: ") +
                                config_.network_protocol,
                            SST_ErrorCode::Configuration);
    }
    FdGuard guard(connect_to_auth(config_));
    message::AuthHelloMessage hello =
        receive_auth_hello(guard.get(), config_.auth_id);
    unsigned char entity_nonce[NONCE_SIZE];
    if (Crypto::generate_nonce(NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.",
                            SST_ErrorCode::Crypto);
    }
    Request req(entity_nonce, hello.get_auth_nonce().data(),
                std::forward<Args>(args)...);
    send_to_auth(guard.get(), req.serialize_and_encrypt(
                                  dist_key_, pub_key_.get(), priv_key_.get()));
    Response resp(receive_from_auth(guard.get()), entity_rsa_key_size());
    decrypt_auth_response(resp, entity_nonce);
    return resp;
}

SessionKeyList SST_API::request_session_keys_locked(
    const std::string& purpose, const unsigned char* expected_key_id) {
    auto resp = request_auth_locked<message::SessionKeyReqMessage,
                                    message::SessionKeyRespMessage>(
        config_.numkey, config_.name, purpose);
    SessionKeyList keys = resp.get_session_keys();
    if (expected_key_id) {
        if (keys.empty()) {
            throw SST_Exception("Auth returned no session key.",
                                SST_ErrorCode::Protocol);
        }
        if (std::memcmp(keys.at(0).key_id, expected_key_id,
                        SESSION_KEY_ID_SIZE) != 0) {
            throw SST_Exception("Session key id is NOT as expected.",
                                SST_ErrorCode::Protocol);
        }
    }
    // Key modes come from the config, not the serialized SessionKey fields.
    for (int i = 0; i < keys.size(); i++) {
        session_key_t& key = keys.at(static_cast<size_t>(i));
        key.enc_mode = config_.session_key_enc_mode;
        key.hmac_mode = config_.hmac_mode;
        key.perm_dist_key_mode = config_.perm_dist_key_mode;
    }
    return keys;
}

void SST_API::send_add_reader_req_via_TCP(const std::string& add_reader) {
    std::lock_guard<std::mutex> lock(mutex_);
    request_auth_locked<message::AddReaderReqMessage,
                        message::AddReaderRespMessage>(config_.name,
                                                       add_reader);
    LOG_INF << "Add a file reader to the database.";
}

// ---------------------------------------------------------------------------
// SST_API: entity-to-entity handshake
// ---------------------------------------------------------------------------

std::unique_ptr<SST_Session> SST_API::secure_connect_to_server(
    session_key_t& s_key) {
    int sock = connect_as_client(config_.entity_server_ip_addr,
                                 config_.entity_server_port_num);
    if (sock < 0) {
        throw SST_Exception(
            std::string("Failed to connect to entity server at ") +
                config_.entity_server_ip_addr + ":" +
                std::to_string(config_.entity_server_port_num),
            SST_ErrorCode::Network);
    }
    return secure_connect_to_server_with_socket(s_key, sock);
}

std::unique_ptr<SST_Session> SST_API::secure_connect_to_server_with_socket(
    session_key_t& s_key, int sock) {
    FdGuard guard(sock);

    // Send handshake 1.
    unsigned char entity_nonce[HS_NONCE_SIZE];
    Bytes parsed = make_handshake_1_payload(s_key, entity_nonce);
    Bytes sender_HS_1 =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_1, std::move(parsed))
            .serialize();
    if (write_bytes_to_socket(sock, sender_HS_1) < 0) {
        throw SST_Exception("Failed to send handshake 1.",
                            SST_ErrorCode::Network);
    }

    // Receive handshake 2.
    MessageType message_type;
    Bytes received;
    int data_buf_length =
        IoTSPMessage::read(sock, MAX_HS_BUF_LENGTH, message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception(
            "Socket read error in secure_connect_to_server_with_socket().",
            SST_ErrorCode::Network);
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake2 in "
            "secure_connect_to_server_with_socket().",
            SST_ErrorCode::PeerClosed);
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_2) {
        throw SST_Exception(
            "Comm init failed: expected SKEY_HANDSHAKE_2, got " +
                message::to_string(message_type),
            SST_ErrorCode::Protocol);
    }

    // Send handshake 3.
    Bytes hs3 = check_handshake_2_send_handshake_3(
        received.data(), static_cast<unsigned int>(received.size()),
        entity_nonce, s_key);
    Bytes sender_HS_3 =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_3, std::move(hs3)).serialize();
    if (write_bytes_to_socket(sock, sender_HS_3) < 0) {
        throw SST_Exception("Failed to send handshake 3.",
                            SST_ErrorCode::Network);
    }
    update_validity(s_key);
    LOG_DBG << "Switching to IN_COMM.";
    return std::make_unique<SST_Session>(guard.release(), s_key);
}

std::unique_ptr<SST_Session> SST_API::server_secure_comm_setup(
    int clnt_sock, SessionKeyList& existing_s_key_list) {
    FdGuard guard(clnt_sock);

    // Receive handshake 1.
    MessageType message_type;
    Bytes received;
    int data_buf_length = IoTSPMessage::read(clnt_sock, MAX_HS_BUF_LENGTH,
                                             message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().",
                            SST_ErrorCode::Network);
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake1 in "
            "server_secure_comm_setup().",
            SST_ErrorCode::PeerClosed);
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_1) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_1, got " +
                message::to_string(message_type),
            SST_ErrorCode::Protocol);
    }
    if (received.size() < SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.", SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Received session key handshake1.";

    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    std::memcpy(target_session_key_id, received.data(), SESSION_KEY_ID_SIZE);
    session_key_t* s_key =
        get_session_key_by_ID(target_session_key_id, existing_s_key_list);

    // Send handshake 2.
    unsigned char server_nonce[HS_NONCE_SIZE];
    Bytes hs2 = check_handshake1_send_handshake2(
        received.data(), static_cast<unsigned int>(received.size()),
        server_nonce, *s_key);
    Bytes sender =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_2, std::move(hs2)).serialize();
    if (write_bytes_to_socket(clnt_sock, sender) < 0) {
        throw SST_Exception("Failed to send handshake 2.",
                            SST_ErrorCode::Network);
    }
    LOG_DBG << "Switching to HANDSHAKE_2_SENT.";

    // Receive handshake 3.
    data_buf_length = IoTSPMessage::read(clnt_sock, MAX_HS_BUF_LENGTH,
                                         message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().",
                            SST_ErrorCode::Network);
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake3 in "
            "server_secure_comm_setup().",
            SST_ErrorCode::PeerClosed);
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_3) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_3, got " +
                message::to_string(message_type),
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Received session key handshake3!";
    Bytes decrypted;
    if (handshake_decrypt(received.data(),
                          static_cast<unsigned int>(received.size()), *s_key,
                          decrypted) < 0 ||
        decrypted.size() < HS_NONCE_FIELDS_SIZE) {
        throw SST_Exception(
            "Error during decryption in HANDSHAKE_2_SENT state.",
            SST_ErrorCode::Crypto);
    }
    HS_nonce_t hs;
    parse_handshake_body(decrypted.data(), hs);
    if (std::memcmp(hs.reply_nonce, server_nonce, HS_NONCE_SIZE) != 0) {
        throw SST_Exception(
            "Comm init failed: client NOT verified, nonce NOT matched, "
            "disconnecting...",
            SST_ErrorCode::Protocol);
    }
    LOG_DBG << "Client authenticated/authorized by solving nonce!";
    update_validity(*s_key);
    LOG_DBG << "Switching to IN_COMM.";
    return std::make_unique<SST_Session>(guard.release(), *s_key);
}

// ---------------------------------------------------------------------------
// SST_API: buffer encryption with a session key
// ---------------------------------------------------------------------------

int SST_API::encrypt_buf_with_session_key(const session_key_t& s_key,
                                          const unsigned char* plaintext,
                                          unsigned int plaintext_length,
                                          unsigned char* encrypted,
                                          unsigned int* encrypted_length) {
    if (!is_session_key_valid(s_key)) {
        LOG_ERR << "Session key is expired.";
        return -1;
    }
    if (Crypto::symmetric_encrypt_authenticate(
            plaintext, plaintext_length, s_key.mac_key, s_key.mac_key_size,
            s_key.cipher_key, s_key.cipher_key_size, AES_128_CBC_IV_SIZE,
            s_key.enc_mode, s_key.hmac_mode, encrypted, encrypted_length) < 0) {
        LOG_ERR << "Failed to symmetric_encrypt_authenticate(). Error during "
                   "encrypting buffer with session key.";
        return -1;
    }
    return 0;
}

int SST_API::decrypt_buf_with_session_key(const session_key_t& s_key,
                                          const unsigned char* encrypted,
                                          unsigned int encrypted_length,
                                          unsigned char* decrypted,
                                          unsigned int* decrypted_length) {
    if (!is_session_key_valid(s_key)) {
        LOG_ERR << "Session key is expired.";
        return -1;
    }
    if (!check_encrypted_length(encrypted_length, s_key.mac_key_size,
                                s_key.enc_mode, s_key.hmac_mode)) {
        return -1;
    }
    if (Crypto::symmetric_decrypt_authenticate(
            encrypted, encrypted_length, s_key.mac_key, s_key.mac_key_size,
            s_key.cipher_key, s_key.cipher_key_size, AES_128_CBC_IV_SIZE,
            s_key.enc_mode, s_key.hmac_mode, decrypted, decrypted_length) < 0) {
        LOG_ERR << "Failed to symmetric_decrypt_authenticate(). Error during "
                   "decrypting buffer with session key.";
        return -1;
    }
    return 0;
}

}  // namespace sst
