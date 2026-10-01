/**
 * @file api.cpp
 * @brief Implementation of the SST C++ API (see api.hpp).
 *
 * The protocol code is a port of src/c_common.c, src/c_secure_comm.c,
 * src/load_config.c and src/c_api.c, built on the zero-allocation
 * sst::Crypto layer. Variable-length working buffers use std::vector; the
 * on-the-wire formats are byte-for-byte identical to the C API.
 */

#include "api.hpp"

#include <errno.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
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

// Sizes.
constexpr unsigned int HS_NONCE_SIZE = 8;
constexpr unsigned int HS_INDICATOR_SIZE = 1 + HS_NONCE_SIZE * 2;
constexpr unsigned int MAX_HS_BUF_LENGTH = 256;
constexpr unsigned int NONCE_SIZE = 8;
constexpr unsigned int KEY_ID_SIZE = 8;
// The C API uses 1024 here; a larger buffer also fits responses carrying
// MAX_SESSION_KEY keys together with a distribution key.
constexpr unsigned int MAX_AUTH_COMM_LENGTH = 4096;

// Handshake nonces (HS_nonce_t).
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
        oss << ' ' << std::hex << std::setw(2) << std::setfill('0')
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

// Decodes a variable length integer (7 bits per byte, high bit = continue).
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

// Encodes a variable length integer.
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

// Reads exactly `length` bytes.
// @return `length` on success, 0 on EOF before any byte was read, -1 on
// error or on a truncated read.
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

// Connects to ip_addr:port_num with retries, like the C API.
// @return connected socket, or -1 on failure.
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
        // reinterpret_cast: required by the POSIX connect() signature.
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

// ret = indicator (1) + nonce (8) + reply_nonce (8).
int serialize_handshake(const unsigned char* nonce,
                        const unsigned char* reply_nonce, unsigned char* ret) {
    if (nonce == nullptr && reply_nonce == nullptr) {
        LOG_ERR << "Handshake should include at least one nonce.";
        return -1;
    }
    unsigned char indicator = 0;
    if (nonce != nullptr) {
        indicator += 1;
        std::memcpy(ret + 1, nonce, HS_NONCE_SIZE);
    }
    if (reply_nonce != nullptr) {
        indicator += 2;
        std::memcpy(ret + 1 + HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    ret[0] = indicator;
    return 0;
}

void parse_handshake(const unsigned char* buf, HS_nonce_t& ret) {
    std::memset(&ret, 0, sizeof(ret));
    if ((buf[0] & 1) != 0) {
        std::memcpy(ret.nonce, buf + 1, HS_NONCE_SIZE);
    }
    if ((buf[0] & 2) != 0) {
        std::memcpy(ret.reply_nonce, buf + 1 + HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers with vector outputs
// ---------------------------------------------------------------------------

uint64_t current_time_ms() {
    return static_cast<uint64_t>(std::time(nullptr)) * 1000ULL;
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

// Builds SKEY_HANDSHAKE_1: key_id (8) + Enc(indicator (1) + entity_nonce (8)).
Bytes parse_handshake_1(const session_key_t& s_key,
                        unsigned char* entity_nonce) {
    if (Crypto::generate_nonce(HS_NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.");
    }
    unsigned char indicator_entity_nonce[1 + HS_NONCE_SIZE];
    indicator_entity_nonce[0] = 1;
    std::memcpy(indicator_entity_nonce + 1, entity_nonce, HS_NONCE_SIZE);

    Bytes encrypted;
    if (handshake_encrypt(indicator_entity_nonce, 1 + HS_NONCE_SIZE, s_key,
                          encrypted) < 0) {
        throw SST_Exception("Failed to encrypt handshake 1.");
    }
    Bytes ret;
    ret.reserve(KEY_ID_SIZE + encrypted.size());
    ret.insert(ret.end(), s_key.key_id, s_key.key_id + KEY_ID_SIZE);
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
        decrypted.size() < HS_INDICATOR_SIZE) {
        throw SST_Exception("Error during decryption in checking handshake2.");
    }
    HS_nonce_t hs;
    parse_handshake(decrypted.data(), hs);

    if (std::memcmp(hs.reply_nonce, entity_nonce, HS_NONCE_SIZE) != 0) {
        throw SST_Exception(
            "Comm init failed: server NOT verified, nonce NOT matched, "
            "disconnecting...");
    }
    LOG_DBG << "Server authenticated/authorized by solving nonce!";

    unsigned char buf[HS_INDICATOR_SIZE];
    std::memset(buf, 0, HS_INDICATOR_SIZE);
    if (serialize_handshake(entity_nonce, hs.nonce, buf) < 0) {
        throw SST_Exception("Failed serialize_handshake().");
    }
    Bytes ret;
    if (handshake_encrypt(buf, HS_INDICATOR_SIZE, s_key, ret) < 0) {
        throw SST_Exception("Error during encryption while send_handshake_3.");
    }
    return ret;
}

// Server: verifies SKEY_HANDSHAKE_1 and builds SKEY_HANDSHAKE_2.
Bytes check_handshake1_send_handshake2(const unsigned char* received_buf,
                                       unsigned int received_buf_length,
                                       unsigned char* server_nonce,
                                       const session_key_t& s_key) {
    if (received_buf_length <= SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.");
    }
    Bytes decrypted;
    if (handshake_decrypt(received_buf + SESSION_KEY_ID_SIZE,
                          received_buf_length - SESSION_KEY_ID_SIZE, s_key,
                          decrypted) < 0 ||
        decrypted.size() < 1 + HS_NONCE_SIZE) {
        throw SST_Exception("Error during decrypting handshake1.");
    }
    HS_nonce_t hs;
    parse_handshake(decrypted.data(), hs);
    LOG_DBG << "Client's nonce:" << to_hex(hs.nonce, HS_NONCE_SIZE);

    if (Crypto::generate_nonce(HS_NONCE_SIZE, server_nonce) < 0) {
        throw SST_Exception("Failed to generate server nonce.");
    }
    LOG_DBG << "Server's nonce:" << to_hex(server_nonce, HS_NONCE_SIZE);

    unsigned char buf[HS_INDICATOR_SIZE];
    std::memset(buf, 0, HS_INDICATOR_SIZE);
    if (serialize_handshake(server_nonce, hs.nonce, buf) < 0) {
        throw SST_Exception("Failed serialize_handshake().");
    }
    Bytes ret;
    if (handshake_encrypt(buf, HS_INDICATOR_SIZE, s_key, ret) < 0) {
        throw SST_Exception(
            "Error during encryption while sending handshake2.");
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
        throw SST_Exception("Distribution key buffer too short.");
    }
    parsed.abs_validity =
        read_unsigned_long_int_BE(buf, DIST_KEY_EXPIRATION_TIME_SIZE);
    cur_index += DIST_KEY_EXPIRATION_TIME_SIZE;

    unsigned int cipher_key_size = buf[cur_index];
    cur_index += 1;
    if (cipher_key_size > MAX_CIPHER_KEY_SIZE ||
        cur_index + cipher_key_size + 1 > buf_length) {
        throw SST_Exception("Invalid distribution cipher key size.");
    }
    parsed.cipher_key_size = cipher_key_size;
    std::memcpy(parsed.cipher_key, buf + cur_index, cipher_key_size);
    cur_index += cipher_key_size;

    unsigned int mac_key_size = buf[cur_index];
    cur_index += 1;
    if (mac_key_size > MAC_KEY_SIZE || cur_index + mac_key_size > buf_length) {
        throw SST_Exception("Invalid distribution MAC key size.");
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
                            std::to_string(config.auth_port_num));
    }
    return sock;
}

// Reads the next message from Auth. An AUTH_ALERT is turned into an
// SST_Exception here, so every request flow handles alerts the same way.
IoTSPMessage receive_from_auth(int sock) {
    IoTSPMessage msg = IoTSPMessage::receive(sock, MAX_AUTH_COMM_LENGTH);
    if (msg.get_type() == MessageType::AUTH_ALERT) {
        throw SST_Exception(message::AuthAlertMessage(msg).describe());
    }
    return msg;
}

// Reads AUTH_HELLO and checks that it comes from the configured Auth.
message::AuthHelloMessage receive_auth_hello(int sock, int expected_auth_id) {
    message::AuthHelloMessage hello(receive_from_auth(sock));
    if (hello.get_auth_id() != static_cast<uint32_t>(expected_auth_id)) {
        throw SST_Exception("Auth ID NOT matched. Received " +
                            std::to_string(hello.get_auth_id()) +
                            ", expected " + std::to_string(expected_auth_id));
    }
    return hello;
}

void send_to_auth(int sock, const Bytes& wire) {
    if (write_bytes_to_socket(sock, wire) < 0) {
        throw SST_Exception("Failed to send request to Auth.");
    }
}

// ---------------------------------------------------------------------------
// Config file parsing (load_config.c)
// ---------------------------------------------------------------------------

void copy_config_value(char* dest, size_t dest_size, const std::string& value,
                       const std::string& key) {
    if (value.size() + 1 > dest_size) {
        throw SST_Exception("Config value too long for " + key + ": " + value);
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
                        "\"AES_128_GCM\".");
}

bool parse_on_off(const std::string& v, const std::string& key) {
    if (v == "on" || v == "1") return true;
    if (v == "off" || v == "0") return false;
    throw SST_Exception("Wrong input for " + key +
                        ". Please type \"on\"/\"1\" or \"off\"/\"0\".");
}

int parse_int(const std::string& v, const std::string& key) {
    try {
        return std::stoi(v);
    } catch (const std::exception&) {
        throw SST_Exception("Invalid integer for " + key + ": " + v);
    }
}

int parse_port(const std::string& v, const std::string& key) {
    int port = parse_int(v, key);
    if (port < 0 || port > 65535) {
        throw SST_Exception("Invalid port number for " + key + ": " + v);
    }
    return port;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Parses the SST config file. Accepts the C API key names
// (entityInfo.name=...) and, for compatibility, the earlier C++ key names
// (name = ...).
void load_config(config_t& c, const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (errno == ENOENT) {
            throw SST_Exception("SST Config file not found on path " + path);
        } else if (errno == EACCES) {
            throw SST_Exception("SST Config file permission denied on path " +
                                path);
        }
        throw SST_Exception("SST Config file open failed on path " + path);
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
            throw SST_Exception("Config line without '=': " + trimmed);
        }
        std::string key = trim(trimmed.substr(0, eq_pos));
        std::string value = trim(trimmed.substr(eq_pos + 1));
        if (value.empty()) {
            throw SST_Exception("Config value does not exist for " + key);
        }

        if (key == "entityInfo.name" || key == "name") {
            LOG_DBG << "Name: " << value;
            copy_config_value(c.name, sizeof(c.name), value, key);
        } else if (key == "entityInfo.purpose") {
            if (purpose_count <= 1) {
                LOG_DBG << "Purpose #" << (purpose_count + 1) << ": " << value;
                copy_config_value(c.purpose[purpose_count],
                                  sizeof(c.purpose[purpose_count]), value, key);
                purpose_count += 1;
            } else {
                LOG_DBG << "Error for wrong number of purpose.";
            }
            c.purpose_index = static_cast<unsigned short>(purpose_count - 1);
        } else if (key.rfind("purpose[", 0) == 0 && key.back() == ']') {
            int idx = parse_int(key.substr(8, key.size() - 9), key);
            if (idx < 0 || idx > 1) {
                throw SST_Exception("Purpose index out of range: " + key);
            }
            copy_config_value(c.purpose[idx], sizeof(c.purpose[idx]), value,
                              key);
        } else if (key == "purpose_index") {
            int idx = parse_int(value, key);
            if (idx < 0 || idx > 1) {
                throw SST_Exception("purpose_index must be 0 or 1, got " +
                                    value);
            }
            c.purpose_index = static_cast<unsigned short>(idx);
        } else if (key == "entityInfo.number_key" || key == "numkey") {
            LOG_DBG << "Numkey: " << value;
            c.numkey = parse_int(value, key);
        } else if (key == "sessionKey.encryptionMode" ||
                   key == "session_key_enc_mode") {
            LOG_DBG << "Session key encryption mode: " << value;
            c.session_key_enc_mode = parse_enc_mode(value, key);
        } else if (key == "HmacMode" || key == "hmac_mode") {
            c.hmac_mode = parse_on_off(value, key) ? USE_HMAC : NO_HMAC;
        } else if (key == "PermanentDistKeyMode" ||
                   key == "perm_dist_key_mode") {
            c.perm_dist_key_mode = parse_on_off(value, key)
                                       ? USE_PERMANENT_DIST_KEY
                                       : NO_PERMANENT_DIST_KEY;
        } else if (key == "authInfo.id" || key == "auth_id") {
            LOG_DBG << "Auth ID: " << value;
            c.auth_id = parse_int(value, key);
        } else if (key == "authInfo.pubkey.path" || key == "auth_pubkey_path") {
            LOG_DBG << "Pubkey path of Auth: " << value;
            copy_config_value(c.auth_pubkey_path, sizeof(c.auth_pubkey_path),
                              value, key);
        } else if (key == "entityInfo.privkey.path" ||
                   key == "entity_privkey_path") {
            LOG_DBG << "Privkey path of Entity: " << value;
            copy_config_value(c.entity_privkey_path,
                              sizeof(c.entity_privkey_path), value, key);
        } else if (key == "auth.ip.address" || key == "auth_ip_addr") {
            LOG_DBG << "IP address of Auth: " << value;
            copy_config_value(c.auth_ip_addr, sizeof(c.auth_ip_addr), value,
                              key);
        } else if (key == "auth.port.number" || key == "auth_port_num") {
            c.auth_port_num = parse_port(value, key);
        } else if (key == "entity.server.ip.address" ||
                   key == "entity_server_ip_addr") {
            LOG_DBG << "IP address of entity server: " << value;
            copy_config_value(c.entity_server_ip_addr,
                              sizeof(c.entity_server_ip_addr), value, key);
        } else if (key == "entity.server.port.number" ||
                   key == "entity_server_port_num") {
            LOG_DBG << "Port number of entity server: " << value;
            c.entity_server_port_num = parse_port(value, key);
        } else if (key == "network.protocol") {
            LOG_DBG << "Network Protocol: " << value;
            copy_config_value(c.network_protocol, sizeof(c.network_protocol),
                              value, key);
        } else if (key == "fileSystemManager.ip.address") {
            copy_config_value(c.file_system_manager_ip_addr,
                              sizeof(c.file_system_manager_ip_addr), value,
                              key);
        } else if (key == "fileSystemManager.port.number") {
            c.file_system_manager_port_num = parse_port(value, key);
        } else if (key == "distKey.cipherkey.path") {
            copy_config_value(c.dist_cipher_key_path,
                              sizeof(c.dist_cipher_key_path), value, key);
        } else if (key == "distkey.mackey.path") {
            copy_config_value(c.dist_mac_key_path, sizeof(c.dist_mac_key_path),
                              value, key);
        } else if (key == "distKey.encryptionMode" ||
                   key == "dist_key_enc_mode") {
            LOG_DBG << "Distribution key encryption mode: " << value;
            c.dist_key_enc_mode = parse_enc_mode(value, key);
        } else {
            throw SST_Exception("Unknown config type " + key + ".");
        }
    }

    if (c.perm_dist_key_mode == NO_PERMANENT_DIST_KEY) {
        if (std::strlen(c.dist_cipher_key_path) > 0 ||
            std::strlen(c.dist_mac_key_path) > 0) {
            throw SST_Exception(
                "PermanentDistKeyMode is turned off, but dist_key path(s) are "
                "provided.");
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
    // reinterpret_cast: std::string bytes are sent as raw unsigned bytes.
    return send_secure_message(
        reinterpret_cast<const unsigned char*>(msg.data()),
        static_cast<unsigned int>(msg.size()));
}

int SST_Session::send_secure_message(const unsigned char* msg,
                                     unsigned int msg_length) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    if (msg_length > MAX_PAYLOAD_LENGTH) {
        LOG_ERR << "Message too long: " << msg_length << " > "
                << MAX_PAYLOAD_LENGTH;
        return -1;
    }
    if (!is_session_key_valid(s_key_)) {
        LOG_ERR << "Session key expired!";
        return -1;
    }
    // seq_num (8) + msg.
    Bytes buf(SEQ_NUM_SIZE + msg_length, 0);
    write_in_n_bytes(sent_seq_num_, SEQ_NUM_SIZE, buf.data());
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
        return -1;
    }
    sent_seq_num_++;
    encrypted.resize(encrypted_length);
    Bytes sender =
        IoTSPMessage(MessageType::SECURE_COMM_MSG, std::move(encrypted))
            .serialize();
    int bytes_written = write_bytes_to_socket(sock_, sender);
    if (bytes_written < 0) {
        LOG_ERR << "Failed sst_write_to_socket().";
        return -1;
    }
    return bytes_written;
}

int SST_Session::read_secure_message(unsigned char* plaintext,
                                     unsigned int plaintext_capacity) {
    std::lock_guard<std::mutex> lock(recv_mutex_);
    MessageType message_type;
    Bytes received;
    int bytes_read = IoTSPMessage::read(sock_, MAX_SECURE_COMM_MSG_LENGTH,
                                        message_type, received);
    if (bytes_read == 0) {
        LOG_DBG << "Socket was disconnected while reading secure message.";
        return 0;
    } else if (bytes_read < 0) {
        LOG_ERR << "Failed to read a secure message.";
        return -1;
    }
    if (message_type != MessageType::SECURE_COMM_MSG) {
        LOG_ERR << "Wrong message type " << message::to_string(message_type)
                << ", expected SECURE_COMM_MSG.";
        return -1;
    }
    Bytes decrypted;
    if (symmetric_decrypt_authenticate(
            received.data(), static_cast<unsigned int>(received.size()),
            s_key_.mac_key, MAC_KEY_SIZE, s_key_.cipher_key, CIPHER_KEY_SIZE,
            s_key_.enc_mode, s_key_.hmac_mode, decrypted) < 0) {
        LOG_ERR << "Failed to decrypt received message.";
        return -1;
    }
    if (decrypted.size() < SEQ_NUM_SIZE) {
        LOG_ERR << "Decrypted message shorter than the sequence number.";
        return -1;
    }
    unsigned int received_seq_num =
        read_unsigned_int_BE(decrypted.data(), SEQ_NUM_SIZE);
    if (received_seq_num != received_seq_num_) {
        LOG_ERR << "Wrong sequence number expected. Got " << received_seq_num
                << ", expected " << received_seq_num_;
        return -1;
    }
    if (!is_session_key_valid(s_key_)) {
        LOG_ERR << "Session key expired!";
        return -1;
    }
    received_seq_num_++;
    LOG_DBG << "Received seq_num: " << received_seq_num << ".";

    unsigned int plaintext_length =
        static_cast<unsigned int>(decrypted.size()) - SEQ_NUM_SIZE;
    if (plaintext_length > plaintext_capacity) {
        LOG_ERR << "Plaintext buffer too small: need " << plaintext_length
                << ", have " << plaintext_capacity;
        return -1;
    }
    std::memcpy(plaintext, decrypted.data() + SEQ_NUM_SIZE, plaintext_length);
    return static_cast<int>(plaintext_length);
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
        // reinterpret_cast: print the plaintext bytes as text.
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
    purpose_for_requesting_key_ = config_.purpose[config_.purpose_index];

    if (config_.perm_dist_key_mode == NO_PERMANENT_DIST_KEY) {
        pub_key_.reset(Crypto::load_auth_public_key(config_.auth_pubkey_path));
        if (!pub_key_) {
            throw SST_Exception(
                std::string("Failed load_auth_public_key(). Given path: ") +
                config_.auth_pubkey_path + ", config_path: " + config_path);
        }
        priv_key_.reset(
            Crypto::load_entity_private_key(config_.entity_privkey_path));
        if (!priv_key_) {
            throw SST_Exception(
                std::string("Failed load_entity_private_key(). Given path: ") +
                config_.entity_privkey_path + ", config_path: " + config_path);
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
            "distkey.mackey.path must be set.");
    }
    {
        std::ifstream fp(config_.dist_cipher_key_path, std::ios::binary);
        if (!fp.is_open()) {
            throw SST_Exception(
                std::string("Failed to open dist_cipher_key_path: ") +
                config_.dist_cipher_key_path);
        }
        // reinterpret_cast: ifstream reads into char buffers.
        fp.read(reinterpret_cast<char*>(dist_key_.cipher_key), CIPHER_KEY_SIZE);
        if (static_cast<unsigned int>(fp.gcount()) != CIPHER_KEY_SIZE) {
            throw SST_Exception(
                std::string("Failed to read CIPHER_KEY_SIZE bytes from "
                            "dist_cipher_key_path: ") +
                config_.dist_cipher_key_path);
        }
        dist_key_.cipher_key_size = CIPHER_KEY_SIZE;
    }
    {
        std::ifstream fp(config_.dist_mac_key_path, std::ios::binary);
        if (!fp.is_open()) {
            throw SST_Exception(
                std::string("Failed to open dist_mac_key_path: ") +
                config_.dist_mac_key_path);
        }
        fp.read(reinterpret_cast<char*>(dist_key_.mac_key), MAC_KEY_SIZE);
        if (static_cast<unsigned int>(fp.gcount()) != MAC_KEY_SIZE) {
            throw SST_Exception(
                std::string("Failed to read MAC_KEY_SIZE bytes from "
                            "dist_mac_key_path: ") +
                config_.dist_mac_key_path);
        }
        dist_key_.mac_key_size = MAC_KEY_SIZE;
    }
}

// ---------------------------------------------------------------------------
// SST_API: session key requests
// ---------------------------------------------------------------------------

SessionKeyList SST_API::request_session_keys_locked(int purpose_index) {
    if (purpose_index < 0 || purpose_index > 1) {
        throw SST_Exception("Purpose index out of range.");
    }
    purpose_for_requesting_key_ = config_.purpose[purpose_index];
    if (std::strcmp(config_.network_protocol, "TCP") != 0) {
        throw SST_Exception(std::string("Unsupported network protocol: ") +
                            config_.network_protocol);
    }
    return send_session_key_req_via_TCP();
}

SessionKeyList SST_API::get_session_key_with_index(int purpose_index) {
    std::lock_guard<std::mutex> lock(mutex_);
    return request_session_keys_locked(purpose_index);
}

void SST_API::get_session_key_with_index(int purpose_index,
                                         SessionKeyList& existing_s_key_list) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!existing_s_key_list.addable(config_.numkey)) {
        LOG_WRN << "The session key list is not addable.";
        return;
    }
    SessionKeyList earned = request_session_keys_locked(purpose_index);
    existing_s_key_list.append(earned);
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

    // If the entity already has the session key, no request to Auth is
    // needed.
    int session_key_idx = existing_s_key_list.find(target_id);
    if (session_key_idx >= 0) {
        return &existing_s_key_list.s_key[static_cast<size_t>(session_key_idx)];
    }

    purpose_for_requesting_key_ =
        "{\"keyId\":" + std::to_string(target_id) + "}";
    SessionKeyList s_key_list;
    try {
        s_key_list =
            send_session_key_request_check_protocol(target_session_key_id);
    } catch (...) {
        purpose_for_requesting_key_ = config_.purpose[config_.purpose_index];
        throw;
    }
    // Restore the original purpose after the key has been fetched.
    purpose_for_requesting_key_ = config_.purpose[config_.purpose_index];

    int index = existing_s_key_list.add(s_key_list.s_key[0]);
    return &existing_s_key_list.s_key[static_cast<size_t>(index)];
}

SessionKeyList SST_API::send_session_key_request_check_protocol(
    const unsigned char* target_key_id) {
    if (std::strcmp(config_.network_protocol, "TCP") != 0) {
        throw SST_Exception(std::string("Invalid network protocol name: ") +
                            config_.network_protocol);
    }
    SessionKeyList s_key_list = send_session_key_req_via_TCP();
    LOG_DBG << "Received " << s_key_list.num_key << " keys.";
    if (s_key_list.empty()) {
        throw SST_Exception("Auth returned no session key.");
    }
    if (std::memcmp(s_key_list.s_key[0].key_id, target_key_id,
                    SESSION_KEY_ID_SIZE) != 0) {
        throw SST_Exception("Session key id is NOT as expected.");
    }
    LOG_DBG << "Session key id is as expected.";
    return s_key_list;
}

void SST_API::save_distribution_key(const Bytes& encrypted_dist_key) {
    // Enc_entityPubKey(dist key) (key_size) + Sign_authPrivKey(...)
    // (key_size).
    size_t key_size = encrypted_dist_key.size() / 2;
    const unsigned char* data_buf = encrypted_dist_key.data();
    if (Crypto::sha256_verify(data_buf, static_cast<unsigned int>(key_size),
                              data_buf + key_size, key_size,
                              pub_key_.get()) < 0) {
        throw SST_Exception("Failed sha256_verify() of distribution key.");
    }
    LOG_DBG << "Auth signature verified.";

    Bytes decrypted(key_size);
    size_t decrypted_length = decrypted.size();
    if (Crypto::private_decrypt(data_buf, key_size, RSA_PKCS1_OAEP_PADDING,
                                priv_key_.get(), decrypted.data(),
                                &decrypted_length) < 0) {
        throw SST_Exception("Failed private_decrypt() of distribution key.");
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
    LOG_DBG << "Reply nonce in response:"
            << to_hex(resp.get_entity_nonce().data(), NONCE_SIZE);
    if (std::memcmp(resp.get_entity_nonce().data(), entity_nonce, NONCE_SIZE) !=
        0) {
        throw SST_Exception("Auth nonce NOT verified.");
    }
    LOG_DBG << "Auth nonce verified!";
}

SessionKeyList SST_API::send_session_key_req_via_TCP() {
    FdGuard guard(connect_to_auth(config_));
    int sock = guard.get();

    message::AuthHelloMessage hello = receive_auth_hello(sock, config_.auth_id);
    unsigned char entity_nonce[NONCE_SIZE];
    if (Crypto::generate_nonce(NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.");
    }
    message::SessionKeyReqMessage req(
        entity_nonce, hello.get_auth_nonce().data(), config_.numkey,
        config_.name, purpose_for_requesting_key_);
    send_to_auth(sock, req.serialize_and_encrypt(dist_key_, pub_key_.get(),
                                                 priv_key_.get()));

    message::SessionKeyRespMessage resp(receive_from_auth(sock),
                                        entity_rsa_key_size());
    decrypt_auth_response(resp, entity_nonce);

    SessionKeyList session_key_list = resp.get_session_keys();
    // The key modes are not on the wire; they come from the config.
    for (int i = 0; i < session_key_list.num_key; i++) {
        session_key_t& key = session_key_list.s_key[static_cast<size_t>(i)];
        key.enc_mode = config_.session_key_enc_mode;
        key.hmac_mode = config_.hmac_mode;
        key.perm_dist_key_mode = config_.perm_dist_key_mode;
    }
    return session_key_list;
}

void SST_API::send_add_reader_req_via_TCP(const std::string& add_reader) {
    std::lock_guard<std::mutex> lock(mutex_);
    FdGuard guard(connect_to_auth(config_));
    int sock = guard.get();

    message::AuthHelloMessage hello = receive_auth_hello(sock, config_.auth_id);
    unsigned char entity_nonce[NONCE_SIZE];
    if (Crypto::generate_nonce(NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.");
    }
    message::AddReaderReqMessage req(
        entity_nonce, hello.get_auth_nonce().data(), config_.name, add_reader);
    send_to_auth(sock, req.serialize_and_encrypt(dist_key_, pub_key_.get(),
                                                 priv_key_.get()));

    message::AddReaderRespMessage resp(receive_from_auth(sock),
                                       entity_rsa_key_size());
    decrypt_auth_response(resp, entity_nonce);
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
            std::to_string(config_.entity_server_port_num));
    }
    return secure_connect_to_server_with_socket(s_key, sock);
}

std::unique_ptr<SST_Session> SST_API::secure_connect_to_server_with_socket(
    session_key_t& s_key, int sock) {
    FdGuard guard(sock);

    // Send handshake 1.
    unsigned char entity_nonce[HS_NONCE_SIZE];
    Bytes parsed = parse_handshake_1(s_key, entity_nonce);
    Bytes sender_HS_1 =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_1, std::move(parsed))
            .serialize();
    if (write_bytes_to_socket(sock, sender_HS_1) < 0) {
        throw SST_Exception("Failed to send handshake 1.");
    }

    // Receive handshake 2.
    MessageType message_type;
    Bytes received;
    int data_buf_length =
        IoTSPMessage::read(sock, MAX_HS_BUF_LENGTH, message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception(
            "Socket read error in secure_connect_to_server_with_socket().");
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake2 in "
            "secure_connect_to_server_with_socket().");
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_2) {
        throw SST_Exception(
            "Comm init failed: expected SKEY_HANDSHAKE_2, got " +
            message::to_string(message_type));
    }

    // Send handshake 3.
    Bytes hs3 = check_handshake_2_send_handshake_3(
        received.data(), static_cast<unsigned int>(received.size()),
        entity_nonce, s_key);
    Bytes sender_HS_3 =
        IoTSPMessage(MessageType::SKEY_HANDSHAKE_3, std::move(hs3)).serialize();
    if (write_bytes_to_socket(sock, sender_HS_3) < 0) {
        throw SST_Exception("Failed to send handshake 3.");
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
        throw SST_Exception("Socket read error in server_secure_comm_setup().");
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake1 in "
            "server_secure_comm_setup().");
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_1) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_1, got " +
            message::to_string(message_type));
    }
    if (received.size() < SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.");
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
        throw SST_Exception("Failed to send handshake 2.");
    }
    LOG_DBG << "Switching to HANDSHAKE_2_SENT.";

    // Receive handshake 3.
    data_buf_length = IoTSPMessage::read(clnt_sock, MAX_HS_BUF_LENGTH,
                                         message_type, received);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().");
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake3 in "
            "server_secure_comm_setup().");
    }
    if (message_type != MessageType::SKEY_HANDSHAKE_3) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_3, got " +
            message::to_string(message_type));
    }
    LOG_DBG << "Received session key handshake3!";
    Bytes decrypted;
    if (handshake_decrypt(received.data(),
                          static_cast<unsigned int>(received.size()), *s_key,
                          decrypted) < 0 ||
        decrypted.size() < HS_INDICATOR_SIZE) {
        throw SST_Exception(
            "Error during decryption in HANDSHAKE_2_SENT state.");
    }
    HS_nonce_t hs;
    parse_handshake(decrypted.data(), hs);
    if (std::memcmp(hs.reply_nonce, server_nonce, HS_NONCE_SIZE) != 0) {
        throw SST_Exception(
            "Comm init failed: client NOT verified, nonce NOT matched, "
            "disconnecting...");
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
