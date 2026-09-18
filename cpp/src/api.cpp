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
#include <vector>

#include "api_internal.hpp"
#include "log/log_manager.hpp"

namespace sst {

namespace {

using Bytes = std::vector<unsigned char>;

// ---------------------------------------------------------------------------
// Protocol constants (mirror src/c_common.h and src/c_secure_comm.h)
// ---------------------------------------------------------------------------

// Message types.
constexpr unsigned char AUTH_HELLO = 0;
constexpr unsigned char SESSION_KEY_REQ_IN_PUB_ENC = 20;
constexpr unsigned char SESSION_KEY_RESP_WITH_DIST_KEY = 21;
constexpr unsigned char SESSION_KEY_REQ = 22;
constexpr unsigned char SESSION_KEY_RESP = 23;
constexpr unsigned char SKEY_HANDSHAKE_1 = 30;
constexpr unsigned char SKEY_HANDSHAKE_2 = 31;
constexpr unsigned char SKEY_HANDSHAKE_3 = 32;
constexpr unsigned char SECURE_COMM_MSG = 33;
constexpr unsigned char ADD_READER_REQ_IN_PUB_ENC = 60;
constexpr unsigned char ADD_READER_RESP_WITH_DIST_KEY = 61;
constexpr unsigned char ADD_READER_REQ = 62;
constexpr unsigned char ADD_READER_RESP = 63;
constexpr unsigned char AUTH_ALERT = 100;

// Sizes.
constexpr unsigned int MESSAGE_TYPE_SIZE = 1;
constexpr unsigned int MAX_PAYLOAD_BUF_SIZE = 5;
constexpr unsigned int HS_NONCE_SIZE = 8;
constexpr unsigned int HS_INDICATOR_SIZE = 1 + HS_NONCE_SIZE * 2;
constexpr unsigned int MAX_HS_BUF_LENGTH = 256;
constexpr unsigned int AUTH_ID_LEN = 4;
constexpr unsigned int NUMKEY_SIZE = 4;
constexpr unsigned int NONCE_SIZE = 8;
constexpr unsigned int KEY_ID_SIZE = 8;
constexpr unsigned int ABS_VALIDITY_SIZE = 6;
constexpr unsigned int REL_VALIDITY_SIZE = 6;
// The C API uses 1024 here; a larger buffer also fits responses carrying
// MAX_SESSION_KEY keys together with a distribution key.
constexpr unsigned int MAX_AUTH_COMM_LENGTH = 4096;

// Auth alert codes.
enum auth_alert_code {
    INVALID_DISTRIBUTION_KEY,
    INVALID_SESSION_KEY_REQ,
    UNKNOWN_INTERNAL_ERROR,
};

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

// Prepends the SST header (message type + variable length payload size).
Bytes make_sender_buf(const unsigned char* payload, unsigned int payload_length,
                      unsigned char message_type) {
    unsigned char payload_buf[MAX_PAYLOAD_BUF_SIZE];
    unsigned int payload_buf_len;
    num_to_var_length_int(payload_length, payload_buf, &payload_buf_len);
    Bytes sender;
    sender.reserve(MESSAGE_TYPE_SIZE + payload_buf_len + payload_length);
    sender.push_back(message_type);
    sender.insert(sender.end(), payload_buf, payload_buf + payload_buf_len);
    sender.insert(sender.end(), payload, payload + payload_length);
    return sender;
}

Bytes make_sender_buf(const Bytes& payload, unsigned char message_type) {
    return make_sender_buf(payload.data(),
                           static_cast<unsigned int>(payload.size()),
                           message_type);
}

}  // namespace

// ---------------------------------------------------------------------------
// Socket helpers (c_common.c), shared with ipfs.cpp via api_internal.hpp
// ---------------------------------------------------------------------------

namespace internal {

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
using internal::read_exact;
using internal::sst_read_from_socket;
using internal::sst_write_to_socket;

namespace {

// Writes a whole byte vector.
int write_bytes_to_socket(int sock, const Bytes& buf) {
    return sst_write_to_socket(sock, buf.data(),
                               static_cast<unsigned int>(buf.size()));
}

// Reads the SST header one byte at a time, then the whole payload into `buf`.
// @return payload length, 0 when the socket was closed, -1 on error.
int read_header_return_data_buf_pointer(int sock, unsigned char* message_type,
                                        unsigned char* buf,
                                        unsigned int buf_length) {
    unsigned char header[MESSAGE_TYPE_SIZE + MAX_PAYLOAD_BUF_SIZE];
    int ret = read_exact(sock, header, MESSAGE_TYPE_SIZE);
    if (ret < 0) {
        LOG_ERR
            << "Socket read error in read_header_return_data_buf_pointer().";
        return -1;
    } else if (ret == 0) {
        LOG_INF << "End of file. Disconnected from socket " << sock;
        return 0;
    }
    *message_type = header[0];

    // Variable length payload size: continue while the high bit is set.
    unsigned int var_length_buf_size = 0;
    while (var_length_buf_size < MAX_PAYLOAD_BUF_SIZE) {
        ret = read_exact(sock, header + MESSAGE_TYPE_SIZE + var_length_buf_size,
                         1);
        if (ret <= 0) {
            LOG_ERR << "Failed to read variable length header.";
            return -1;
        }
        var_length_buf_size++;
        if ((header[MESSAGE_TYPE_SIZE + var_length_buf_size - 1] & 128) == 0) {
            break;
        }
    }
    unsigned int payload_length;
    int var_length_buf_size_checked;
    var_length_int_to_num(header + MESSAGE_TYPE_SIZE, var_length_buf_size,
                          &payload_length, &var_length_buf_size_checked);
    if (static_cast<unsigned int>(var_length_buf_size_checked) !=
        var_length_buf_size) {
        LOG_ERR << "Wrong header calculation.";
        return -1;
    }
    if (payload_length > buf_length) {
        LOG_ERR << "Larger buffer size required. Payload: " << payload_length
                << ", buffer: " << buf_length;
        return -1;
    }
    if (payload_length == 0) {
        return 0;
    }
    ret = read_exact(sock, buf, payload_length);
    if (ret <= 0) {
        LOG_ERR << "Failed to read from socket while reading the payload.";
        return -1;
    }
    return static_cast<int>(payload_length);
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

bool check_distribution_key_validity(const distribution_key_t& dist_key) {
    bool valid = check_validity(dist_key.abs_validity);
    if (!valid) {
        LOG_DBG << "Distribution key expired!";
    }
    return valid;
}

// Encrypt-then-MAC into a vector sized from the expected length.
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

// Rejects encrypted buffers that cannot hold the IV, the optional HMAC, the
// GCM tag and (for CBC) at least one whole ciphertext block, so that the
// crypto layer's length arithmetic never underflows on truncated input.
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

// Verify-then-decrypt into a vector sized from the expected maximum length.
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
// Auth request serialization (c_secure_comm.c)
// ---------------------------------------------------------------------------

// entity_nonce (8) + auth_nonce (8) + [num_key (4)] + varlen(sender) + sender
// + varlen(purpose) + purpose.
Bytes serialize_message_for_auth(const unsigned char* entity_nonce,
                                 const unsigned char* auth_nonce, int num_key,
                                 const std::string& sender,
                                 const std::string& purpose) {
    Bytes ret;
    ret.insert(ret.end(), entity_nonce, entity_nonce + NONCE_SIZE);
    ret.insert(ret.end(), auth_nonce, auth_nonce + NONCE_SIZE);
    if (num_key != 0) {
        unsigned char num_key_buf[NUMKEY_SIZE];
        write_in_n_bytes(static_cast<uint64_t>(num_key), NUMKEY_SIZE,
                         num_key_buf);
        ret.insert(ret.end(), num_key_buf, num_key_buf + NUMKEY_SIZE);
    }
    unsigned char var_length_int_buf[MAX_PAYLOAD_BUF_SIZE];
    unsigned int var_length_int_len;

    num_to_var_length_int(static_cast<unsigned int>(sender.size()),
                          var_length_int_buf, &var_length_int_len);
    ret.insert(ret.end(), var_length_int_buf,
               var_length_int_buf + var_length_int_len);
    ret.insert(ret.end(), sender.begin(), sender.end());

    num_to_var_length_int(static_cast<unsigned int>(purpose.size()),
                          var_length_int_buf, &var_length_int_len);
    ret.insert(ret.end(), var_length_int_buf,
               var_length_int_buf + var_length_int_len);
    ret.insert(ret.end(), purpose.begin(), purpose.end());
    return ret;
}

// RSA-OAEP encrypts `buf` with Auth's public key and appends the entity's
// SHA-256 RSA signature over the ciphertext.
Bytes encrypt_and_sign(const unsigned char* buf, unsigned int buf_len,
                       EVP_PKEY* pub_key, EVP_PKEY* priv_key) {
    Bytes encrypted(static_cast<size_t>(EVP_PKEY_size(pub_key)));
    size_t encrypted_length = encrypted.size();
    if (Crypto::public_encrypt(buf, buf_len, RSA_PKCS1_OAEP_PADDING, pub_key,
                               encrypted.data(), &encrypted_length) < 0) {
        throw SST_Exception("Failed public_encrypt().");
    }
    encrypted.resize(encrypted_length);

    Bytes signature(static_cast<size_t>(EVP_PKEY_size(priv_key)));
    size_t sig_length = signature.size();
    if (Crypto::sha256_sign(encrypted.data(),
                            static_cast<unsigned int>(encrypted.size()),
                            priv_key, signature.data(), &sig_length) < 0) {
        throw SST_Exception("Failed sha256_sign().");
    }
    signature.resize(sig_length);

    Bytes message;
    message.reserve(encrypted.size() + signature.size());
    message.insert(message.end(), encrypted.begin(), encrypted.end());
    message.insert(message.end(), signature.begin(), signature.end());
    return message;
}

// name_length (1) + name + Enc_dist_key(serialized).
Bytes serialize_session_key_req_with_distribution_key(
    const unsigned char* serialized, unsigned int serialized_length,
    const distribution_key_t& dist_key, const std::string& name) {
    Bytes encrypted;
    if (symmetric_encrypt_authenticate(
            serialized, serialized_length, dist_key.mac_key,
            dist_key.mac_key_size, dist_key.cipher_key,
            dist_key.cipher_key_size, dist_key.enc_mode, USE_HMAC,
            encrypted) < 0) {
        throw SST_Exception(
            "Error during encryption while symmetric_encrypt_authenticate().");
    }
    Bytes ret;
    ret.reserve(1 + name.size() + encrypted.size());
    ret.push_back(static_cast<unsigned char>(name.size()));
    ret.insert(ret.end(), name.begin(), name.end());
    ret.insert(ret.end(), encrypted.begin(), encrypted.end());
    return ret;
}

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

// key_id (8) + abs_validity (6) + rel_validity (6) + cipher_key_size (1) +
// cipher_key + mac_key_size (1) + mac_key.
// @return number of bytes consumed.
unsigned int parse_session_key(session_key_t& ret, const unsigned char* buf,
                               unsigned int buf_length) {
    if (buf_length <
        SESSION_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE + 1) {
        throw SST_Exception("Session key buffer too short.");
    }
    std::memcpy(ret.key_id, buf, SESSION_KEY_ID_SIZE);
    unsigned int cur_idx = SESSION_KEY_ID_SIZE;

    ret.abs_validity =
        read_unsigned_long_int_BE(buf + cur_idx, ABS_VALIDITY_SIZE);
    cur_idx += ABS_VALIDITY_SIZE;
    ret.rel_validity =
        read_unsigned_long_int_BE(buf + cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;

    ret.cipher_key_size = buf[cur_idx];
    cur_idx += 1;
    if (ret.cipher_key_size > MAX_CIPHER_KEY_SIZE ||
        cur_idx + ret.cipher_key_size + 1 > buf_length) {
        throw SST_Exception("Invalid session cipher key size.");
    }
    std::memcpy(ret.cipher_key, buf + cur_idx, ret.cipher_key_size);
    cur_idx += ret.cipher_key_size;

    ret.mac_key_size = buf[cur_idx];
    cur_idx += 1;
    if (ret.mac_key_size > MAC_KEY_SIZE ||
        cur_idx + ret.mac_key_size > buf_length) {
        throw SST_Exception("Invalid session MAC key size.");
    }
    std::memcpy(ret.mac_key, buf + cur_idx, ret.mac_key_size);
    cur_idx += ret.mac_key_size;
    return cur_idx;
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
    Bytes sender =
        make_sender_buf(encrypted.data(), encrypted_length, SECURE_COMM_MSG);
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
    unsigned char message_type;
    unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
    int bytes_read = read_header_return_data_buf_pointer(
        sock_, &message_type, received_buf, MAX_SECURE_COMM_MSG_LENGTH);
    if (bytes_read == 0) {
        LOG_DBG << "Socket was disconnected while reading secure message.";
        return 0;
    } else if (bytes_read < 0) {
        LOG_ERR << "Failed to read_header_return_data_buf_pointer().";
        return -1;
    }
    if (message_type != SECURE_COMM_MSG) {
        LOG_ERR << "Wrong message type " << static_cast<int>(message_type)
                << ", expected SECURE_COMM_MSG.";
        return -1;
    }
    Bytes decrypted;
    if (symmetric_decrypt_authenticate(
            received_buf, static_cast<unsigned int>(bytes_read), s_key_.mac_key,
            MAC_KEY_SIZE, s_key_.cipher_key, CIPHER_KEY_SIZE, s_key_.enc_mode,
            s_key_.hmac_mode, decrypted) < 0) {
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

void SST_API::parse_session_key_response(const unsigned char* buf,
                                         unsigned int buf_length,
                                         unsigned char* reply_nonce,
                                         SessionKeyList& list) const {
    if (buf_length < NONCE_SIZE + 1) {
        throw SST_Exception("Session key response too short.");
    }
    std::memcpy(reply_nonce, buf, NONCE_SIZE);
    unsigned int buf_idx = NONCE_SIZE;

    // Crypto spec string: varlen + bytes. Currently unused, skip it.
    unsigned int crypto_spec_len;
    int var_len_int_buf_size;
    var_length_int_to_num(buf + buf_idx, buf_length - buf_idx, &crypto_spec_len,
                          &var_len_int_buf_size);
    if (var_len_int_buf_size == 0) {
        throw SST_Exception(
            "Buffer size of the variable length integer cannot be 0.");
    }
    unsigned int prefix_len = static_cast<unsigned int>(var_len_int_buf_size);
    // Both subtractions are safe: prefix_len <= buf_length - buf_idx by
    // construction, and the comparison rejects an oversized spec length
    // before it can move buf_idx past the end of the response.
    if (crypto_spec_len > buf_length - buf_idx - prefix_len ||
        buf_length - buf_idx - prefix_len - crypto_spec_len < 4) {
        throw SST_Exception("Session key response truncated.");
    }
    buf_idx += prefix_len + crypto_spec_len;
    unsigned int session_key_list_length =
        read_unsigned_int_BE(buf + buf_idx, 4);
    buf_idx += 4;
    if (session_key_list_length > MAX_SESSION_KEY) {
        throw SST_Exception("Too many session keys in response: " +
                            std::to_string(session_key_list_length));
    }
    for (unsigned int i = 0; i < session_key_list_length; i++) {
        buf_idx += parse_session_key(list.s_key[i], buf + buf_idx,
                                     buf_length - buf_idx);
        list.s_key[i].enc_mode = config_.session_key_enc_mode;
        list.s_key[i].hmac_mode = config_.hmac_mode;
        list.s_key[i].perm_dist_key_mode = config_.perm_dist_key_mode;
    }
    list.num_key = static_cast<int>(session_key_list_length);
    list.rear_idx = list.num_key % static_cast<int>(MAX_SESSION_KEY);
}

void SST_API::save_distribution_key(const unsigned char* data_buf,
                                    size_t key_size) {
    // data_buf = Enc_pub(dist key) (key_size) + Sign(Enc_pub(dist key))
    // (key_size).
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

void SST_API::send_auth_request_message(const unsigned char* serialized,
                                        unsigned int serialized_length,
                                        int sock, bool request_index) {
    Bytes message;
    if (!check_distribution_key_validity(dist_key_)) {
        LOG_DBG << "Current distribution key expired, requesting new "
                   "distribution key as well...";
        if (!pub_key_ || !priv_key_) {
            throw SST_Exception(
                "Distribution key expired but no public/private key loaded.");
        }
        Bytes enc = encrypt_and_sign(serialized, serialized_length,
                                     pub_key_.get(), priv_key_.get());
        message =
            make_sender_buf(enc, request_index ? SESSION_KEY_REQ_IN_PUB_ENC
                                               : ADD_READER_REQ_IN_PUB_ENC);
    } else {
        Bytes enc = serialize_session_key_req_with_distribution_key(
            serialized, serialized_length, dist_key_, config_.name);
        message = make_sender_buf(
            enc, request_index ? SESSION_KEY_REQ : ADD_READER_REQ);
    }
    if (write_bytes_to_socket(sock, message) < 0) {
        throw SST_Exception("Failed to send request to Auth.");
    }
}

void SST_API::handle_AUTH_HELLO(const unsigned char* data_buf,
                                unsigned char* entity_nonce, int sock,
                                int num_key, const std::string& purpose,
                                bool request_index) {
    unsigned int auth_id = read_unsigned_int_BE(data_buf, AUTH_ID_LEN);
    if (auth_id != static_cast<unsigned int>(config_.auth_id)) {
        throw SST_Exception("Auth ID NOT matched. Received " +
                            std::to_string(auth_id) + ", expected " +
                            std::to_string(config_.auth_id));
    }
    unsigned char auth_nonce[NONCE_SIZE];
    std::memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE);
    if (Crypto::generate_nonce(NONCE_SIZE, entity_nonce) < 0) {
        throw SST_Exception("Failed to generate entity nonce.");
    }
    Bytes serialized = serialize_message_for_auth(
        entity_nonce, auth_nonce, num_key, config_.name, purpose);
    send_auth_request_message(serialized.data(),
                              static_cast<unsigned int>(serialized.size()),
                              sock, request_index);
}

SessionKeyList SST_API::send_session_key_req_via_TCP() {
    int sock = connect_as_client(config_.auth_ip_addr, config_.auth_port_num);
    if (sock < 0) {
        throw SST_Exception(std::string("Failed to connect to Auth at ") +
                            config_.auth_ip_addr + ":" +
                            std::to_string(config_.auth_port_num));
    }
    FdGuard guard(sock);

    enum send_state {
        INIT,
        AUTH_HELLO_RECEIVED,
    };
    send_state state = INIT;
    unsigned char entity_nonce[NONCE_SIZE];
    SessionKeyList session_key_list;

    while (true) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
        unsigned char message_type;
        int data_buf_length = read_header_return_data_buf_pointer(
            sock, &message_type, received_buf, sizeof(received_buf));
        if (data_buf_length < 0) {
            throw SST_Exception("Failed to read from Auth.");
        } else if (data_buf_length == 0) {
            throw SST_Exception("Auth closed the connection.");
        }
        unsigned int data_len = static_cast<unsigned int>(data_buf_length);

        if (state == INIT && message_type == AUTH_HELLO) {
            if (data_len < AUTH_ID_LEN + NONCE_SIZE) {
                throw SST_Exception("AUTH_HELLO too short.");
            }
            state = AUTH_HELLO_RECEIVED;
            handle_AUTH_HELLO(received_buf, entity_nonce, sock, config_.numkey,
                              purpose_for_requesting_key_, true);
        } else if (state == AUTH_HELLO_RECEIVED &&
                   message_type == SESSION_KEY_RESP) {
            LOG_DBG << "Received session key response encrypted with "
                       "distribution key.";
            Bytes decrypted;
            if (symmetric_decrypt_authenticate(
                    received_buf, data_len, dist_key_.mac_key,
                    dist_key_.mac_key_size, dist_key_.cipher_key,
                    dist_key_.cipher_key_size, config_.session_key_enc_mode,
                    USE_HMAC, decrypted) < 0) {
                throw SST_Exception(
                    "Failed to decrypt SESSION_KEY_RESP with the "
                    "distribution key.");
            }
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(
                decrypted.data(), static_cast<unsigned int>(decrypted.size()),
                reply_nonce, session_key_list);
            LOG_DBG << "Reply_nonce in sessionKeyResp:"
                    << to_hex(reply_nonce, NONCE_SIZE);
            if (std::memcmp(reply_nonce, entity_nonce, NONCE_SIZE) != 0) {
                throw SST_Exception("Auth nonce NOT verified.");
            }
            LOG_DBG << "Auth nonce verified!";
            return session_key_list;
        } else if (state == AUTH_HELLO_RECEIVED &&
                   message_type == SESSION_KEY_RESP_WITH_DIST_KEY) {
            if (!priv_key_) {
                throw SST_Exception(
                    "Received SESSION_KEY_RESP_WITH_DIST_KEY without a "
                    "private key.");
            }
            size_t key_size =
                static_cast<size_t>(EVP_PKEY_size(priv_key_.get()));
            if (data_len <= key_size * 2) {
                throw SST_Exception(
                    "SESSION_KEY_RESP_WITH_DIST_KEY too short.");
            }
            save_distribution_key(received_buf, key_size);

            // Decrypt the session keys with the fresh distribution key.
            Bytes decrypted;
            if (symmetric_decrypt_authenticate(
                    received_buf + key_size * 2,
                    data_len - static_cast<unsigned int>(key_size * 2),
                    dist_key_.mac_key, dist_key_.mac_key_size,
                    dist_key_.cipher_key, dist_key_.cipher_key_size,
                    config_.session_key_enc_mode, USE_HMAC, decrypted) < 0) {
                throw SST_Exception(
                    "Failed to decrypt SESSION_KEY_RESP_WITH_DIST_KEY.");
            }
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(
                decrypted.data(), static_cast<unsigned int>(decrypted.size()),
                reply_nonce, session_key_list);
            LOG_DBG << "Reply_nonce in sessionKeyResp:"
                    << to_hex(reply_nonce, NONCE_SIZE);
            if (std::memcmp(reply_nonce, entity_nonce, NONCE_SIZE) != 0) {
                throw SST_Exception("Auth nonce NOT verified.");
            }
            LOG_DBG << "Auth nonce verified!";
            return session_key_list;
        } else if (message_type == AUTH_ALERT) {
            std::string reason;
            switch (received_buf[0]) {
                case INVALID_DISTRIBUTION_KEY:
                    reason = "Invalid Distribution Key.";
                    break;
                case INVALID_SESSION_KEY_REQ:
                    reason = "Invalid Session Key Request.";
                    break;
                case UNKNOWN_INTERNAL_ERROR:
                    reason = "Unknown Internal Error.";
                    break;
                default:
                    reason = "Unknown Code.";
                    break;
            }
            throw SST_Exception("AUTH_ALERT received from Auth: " + reason);
        } else {
            throw SST_Exception("Unexpected message type " +
                                std::to_string(message_type) + " from Auth.");
        }
    }
}

void SST_API::send_add_reader_req_via_TCP(const std::string& add_reader) {
    std::lock_guard<std::mutex> lock(mutex_);
    int sock = connect_as_client(config_.auth_ip_addr, config_.auth_port_num);
    if (sock < 0) {
        throw SST_Exception(std::string("Failed to connect to Auth at ") +
                            config_.auth_ip_addr + ":" +
                            std::to_string(config_.auth_port_num));
    }
    FdGuard guard(sock);
    unsigned char entity_nonce[NONCE_SIZE];
    bool hello_received = false;

    while (true) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
        unsigned char message_type;
        int data_buf_length = read_header_return_data_buf_pointer(
            sock, &message_type, received_buf, sizeof(received_buf));
        if (data_buf_length < 0) {
            throw SST_Exception("Failed to read from Auth.");
        } else if (data_buf_length == 0) {
            throw SST_Exception("Auth closed the connection.");
        }
        unsigned int data_len = static_cast<unsigned int>(data_buf_length);

        if (!hello_received && message_type == AUTH_HELLO) {
            if (data_len < AUTH_ID_LEN + NONCE_SIZE) {
                throw SST_Exception("AUTH_HELLO too short.");
            }
            hello_received = true;
            // num_key 0: the add reader request carries no key count.
            handle_AUTH_HELLO(received_buf, entity_nonce, sock, 0, add_reader,
                              false);
        } else if (hello_received &&
                   message_type == ADD_READER_RESP_WITH_DIST_KEY) {
            if (!priv_key_) {
                throw SST_Exception(
                    "Received ADD_READER_RESP_WITH_DIST_KEY without a "
                    "private key.");
            }
            size_t key_size =
                static_cast<size_t>(EVP_PKEY_size(priv_key_.get()));
            if (data_len <= key_size * 2) {
                throw SST_Exception("ADD_READER_RESP_WITH_DIST_KEY too short.");
            }
            save_distribution_key(received_buf, key_size);
            Bytes decrypted;
            if (symmetric_decrypt_authenticate(
                    received_buf + key_size * 2,
                    data_len - static_cast<unsigned int>(key_size * 2),
                    dist_key_.mac_key, dist_key_.mac_key_size,
                    dist_key_.cipher_key, dist_key_.cipher_key_size,
                    config_.session_key_enc_mode, USE_HMAC, decrypted) < 0 ||
                decrypted.size() < NONCE_SIZE) {
                throw SST_Exception(
                    "Error during decryption after receiving "
                    "ADD_READER_RESP_WITH_DIST_KEY.");
            }
            if (std::memcmp(decrypted.data(), entity_nonce, NONCE_SIZE) != 0) {
                throw SST_Exception("Auth nonce NOT verified.");
            }
            LOG_DBG << "Auth nonce verified!";
            LOG_INF << "Add a file reader to the database.";
            return;
        } else if (hello_received && message_type == ADD_READER_RESP) {
            Bytes decrypted;
            if (symmetric_decrypt_authenticate(
                    received_buf, data_len, dist_key_.mac_key,
                    dist_key_.mac_key_size, dist_key_.cipher_key,
                    dist_key_.cipher_key_size, config_.session_key_enc_mode,
                    USE_HMAC, decrypted) < 0 ||
                decrypted.size() < NONCE_SIZE) {
                throw SST_Exception(
                    "Error during decryption after receiving "
                    "ADD_READER_RESP.");
            }
            if (std::memcmp(decrypted.data(), entity_nonce, NONCE_SIZE) != 0) {
                throw SST_Exception("Auth nonce NOT verified.");
            }
            LOG_DBG << "Auth nonce verified!";
            LOG_INF << "Add a file reader to the database.";
            return;
        } else if (message_type == AUTH_ALERT) {
            throw SST_Exception("AUTH_ALERT received from Auth: code " +
                                std::to_string(received_buf[0]));
        } else {
            throw SST_Exception("Unexpected message type " +
                                std::to_string(message_type) + " from Auth.");
        }
    }
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
    Bytes sender_HS_1 = make_sender_buf(parsed, SKEY_HANDSHAKE_1);
    if (write_bytes_to_socket(sock, sender_HS_1) < 0) {
        throw SST_Exception("Failed to send handshake 1.");
    }

    // Receive handshake 2.
    unsigned char received_buf[MAX_HS_BUF_LENGTH];
    unsigned char message_type;
    int data_buf_length = read_header_return_data_buf_pointer(
        sock, &message_type, received_buf, MAX_HS_BUF_LENGTH);
    if (data_buf_length < 0) {
        throw SST_Exception(
            "Socket read error in secure_connect_to_server_with_socket().");
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake2 in "
            "secure_connect_to_server_with_socket().");
    }
    if (message_type != SKEY_HANDSHAKE_2) {
        throw SST_Exception(
            "Comm init failed: expected SKEY_HANDSHAKE_2, got " +
            std::to_string(message_type));
    }

    // Send handshake 3.
    Bytes hs3 = check_handshake_2_send_handshake_3(
        received_buf, static_cast<unsigned int>(data_buf_length), entity_nonce,
        s_key);
    Bytes sender_HS_3 = make_sender_buf(hs3, SKEY_HANDSHAKE_3);
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
    unsigned char received_buf[MAX_HS_BUF_LENGTH];
    unsigned char message_type;
    int data_buf_length = read_header_return_data_buf_pointer(
        clnt_sock, &message_type, received_buf, MAX_HS_BUF_LENGTH);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().");
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake1 in "
            "server_secure_comm_setup().");
    }
    if (message_type != SKEY_HANDSHAKE_1) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_1, got " +
            std::to_string(message_type));
    }
    if (static_cast<unsigned int>(data_buf_length) < SESSION_KEY_ID_SIZE) {
        throw SST_Exception("Handshake 1 too short.");
    }
    LOG_DBG << "Received session key handshake1.";

    unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
    std::memcpy(target_session_key_id, received_buf, SESSION_KEY_ID_SIZE);
    session_key_t* s_key =
        get_session_key_by_ID(target_session_key_id, existing_s_key_list);

    // Send handshake 2.
    unsigned char server_nonce[HS_NONCE_SIZE];
    Bytes hs2 = check_handshake1_send_handshake2(
        received_buf, static_cast<unsigned int>(data_buf_length), server_nonce,
        *s_key);
    Bytes sender = make_sender_buf(hs2, SKEY_HANDSHAKE_2);
    if (write_bytes_to_socket(clnt_sock, sender) < 0) {
        throw SST_Exception("Failed to send handshake 2.");
    }
    LOG_DBG << "Switching to HANDSHAKE_2_SENT.";

    // Receive handshake 3.
    data_buf_length = read_header_return_data_buf_pointer(
        clnt_sock, &message_type, received_buf, MAX_HS_BUF_LENGTH);
    if (data_buf_length < 0) {
        throw SST_Exception("Socket read error in server_secure_comm_setup().");
    } else if (data_buf_length == 0) {
        throw SST_Exception(
            "Socket disconnected during handshake3 in "
            "server_secure_comm_setup().");
    }
    if (message_type != SKEY_HANDSHAKE_3) {
        throw SST_Exception(
            "Error during comm init: expected SKEY_HANDSHAKE_3, got " +
            std::to_string(message_type));
    }
    LOG_DBG << "Received session key handshake3!";
    Bytes decrypted;
    if (handshake_decrypt(received_buf,
                          static_cast<unsigned int>(data_buf_length), *s_key,
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
