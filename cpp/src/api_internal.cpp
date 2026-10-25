/**
 * @file api_internal.cpp
 * @brief Shared byte encoding, socket I/O and symmetric crypto helpers.
 */

#include "api_internal.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <sstream>

#include "log/log_manager.hpp"

namespace sst {

namespace internal {

FdGuard::~FdGuard() {
    if (fd_ >= 0) ::close(fd_);
}

std::string to_hex(const unsigned char* buf, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; i++) {
        if (i != 0) oss << ' ';
        oss << std::hex << std::setw(2) << std::setfill('0')
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
            return total_read == 0 ? 0 : -2;
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

// Writes a whole byte vector.
int write_bytes_to_socket(int sock, const Bytes& buf) {
    return sst_write_to_socket(sock, buf.data(),
                               static_cast<unsigned int>(buf.size()));
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

}  // namespace sst
