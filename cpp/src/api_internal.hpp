/**
 * @file api_internal.hpp
 * @brief Helpers shared by the SST C++ API modules (api.cpp, ipfs.cpp and
 * the message classes in message/). Not part of the public API.
 */

#ifndef SST_API_INTERNAL_HPP
#define SST_API_INTERNAL_HPP

#include <cstdint>
#include <vector>

#include "api.hpp"

namespace sst {
namespace internal {

using Bytes = std::vector<unsigned char>;

// Largest encoding of a variable length integer (7 bits per byte).
constexpr unsigned int MAX_PAYLOAD_BUF_SIZE = 5;

// ---- Sockets ----

// Connects to ip_addr:port_num with retries, like the C API.
// @return connected socket, or -1 on failure.
int connect_as_client(const char* ip_addr, int port_num);

// Reads up to buf_length bytes with a single read().
// @return bytes read, 0 on EOF, -1 on error.
int sst_read_from_socket(int sock, unsigned char* buf, unsigned int buf_length);

// Reads exactly `length` bytes.
// @return `length` on success, 0 on EOF before any byte was read, -1 on
// error or on a truncated read.
int read_exact(int sock, unsigned char* buf, unsigned int length);

// Writes the whole buffer, retrying partial writes.
// @return bytes written, or -1 on error.
int sst_write_to_socket(int sock, const unsigned char* buf,
                        unsigned int buf_length);

// ---- Byte encoding ----

// Writes `num` as an n-byte big-endian integer.
void write_in_n_bytes(uint64_t num, int n, unsigned char* buf);

// Reads a big-endian integer of byte_length bytes.
uint64_t read_unsigned_long_int_BE(const unsigned char* buf, int byte_length);
unsigned int read_unsigned_int_BE(const unsigned char* buf, int byte_length);

// Decodes a variable length integer (7 bits per byte, high bit = continue).
// Sets *var_len_int_buf_size to 0 when no valid encoding is found.
void var_length_int_to_num(const unsigned char* buf, unsigned int buf_length,
                           unsigned int* num, int* var_len_int_buf_size);

// Encodes a variable length integer into at most MAX_PAYLOAD_BUF_SIZE bytes.
void num_to_var_length_int(unsigned int num, unsigned char* var_len_int_buf,
                           unsigned int* var_len_int_buf_size);

// ---- Symmetric cryptography ----

// True when the distribution key's absolute validity has not passed yet.
bool is_distribution_key_valid(const distribution_key_t& dist_key);

// Encrypt-then-MAC into a vector sized from the expected length.
// @return 0 on success, -1 on failure.
int symmetric_encrypt_authenticate(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode, Bytes& ret);

// Rejects buffers too short for the IV, optional HMAC and GCM tag (and, for
// CBC, a whole number of ciphertext blocks).
bool check_encrypted_length(unsigned int buf_length, unsigned int mac_key_size,
                            AES_encryption_mode_t enc_mode,
                            hmac_mode_t hmac_mode);

// Verify-then-decrypt into a vector.
// @return 0 on success, -1 on failure.
int symmetric_decrypt_authenticate(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode, Bytes& ret);

}  // namespace internal
}  // namespace sst

#endif  // SST_API_INTERNAL_HPP
