/**
 * @file api_internal.hpp
 * @brief Socket helpers shared by the SST C++ API modules (api.cpp,
 * ipfs.cpp). Not part of the public API.
 */

#ifndef SST_API_INTERNAL_HPP
#define SST_API_INTERNAL_HPP

namespace sst {
namespace internal {

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

}  // namespace internal
}  // namespace sst

#endif  // SST_API_INTERNAL_HPP
