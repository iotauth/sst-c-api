#ifndef SEND_SYN_H
#define SEND_SYN_H

#ifdef __cplusplus
extern "C" {
#endif

// Send TCP SYN to (dst_ip, dst_port).
// Returns 0 on success, nonzero on error.
bool send_syn_packets(const char* src_ip_str, const char* dst_ip,
                      unsigned short dst_port, int repeat);

// new: normal UDP (non-spoofed). If bind_src_ip==NULL, kernel picks a local IP.
// payload can be NULL (sends zero-length UDP). Returns 0 on success.
int send_one_udp_normal(const char* bind_src_ip,   // or NULL
                        const char* dst_ip, unsigned short dst_port,
                        const void* payload, size_t payload_len,
                        int repeat);

#ifdef __cplusplus
}
#endif

#endif  // SEND_SYN_H
