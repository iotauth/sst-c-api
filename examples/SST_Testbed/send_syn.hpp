#ifndef SEND_SYN_H
#define SEND_SYN_H

#ifdef __cplusplus
extern "C" {
#endif

// Send exactly one TCP SYN to (dst_ip, dst_port).
// Returns 0 on success, nonzero on error.
bool send_syn_packets(const char* src_ip_str, const char* dst_ip, unsigned short dst_port, int repeat);

#ifdef __cplusplus
}
#endif

#endif // SEND_SYN_H
