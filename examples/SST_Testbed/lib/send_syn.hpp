#ifndef SEND_SYN_H
#define SEND_SYN_H

#ifdef __cplusplus
extern "C" {
#endif

// Send raw TCP SYN packets to (dst_ip, dst_port) with src IP spoofed.
// @return true on success, false on error.
bool send_raw_syn_packets(const char* src_ip_str, const char* dst_ip,
                          unsigned short dst_port, int repeat);

// Send raw UDP packets to (dst_ip, dst_port) with src IP spoofed.
// This variant always sends an empty UDP payload.
// @param src_ip_str: Source IP address in string format (e.g., "192.168.1.1").
// @param dst_ip: Destination IP address in string format.
// @param dst_port: Destination UDP port.
// @param repeat: Number of UDP packets to send.
// @return true on success, false on error.
bool send_raw_udp_packets(const char* src_ip_str, const char* dst_ip,
                          unsigned short dst_port, int repeat);

// Helper function to get the default source IP address for a given destination IP and port.
// @param dst_ip: Destination IP address in string format.
// @param dst_port: Destination port number.
// @param out_ip: Buffer to store the resulting source IP address in string format.
// @param out_ip_len: Length of the output buffer.
// @return true on success, false on error.
bool get_src_ip(const char* dst_ip, unsigned short dst_port, char* out_ip,
                size_t out_ip_len);

// Resolve source IP for raw packet attacks.
// If provided_src_ip is non-empty, use it directly.
// Otherwise, auto-detects a default local source IP for (dst_ip, dst_port).
// @param provided_src_ip Optional caller-provided source IP (can be NULL).
// @param dst_ip Destination IP.
// @param dst_port Destination port.
// @param src_ip_buf Caller-owned buffer to hold the detected source IP.
// @param ip_buf_len Length of src_ip_buf.
// @param out_src_ip Result pointer set to either provided_src_ip or src_ip_buf.
// @return true on success, false on failure.
bool resolve_src_ip_or_default(const char* provided_src_ip, const char* dst_ip,
                               unsigned short dst_port, char* src_ip_buf,
                               size_t ip_buf_len,
                               const char** out_src_ip);

#ifdef __cplusplus
}
#endif

#endif  // SEND_SYN_H
