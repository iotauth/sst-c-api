#ifndef SEND_SYN_H
#define SEND_SYN_H

#ifdef __cplusplus
extern "C" {
#endif

// Send exactly one TCP SYN to (dst_ip, dst_port).
// Returns 0 on success, nonzero on error.
int send_one_syn(const char* dst_ip, unsigned short dst_port);

#ifdef __cplusplus
}
#endif

#endif // SEND_SYN_H
