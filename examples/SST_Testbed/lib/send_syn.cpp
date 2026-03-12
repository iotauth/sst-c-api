extern "C" {
#include "../../../c_api.h"
}

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h> // struct ip (BSD)
#include <netinet/tcp.h> // struct tcphdr (BSD)
#include <netinet/udp.h> // struct udphdr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Pseudo header for TCP checksum
struct pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} __attribute__((packed));

// RFC 1071 16-bit one's complement checksum
static uint16_t csum16(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* p = (const uint16_t*)data;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

extern "C" bool send_syn_packets(const char* src_ip_str, const char* dst_ip,
                                 unsigned short dst_port, int repeat) {
    // Build IPv4 + TCP SYN
    // Buffer for IP + TCP headers (no payload)
    unsigned char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip* iph = (struct ip*)packet;
    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ip));

    // Fill IPv4 header (BSD layout)
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(packet);
    iph->ip_id = htons(0x1234);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    if (inet_pton(AF_INET, src_ip_str, &iph->ip_src) != 1) {
        SST_print_error("src ip error");
        return EXIT_FAILURE;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1) {
        SST_print_error("dst ip error");
        return EXIT_FAILURE;
    }

    // Fill TCP header (BSD layout uses th_offx2)
    tcph->th_sport = htons(40000 + (rand() % 20000));
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(0xABCDEFFF);
    tcph->th_ack = htonl(0);
    tcph->th_off = 5;  // <-- correct on macOS
    tcph->th_x2 = 0;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(65535);
    tcph->th_urp = 0;

    // TCP checksum (pseudo header + TCP header [+ payload])
    struct pseudo_header ph;
    ph.saddr = *(uint32_t*)&iph->ip_src;
    ph.daddr = *(uint32_t*)&iph->ip_dst;
    ph.zero = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len = htons(sizeof(struct tcphdr));

    unsigned char chkbuf[sizeof(ph) + sizeof(struct tcphdr)];
    memcpy(chkbuf, &ph, sizeof(ph));
    memcpy(chkbuf + sizeof(ph), tcph, sizeof(struct tcphdr));
    tcph->th_sum = csum16(chkbuf, sizeof(chkbuf));

    // IP checksum (required when you provide your own IP header)
    iph->ip_sum = csum16(iph, sizeof(struct ip));

    // Raw IP socket on macOS/BSD: use IPPROTO_RAW and set iph->ip_p to TCP
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        SST_print_error("socket() error");
        return EXIT_FAILURE;
    }

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        SST_print_error("setsockopt(IP_HDRINCL) error");
        return EXIT_FAILURE;
    }

    struct sockaddr_in dst;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
    dst.sin_len = sizeof(dst);  // macOS only
#endif

    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        SST_print_error("dst addr error");
        close(s);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < repeat; ++i) {
        ssize_t n = sendto(s, packet, sizeof(packet), 0, (struct sockaddr*)&dst,
                           sizeof(dst));
        if (n < 0) {
            SST_print_error("sendto() error");
            // close(s);
            // return EXIT_FAILURE;
            continue;
        }
        SST_print_debug("Sent raw SYN from %s:%u to %s:%u (%zd bytes)",
                        src_ip_str, ntohs(tcph->th_sport), dst_ip, dst_port, n);
        SST_print_log("Sent SYN packet %d of %d", i + 1, repeat);
    }

    close(s);

    return EXIT_SUCCESS;
}

// UDP pseudo header
struct udp_pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t udp_len;
} __attribute__((packed));

extern "C" bool send_udp_packets(const char* src_ip_str,
                                     const char* dst_ip,
                                     unsigned short dst_port,
                                     int repeat) {
    const size_t payload_len = 0;
    const size_t ip_len  = sizeof(struct ip);
    const size_t udp_len = sizeof(struct udphdr);

    // Fixed-size packet buffer
    unsigned char packet[sizeof(struct ip) + sizeof(struct udphdr)];
    memset(packet, 0, sizeof(packet));

    // Layout: [IP][UDP]
    struct ip* iph = (struct ip*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + ip_len);

    // Fill IPv4 header (BSD layout)
    iph->ip_v   = 4;
    iph->ip_hl  = 5;
    iph->ip_tos = 0;

    const size_t total_len = ip_len + udp_len + payload_len;
    iph->ip_len = (uint16_t)total_len;
    iph->ip_id  = htons(0x1234);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_UDP;

    if (inet_pton(AF_INET, src_ip_str, &iph->ip_src) != 1) {
        SST_print_error("src ip error");
        return EXIT_FAILURE;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1) {
        SST_print_error("dst ip error");
        return EXIT_FAILURE;
    }

    // Fill UDP header
    uint16_t src_port = (uint16_t)(40000 + (rand() % 20000));

    udph->uh_sport = htons(src_port);
    udph->uh_dport = htons(dst_port);
    udph->uh_ulen  = htons((uint16_t)(udp_len + payload_len));
    udph->uh_sum   = 0; // computed below

    // UDP checksum: pseudo header + UDP header
    udp_pseudo_header ph;
    ph.saddr = *(uint32_t*)&iph->ip_src;
    ph.daddr = *(uint32_t*)&iph->ip_dst;
    ph.zero = 0;
    ph.protocol = IPPROTO_UDP;
    ph.udp_len = htons((uint16_t)(udp_len + payload_len));

    // Build checksum buffer
    unsigned char
        chkbuf[sizeof(udp_pseudo_header) + sizeof(struct udphdr) + 1];
    size_t chklen = 0;

    memcpy(chkbuf + chklen, &ph, sizeof(ph));
    chklen += sizeof(ph);

    memcpy(chkbuf + chklen, udph, udp_len);
    chklen += udp_len;

    // Pad to even length for checksum
    if (chklen & 1) {
        chkbuf[chklen++] = 0;
    }

    udph->uh_sum = csum16(chkbuf, chklen);
    // In IPv4, UDP checksum of 0 means "no checksum", many stacks leave it 0.
    // Keep as is to force computed checksum.

    // IP checksum (required when IP_HDRINCL)
    iph->ip_sum = 0;
    iph->ip_sum = csum16(iph, ip_len);

    // Raw socket
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) {
        SST_print_error("socket() error");
        return EXIT_FAILURE;
    }

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        SST_print_error("setsockopt(IP_HDRINCL) error");
        close(s);
        return EXIT_FAILURE;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    dst.sin_len = sizeof(dst);
#endif
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        SST_print_error("dst addr error");
        close(s);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < repeat; ++i) {
        ssize_t n = sendto(s, packet, total_len, 0, (struct sockaddr*)&dst, sizeof(dst));
        if (n < 0) {
            SST_print_error("sendto() error");
            continue;
        }

        SST_print_debug("Sent raw UDP from %s:%u to %s:%u (%zd bytes)",
                        src_ip_str, src_port, dst_ip, dst_port, n);
        SST_print_log("Sent UDP packet %d of %d", i + 1, repeat);
    }

    close(s);
    return EXIT_SUCCESS;
}

extern "C" int get_src_ip(const char* dst_ip, unsigned short dst_port,
                          char* out_ip, size_t out_ip_len) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        close(s);
        return -1;
    }

    // UDP connect: doesn't actually connect; just sets the default route/peer.
    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
        close(s);
        return -1;
    }

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr*)&local, &len) < 0) {
        close(s);
        return -1;
    }

    close(s);

    if (!inet_ntop(AF_INET, &local.sin_addr, out_ip, (socklen_t)out_ip_len)) {
        return -1;
    }

    return 0;
}

extern "C" bool resolve_src_ip_or_default(
    const char* provided_src_ip, const char* dst_ip, unsigned short dst_port,
    char* src_ip_buf, size_t ip_buf_len, const char** out_src_ip) {
    if (out_src_ip == NULL || src_ip_buf == NULL) {
        SST_print_error("resolve_src_ip_or_default() invalid input.");
        return false;
    }

    if (provided_src_ip != NULL && provided_src_ip[0] != '\0') {
        *out_src_ip = provided_src_ip;
        return true;
    }

    if (get_src_ip(dst_ip, dst_port, src_ip_buf, ip_buf_len) == 0) {
        *out_src_ip = src_ip_buf;
        SST_print_debug("No src_ip provided; using default local IP %s",
                        *out_src_ip);
        return true;
    }

    SST_print_error("Source IP missing and auto-detection failed.");
    return false;
}
