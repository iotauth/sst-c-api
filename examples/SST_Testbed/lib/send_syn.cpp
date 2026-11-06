extern "C" {
#include "../../../src/c_api.h"
}

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>   // struct ip (BSD)
#include <netinet/tcp.h>  // struct tcphdr (BSD)
#include <netinet/udp.h>  // struct udphdr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <bit>
#include <chrono>
#include <random>
#include <span>

#include "metrics.hpp"

static unsigned short random_source_port() {
    std::random_device random;
    std::uniform_int_distribution<unsigned short> ports(40000, 59999);
    return ports(random);
}

// Pseudo header for TCP checksum
struct pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} __attribute__((packed));

// RFC 1071 16-bit one's complement checksum
static uint16_t csum16(std::span<const unsigned char> data) {
    uint32_t sum = 0;
    size_t offset = 0;
    while (data.size() - offset >= sizeof(uint16_t)) {
        uint16_t word;
        memcpy(&word, data.data() + offset, sizeof(word));
        sum += word;
        offset += sizeof(word);
    }
    if (offset < data.size()) sum += data[offset];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

template <typename T>
static uint16_t checksum_object(const T& value) {
    return csum16(std::bit_cast<std::array<unsigned char, sizeof(T)>>(value));
}

bool send_raw_syn_packets_measured(const char* src_ip_str, const char* dst_ip,
                                   unsigned short dst_port, int repeat,
                                   MetricsRow* row) {
    // Build IPv4 + TCP SYN
    // Buffer for IP + TCP headers (no payload)
    std::array<unsigned char, sizeof(ip) + sizeof(tcphdr)> packet{};
    ip ipv4{};
    tcphdr tcp{};

    auto* iph = &ipv4;
    auto* tcph = &tcp;

    // Fill IPv4 header (BSD layout)
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = packet.size();
    iph->ip_id = htons(0x1234);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    if (inet_pton(AF_INET, src_ip_str, &iph->ip_src) != 1) {
        SST_print_error("src ip error");
        return false;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1) {
        SST_print_error("dst ip error");
        return false;
    }

    // Fill TCP header (BSD layout uses th_offx2)
    tcph->th_sport = htons(random_source_port());
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(0xABCDEFFF);
    tcph->th_ack = htonl(0);
    tcph->th_off = 5;  // <-- correct on macOS
    tcph->th_x2 = 0;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(65535);
    tcph->th_urp = 0;

    // TCP checksum (pseudo header + TCP header [+ payload])
    struct pseudo_header ph{};
    ph.saddr = iph->ip_src.s_addr;
    ph.daddr = iph->ip_dst.s_addr;
    ph.zero = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len = htons(sizeof(struct tcphdr));

    std::array<unsigned char, sizeof(ph) + sizeof(tcphdr)> chkbuf{};
    memcpy(chkbuf.data(), &ph, sizeof(ph));
    memcpy(chkbuf.data() + sizeof(ph), tcph, sizeof(struct tcphdr));
    tcph->th_sum = csum16(chkbuf);

    // IP checksum (required when you provide your own IP header)
    iph->ip_sum = checksum_object(*iph);

    // Raw IP socket on macOS/BSD: use IPPROTO_RAW and set iph->ip_p to TCP
    memcpy(packet.data(), iph, sizeof(*iph));
    memcpy(packet.data() + sizeof(*iph), tcph, sizeof(*tcph));
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        SST_print_error("socket() error");
        return false;
    }

    if (int one = 1;
        setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        SST_print_error("setsockopt(IP_HDRINCL) error");
        close(s);
        return false;
    }

    struct sockaddr_in dst{};
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
    dst.sin_len = sizeof(dst);  // macOS only
#endif

    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        SST_print_error("dst addr error");
        close(s);
        return false;
    }

    auto destination = std::bit_cast<sockaddr>(dst);
    bool all_sent = true;
    for (int i = 0; i < repeat; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        ssize_t n = sendto(s, packet.data(), packet.size(), 0, &destination,
                           sizeof(destination));
        auto t1 = std::chrono::steady_clock::now();
        long long dur_us =
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                .count();
        if (n < 0) {
            SST_print_error("sendto() error");
            all_sent = false;
            if (row != nullptr) {
                metrics_add_sample(*row, dur_us, false);
            }
            continue;
        }
        SST_print_debug("Sent raw SYN from %s:%u to %s:%u (%zd bytes)",
                        src_ip_str, ntohs(tcph->th_sport), dst_ip, dst_port, n);
        SST_print_log("Sent SYN packet %d of %d", i + 1, repeat);
        if (row != nullptr) {
            metrics_add_sample(*row, dur_us, true);
        }
    }

    close(s);

    return all_sent;
}

extern "C" bool send_raw_syn_packets(const char* src_ip_str, const char* dst_ip,
                                     unsigned short dst_port, int repeat) {
    return send_raw_syn_packets_measured(src_ip_str, dst_ip, dst_port, repeat,
                                         nullptr);
}

// UDP pseudo header
struct udp_pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_len;
} __attribute__((packed));

bool send_raw_udp_packets_measured(const char* src_ip_str, const char* dst_ip,
                                   unsigned short dst_port, int repeat,
                                   MetricsRow* row) {
    const size_t payload_len = 0;
    const size_t ip_len = sizeof(struct ip);
    const size_t udp_len = sizeof(struct udphdr);

    // Fixed-size packet buffer
    std::array<unsigned char, sizeof(ip) + sizeof(udphdr)> packet{};
    ip ipv4{};
    udphdr udp{};

    // Layout: [IP][UDP]
    auto* iph = &ipv4;
    auto* udph = &udp;

    // Fill IPv4 header (BSD layout)
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;

    const size_t total_len = ip_len + udp_len + payload_len;
    iph->ip_len = (uint16_t)total_len;
    iph->ip_id = htons(0x1234);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_UDP;

    if (inet_pton(AF_INET, src_ip_str, &iph->ip_src) != 1) {
        SST_print_error("src ip error");
        return false;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1) {
        SST_print_error("dst ip error");
        return false;
    }

    // Fill UDP header
    uint16_t src_port = random_source_port();

    udph->uh_sport = htons(src_port);
    udph->uh_dport = htons(dst_port);
    udph->uh_ulen = htons((uint16_t)(udp_len + payload_len));
    udph->uh_sum = 0;  // computed below

    // UDP checksum: pseudo header + UDP header
    udp_pseudo_header ph{};
    ph.saddr = iph->ip_src.s_addr;
    ph.daddr = iph->ip_dst.s_addr;
    ph.zero = 0;
    ph.protocol = IPPROTO_UDP;
    ph.udp_len = htons((uint16_t)(udp_len + payload_len));

    // Build checksum buffer
    std::array<unsigned char, sizeof(udp_pseudo_header) + sizeof(udphdr) + 1>
        chkbuf{};
    size_t chklen = 0;

    memcpy(chkbuf.data() + chklen, &ph, sizeof(ph));
    chklen += sizeof(ph);

    memcpy(chkbuf.data() + chklen, udph, udp_len);
    chklen += udp_len;

    // Pad to even length for checksum
    if (chklen & 1) {
        chkbuf[chklen++] = 0;
    }

    udph->uh_sum = csum16(std::span(chkbuf).first(chklen));
    // In IPv4, UDP checksum of 0 means "no checksum", many stacks leave it 0.
    // Keep as is to force computed checksum.

    // IP checksum (required when IP_HDRINCL)
    iph->ip_sum = 0;
    iph->ip_sum = checksum_object(*iph);

    // Raw socket
    memcpy(packet.data(), iph, sizeof(*iph));
    memcpy(packet.data() + sizeof(*iph), udph, sizeof(*udph));
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) {
        SST_print_error("socket() error");
        return false;
    }

    if (int one = 1;
        setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        SST_print_error("setsockopt(IP_HDRINCL) error");
        close(s);
        return false;
    }

    struct sockaddr_in dst{};
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
    dst.sin_len = sizeof(dst);
#endif
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        SST_print_error("dst addr error");
        close(s);
        return false;
    }

    auto destination = std::bit_cast<sockaddr>(dst);
    bool all_sent = true;
    for (int i = 0; i < repeat; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        ssize_t n = sendto(s, packet.data(), total_len, 0, &destination,
                           sizeof(destination));
        auto t1 = std::chrono::steady_clock::now();
        long long dur_us =
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                .count();
        if (n < 0) {
            SST_print_error("sendto() error");
            all_sent = false;
            if (row != nullptr) {
                metrics_add_sample(*row, dur_us, false);
            }
            continue;
        }

        SST_print_debug("Sent raw UDP from %s:%u to %s:%u (%zd bytes)",
                        src_ip_str, src_port, dst_ip, dst_port, n);
        if (repeat > 1) {
            SST_print_log("Sent UDP packet %d of %d", i + 1, repeat);
        }
        if (row != nullptr) {
            metrics_add_sample(*row, dur_us, true);
        }
    }

    close(s);
    return all_sent;
}

extern "C" bool send_raw_udp_packets(const char* src_ip_str, const char* dst_ip,
                                     unsigned short dst_port, int repeat) {
    return send_raw_udp_packets_measured(src_ip_str, dst_ip, dst_port, repeat,
                                         nullptr);
}

extern "C" bool get_src_ip(const char* dst_ip, unsigned short dst_port,
                           char* out_ip, size_t out_ip_len) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        close(s);
        return false;
    }

    // UDP connect: doesn't actually connect; just sets the default route/peer.
    if (auto destination = std::bit_cast<sockaddr>(dst);
        connect(s, &destination, sizeof(destination)) < 0) {
        close(s);
        return false;
    }

    sockaddr address{};
    if (socklen_t len = sizeof(address); getsockname(s, &address, &len) < 0) {
        close(s);
        return false;
    }

    close(s);

    if (auto local = std::bit_cast<sockaddr_in>(address);
        !inet_ntop(AF_INET, &local.sin_addr, out_ip,
                   static_cast<socklen_t>(out_ip_len))) {
        return false;
    }

    return true;
}

extern "C" bool resolve_src_ip_or_default(const char* provided_src_ip,
                                          const char* dst_ip,
                                          unsigned short dst_port,
                                          char* src_ip_buf, size_t ip_buf_len,
                                          const char** out_src_ip) {
    if (out_src_ip == nullptr || src_ip_buf == nullptr) {
        SST_print_error("resolve_src_ip_or_default() invalid input.");
        return false;
    }

    if (provided_src_ip != nullptr && provided_src_ip[0] != '\0') {
        *out_src_ip = provided_src_ip;
        return true;
    }

    if (get_src_ip(dst_ip, dst_port, src_ip_buf, ip_buf_len)) {
        *out_src_ip = src_ip_buf;
        SST_print_debug("No src_ip provided; using default local IP %s",
                        *out_src_ip);
        return true;
    }

    SST_print_error("Source IP missing and auto-detection failed.");
    return false;
}
