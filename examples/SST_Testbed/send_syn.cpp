extern "C" {
#include "../../c_api.h"
}

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>   // struct ip (BSD)
#include <netinet/tcp.h>  // struct tcphdr (BSD)
#include <netinet/udp.h>   // struct udphdr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

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
        std::cout << "src ip error" << std::endl;
        return EXIT_FAILURE;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1) {
        std::cout << "dst ip error" << std::endl;
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
        std::cout << "socket() error " << strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cout << "setsockopt(IP_HDRINCL) error" << std::endl;
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
        std::cout << "dst addr error" << std::endl;
        close(s);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < repeat; ++i) {
        ssize_t n = sendto(s, packet, sizeof(packet), 0, (struct sockaddr*)&dst,
                           sizeof(dst));
        if (n < 0) {
            std::cout << "sendto() error " << strerror(errno) << std::endl;
            // close(s);
            // return EXIT_FAILURE;
            continue;
        }

        std::cout << "Sent TCP SYN from " << src_ip_str << ":"
                  << ntohs(tcph->th_sport) << " to " << dst_ip << ":"
                  << dst_port << " (" << n << " bytes)" << std::endl;

        std::cout << "Sent SYN packet " << (i + 1) << " of " << repeat
                  << std::endl;
    }

    close(s);

    return EXIT_SUCCESS;
}

extern "C" int send_one_udp_raw(const char* src_ip,
                                const char* dst_ip, unsigned short dst_port,
                                const void* payload, size_t payload_len,
                                int repeat)
{
    const size_t ip_len = sizeof(struct ip), udp_len = sizeof(struct udphdr);

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    const size_t pkt_len = ip_len + udp_len + payload_len;
#else
    const size_t pkt_len = ip_len + udp_len + payload_len;
#endif

    unsigned char* packet = (unsigned char*)malloc(pkt_len);
    if (!packet) return EXIT_FAILURE;
    memset(packet, 0, pkt_len);

    struct ip* iph = (struct ip*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + ip_len);
    if (payload && payload_len)
    {
        memcpy(packet + ip_len + udp_len, payload, payload_len);
    }

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    iph->ip_len = (uint16_t)pkt_len;
#else
    iph->ip_len = htons((uint16_t)pkt_len);
#endif

    iph->ip_id = htons(0x7777);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_UDP;
    if (inet_pton(AF_INET, src_ip, &iph->ip_src) != 1)
    {
        std::cerr << "src ip invalid\n"; free(packet);
        return EXIT_FAILURE;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1)
    {
        std::cerr << "dst ip invalid\n"; free(packet);
        return EXIT_FAILURE;
    }

    udph->uh_sport = htons(40000 + (rand() % 20000));
    udph->uh_dport = htons(dst_port);
    udph->uh_ulen  = htons((uint16_t)(udp_len + payload_len));
    udph->uh_sum   = 0; // IPv4: checksum 0 allowed

    extern uint16_t csum16(const void*, size_t);
    iph->ip_sum = csum16(iph, sizeof(struct ip));

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0)
    {
        std::cerr << "raw UDP socket(): " << strerror(errno) << "\n";
        free(packet);
        return EXIT_FAILURE;
    }
    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        std::cerr << "IP_HDRINCL error\n";
        close(s);
        free(packet);
        return EXIT_FAILURE;
    }
    int snd = 4*1024*1024;
    (void)setsockopt(s, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    dst.sin_len = sizeof(dst);
#endif

    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1)
    {
        std::cerr << "dst addr invalid\n";
        close(s);
        free(packet);
        return EXIT_FAILURE;
    }

    const int max_retries = 3;  // set to 0 for no retries
    for (int i = 0; i < repeat; ++i) {
        // if you want to change uh_sport (UDP Src Port) per packet, do it here
        int tries = 0;
        for (;;) {
            ssize_t n = sendto(s, packet, pkt_len, 0, (sockaddr*)&dst, sizeof(dst));

            if (n >= 0)
            {
                break;
            }
            if (tries++ >= max_retries)
            {
                std::cerr << "sendto() error: " << strerror(errno) << "\n";
                break;
            }
            // retry
        }
    }

    close(s);
    free(packet);
    return EXIT_SUCCESS;
}
