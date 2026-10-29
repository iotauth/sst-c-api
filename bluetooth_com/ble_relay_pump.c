/*
 * Connection-oriented BLE<->TCP relay (byte pump) for the BLE timing relay
 * experiment. Forwards raw bytes between an LE L2CAP channel (bt_link.c) and a
 * TCP connection, in both directions, WITHOUT any session/MAC key -- it only
 * moves the challenge and response frames, so its forwarding delay shows up in
 * the verifier's measured RTT (mafia fraud).
 *
 * Chain:  Robot --BLE-- Relay1(near-robot) --TCP-- Relay2(near-locker) --BLE-- Locker
 *
 * near-robot: BLE peripheral toward the Robot (advertise+accept) <-> TCP client
 *             to Relay2.
 * near-locker: TCP server (accept from Relay1) <-> BLE central to the Locker.
 *
 * Bring-up order (so no side blocks forever): start the Locker responder first,
 * then near-locker (connects BLE to the Locker, then listens for Relay1), then
 * near-robot (connects TCP to Relay2, then advertises for the Robot), then the
 * Robot initiator.
 *
 * Usage (root: advertising + raw HCI):
 *   ble_relay_pump --mode near-locker --port 47030 --locker <BDADDR> [--psm 0x80]
 *   ble_relay_pump --mode near-robot  --relay2 <IP> --port 47030     [--psm 0x80]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bt_link.h"

static int tcp_listen_accept(unsigned port) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return -1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = INADDR_ANY};
    if (bind(ls, (struct sockaddr*)&a, sizeof(a)) || listen(ls, 1)) {
        perror("bind/listen"); close(ls); return -1;
    }
    printf("LOG: relay TCP listening on %u...\n", port);
    int s = accept(ls, NULL, NULL);
    close(ls);
    if (s < 0) { perror("accept"); return -1; }
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return s;
}

static int tcp_connect(const char* ip, unsigned port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        fprintf(stderr, "bad ip %s\n", ip); close(s); return -1;
    }
    if (connect(s, (struct sockaddr*)&a, sizeof(a))) {
        perror("connect"); close(s); return -1;
    }
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    printf("LOG: relay TCP connected to %s:%u\n", ip, port);
    return s;
}

/* Pump bytes both ways between a and b until either closes. */
static void pump(int a, int b) {
    struct pollfd p[2] = {{.fd = a, .events = POLLIN}, {.fd = b, .events = POLLIN}};
    unsigned char buf[4096];
    printf("LOG: relay pumping...\n");
    for (;;) {
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < 2; ++i) {
            if (p[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                int src = i ? b : a, dst = i ? a : b;
                ssize_t n = read(src, buf, sizeof(buf));
                if (n <= 0) { printf("LOG: relay closed (fd %d)\n", src); return; }
                ssize_t off = 0;
                while (off < n) {
                    ssize_t w = write(dst, buf + off, n - off);
                    if (w <= 0) { if (w < 0 && errno == EINTR) continue;
                                  printf("LOG: relay write failed\n"); return; }
                    off += w;
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    const char *mode = NULL, *relay2 = NULL, *locker = NULL;
    unsigned port = 47030, psm = BT_LINK_DEFAULT_PSM;
    for (int i = 1; i < argc; ++i) {
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(argv[i], "--mode") && v) mode = v;
        else if (!strcmp(argv[i], "--relay2") && v) relay2 = v;
        else if (!strcmp(argv[i], "--locker") && v) locker = v;
        else if (!strcmp(argv[i], "--port") && v) port = (unsigned)atoi(v);
        else if (!strcmp(argv[i], "--psm") && v) psm = (unsigned)strtoul(v, NULL, 0);
        else { fprintf(stderr, "bad arg %s\n", argv[i]); return 1; }
        if (v) ++i;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!mode) { fprintf(stderr, "need --mode near-robot|near-locker\n"); return 1; }

    int ble = -1, tcp = -1;
    if (!strcmp(mode, "near-locker")) {
        if (!locker) { fprintf(stderr, "near-locker needs --locker BDADDR\n"); return 1; }
        printf("LOG: near-locker connecting BLE to locker %s...\n", locker);
        ble = bt_link_connect(locker, psm);
        if (ble < 0) return 1;
        printf("LOG: near-locker BLE connected; waiting for Relay1 on TCP\n");
        tcp = tcp_listen_accept(port);
    } else if (!strcmp(mode, "near-robot")) {
        if (!relay2) { fprintf(stderr, "near-robot needs --relay2 IP\n"); return 1; }
        tcp = tcp_connect(relay2, port);
        if (tcp < 0) return 1;
        printf("LOG: near-robot advertising BLE for the robot...\n");
        ble = bt_link_accept(psm);
    } else {
        fprintf(stderr, "bad --mode %s\n", mode); return 1;
    }
    if (ble < 0 || tcp < 0) { if (ble >= 0) close(ble); if (tcp >= 0) close(tcp); return 1; }
    pump(ble, tcp);
    close(ble); close(tcp);
    return 0;
}
