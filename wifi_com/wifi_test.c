/*
 * Wi-Fi RSSI ranging test between two Raspberry Pis, independent of SST.
 *
 * Runs over the direct link from wifi_link.sh on each Pi's USB dongle: one
 * Pi is the AP (192.168.77.1), the other joins it as a station. Over a TCP
 * connection on that link they exchange PING/PONG rounds, and on every round
 * each side reads the RSSI of the last frame it received from the other
 * from its own dongle (`iw dev IFACE station dump`, via wifi_rssi.c: on the
 * AP that entry is the station, on the station it is the AP). Each side then
 * estimates the distance from its median RSSI with the log-distance path
 * loss model,
 *     d = 10 ^ ((rssi_at_1m - rssi) / (10 * n)),
 * swaps its estimate with the peer, and judges its own.
 *
 * Usage:
 *   wifi_test --role ap                               # on the AP Pi
 *   wifi_test --role station --peer 192.168.77.1      # on the station Pi
 * Options: --iface IF (wlan1) --bind IP (ap: 192.168.77.1) --port N (21200)
 *          --rounds N (20) --interval-ms N (100) --rssi-at-1m DBM (-40)
 *          --path-loss N (2.0) --max-distance-m M (2.0)
 *
 * Build: gcc -O2 -Wall -o wifi_test wifi_test.c wifi_rssi.c -lm
 */
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "wifi_rssi.h"

#define IO_TIMEOUT_S 10
#define MAX_ROUNDS 1000
#define MSG_SIZE 4

enum { MSG_PING = 1, MSG_PONG = 2, MSG_REPORT = 3 };

/* Every message: type | value (big-endian u16) | rssi (i8). PING/PONG
 * carry the round number; REPORT carries the sender's distance in cm with
 * its verdict in the top bit. */
typedef struct {
    uint8_t type;
    uint16_t value;
    int8_t rssi;
} msg;

typedef struct {
    int station; /* 1: station (connects, sends PING), 0: AP (answers) */
    const char* peer;
    const char* iface;
    const char* bind_ip; /* AP: accept only on the test link */
    int port;
    int rounds;
    int interval_ms;
    double rssi_at_1m;
    double path_loss;
    double max_distance_m;
} options;

static int send_msg(int sock, const msg* m) {
    uint8_t b[MSG_SIZE] = {m->type, (uint8_t)(m->value >> 8), (uint8_t)m->value,
                           (uint8_t)m->rssi};
    return write(sock, b, sizeof(b)) == (ssize_t)sizeof(b) ? 0 : -1;
}

/* TCP is a byte stream, so a message may arrive in pieces. */
static int recv_msg(int sock, uint8_t type, msg* m) {
    uint8_t b[MSG_SIZE];
    size_t got = 0;
    while (got < sizeof(b)) {
        ssize_t n = read(sock, b + got, sizeof(b) - got);
        if (n <= 0) {
            fprintf(stderr, "ERROR: expected message type %u: %s\n", type,
                    n < 0 ? strerror(errno) : "peer disconnected");
            return -1;
        }
        got += (size_t)n;
    }
    if (b[0] != type) {
        fprintf(stderr, "ERROR: expected message type %u, got %u\n", type,
                b[0]);
        return -1;
    }
    m->type = b[0];
    m->value = (uint16_t)(b[1] << 8 | b[2]);
    m->rssi = (int8_t)b[3];
    return 0;
}

static int set_io_timeout(int sock) {
    struct timeval tv = {.tv_sec = IO_TIMEOUT_S};
    int one = 1;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ||
                   setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) ||
                   setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))
               ? -1
               : 0;
}

static int accept_peer(const char* bind_ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1) {
        fprintf(stderr, "ERROR: bad bind address %s\n", bind_ip);
        return -1;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    if (ls < 0 || setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
        bind(ls, (struct sockaddr*)&a, sizeof(a)) || listen(ls, 1)) {
        perror("ERROR: listen");
        if (ls >= 0) close(ls);
        return -1;
    }
    int sock = accept(ls, NULL, NULL);
    close(ls);
    if (sock < 0) perror("ERROR: accept");
    return sock;
}

static int connect_peer(const char* peer, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, peer, &a.sin_addr) != 1) {
        fprintf(stderr, "ERROR: bad peer address %s\n", peer);
        return -1;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (struct sockaddr*)&a, sizeof(a))) {
        perror("ERROR: connect");
        if (sock >= 0) close(sock);
        return -1;
    }
    return sock;
}

static int cmp_i8(const void* a, const void* b) {
    return *(const int8_t*)a - *(const int8_t*)b;
}

static double median(int8_t* v, int n) {
    qsort(v, (size_t)n, sizeof(*v), cmp_i8);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

static double distance_m(const options* o, double rssi) {
    return pow(10.0, (o->rssi_at_1m - rssi) / (10.0 * o->path_loss));
}

/* Station: PING, then sample after the PONG. AP: sample after the PING,
 * then PONG. Either way each sample follows a frame just received from the
 * peer, one per round per side, spaced by the station's interval. */
static int run_rounds(const options* o, int sock, int8_t* samples) {
    for (int i = 0; i < o->rounds; ++i) {
        msg m = {0};
        if (o->station) {
            m = (msg){MSG_PING, (uint16_t)i, 0};
            if (send_msg(sock, &m) || recv_msg(sock, MSG_PONG, &m) ||
                m.value != i)
                return -1;
        } else if (recv_msg(sock, MSG_PING, &m) || m.value != i) {
            return -1;
        }
        if (wifi_rssi_read(o->iface, &samples[i])) return -1;
        if (!o->station) {
            m = (msg){MSG_PONG, (uint16_t)i, samples[i]};
            if (send_msg(sock, &m)) return -1;
        }
        printf("LOG: round %d rssi=%d dBm\n", i, samples[i]);
        if (o->station && i + 1 < o->rounds) usleep(o->interval_ms * 1000);
    }
    return 0;
}

static int run(const options* o) {
    int sock;
    if (o->station) {
        printf("LOG: connecting to %s:%d over %s...\n", o->peer, o->port,
               o->iface);
        sock = connect_peer(o->peer, o->port);
    } else {
        printf("LOG: waiting for the station on %s:%d (%s)...\n", o->bind_ip,
               o->port, o->iface);
        sock = accept_peer(o->bind_ip, o->port);
    }
    if (sock < 0) return 1;
    printf("LOG: connected\n");
    int status = 1;
    int8_t samples[MAX_ROUNDS];
    if (set_io_timeout(sock) || run_rounds(o, sock, samples)) goto out;

    double mine = median(samples, o->rounds);
    double d = distance_m(o, mine);
    int pass = d <= o->max_distance_m;
    /* Distance in cm saturates at 327.67 m; the top bit is the verdict. The
     * station reports first. */
    msg me = {MSG_REPORT,
              (uint16_t)((uint16_t)fmin(lround(d * 100), 0x7fff) |
                         (pass ? 0x8000 : 0)),
              (int8_t)lround(mine)};
    msg peer;
    if (o->station ? send_msg(sock, &me) || recv_msg(sock, MSG_REPORT, &peer)
                   : recv_msg(sock, MSG_REPORT, &peer) || send_msg(sock, &me))
        goto out;

    printf(
        "LOG: WIFI RANGE: local median_rssi=%.1f dBm distance_m=%.2f "
        "max_distance_m=%.2f result=%s\n",
        mine, d, o->max_distance_m, pass ? "PASS" : "FAIL");
    printf(
        "LOG: WIFI RANGE: peer median_rssi=%d dBm distance_m=%.2f "
        "result=%s\n",
        peer.rssi, (peer.value & 0x7fff) / 100.0,
        peer.value & 0x8000 ? "PASS" : "FAIL");
    printf("LOG: WIFI RANGE: model rssi_at_1m=%.1f path_loss=%.2f rounds=%d\n",
           o->rssi_at_1m, o->path_loss, o->rounds);
    status = pass ? 0 : 2;
out:
    close(sock);
    return status;
}

static void usage(const char* p) {
    fprintf(stderr,
            "Usage: %s --role station|ap [--peer IP] [--iface IF]\n"
            "  [--bind IP] [--port N] [--rounds N] [--interval-ms N]\n"
            "  [--rssi-at-1m DBM] [--path-loss N] [--max-distance-m M]\n",
            p);
}

int main(int argc, char** argv) {
    options o = {.station = -1,
                 .iface = "wlan1",
                 .bind_ip = "192.168.77.1",
                 .port = 21200,
                 .rounds = 20,
                 .interval_ms = 100,
                 .rssi_at_1m = -40,
                 .path_loss = 2.0,
                 .max_distance_m = 2.0};
    for (int i = 1; i < argc; i += 2) {
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) {
            usage(argv[0]);
            return 1;
        }
        if (!strcmp(argv[i], "--role"))
            o.station = !strcmp(v, "station") ? 1 : !strcmp(v, "ap") ? 0 : -1;
        else if (!strcmp(argv[i], "--peer"))
            o.peer = v;
        else if (!strcmp(argv[i], "--iface"))
            o.iface = v;
        else if (!strcmp(argv[i], "--bind"))
            o.bind_ip = v;
        else if (!strcmp(argv[i], "--port"))
            o.port = atoi(v);
        else if (!strcmp(argv[i], "--rounds"))
            o.rounds = atoi(v);
        else if (!strcmp(argv[i], "--interval-ms"))
            o.interval_ms = atoi(v);
        else if (!strcmp(argv[i], "--rssi-at-1m"))
            o.rssi_at_1m = atof(v);
        else if (!strcmp(argv[i], "--path-loss"))
            o.path_loss = atof(v);
        else if (!strcmp(argv[i], "--max-distance-m"))
            o.max_distance_m = atof(v);
        else {
            usage(argv[0]);
            return 1;
        }
    }
    if (o.station < 0 || (o.station && !o.peer) || o.rounds < 1 ||
        o.rounds > MAX_ROUNDS || o.interval_ms < 0 || o.port < 1 ||
        o.port > 65535 || o.path_loss <= 0 || o.max_distance_m <= 0) {
        usage(argv[0]);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    return run(&o);
}
