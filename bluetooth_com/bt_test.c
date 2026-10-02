/*
 * Bluetooth LE ranging test between two Raspberry Pis, independent of SST.
 *
 * The responder advertises and listens on an LE L2CAP channel; the initiator
 * connects to it by address (bt_link.c: the same link the SST handshake
 * uses). Over that channel they exchange PING/PONG rounds, and on every
 * round each side reads the link's RSSI from its own controller. Each side
 * then estimates the distance from its median RSSI with the log-distance
 * path loss model,
 *     d = 10 ^ ((rssi_at_1m - rssi) / (10 * n)),
 * swaps its estimate with the peer over the channel, and judges its own.
 *
 * Usage (as root: advertising and raw HCI commands need CAP_NET_ADMIN):
 *   bt_test --role responder
 *   bt_test --role initiator --peer D8:3A:DD:2B:3A:03
 * Options: --rounds N (20) --interval-ms N (100) --psm N (0x80)
 *          --rssi-at-1m DBM (-60) --path-loss N (2.0) --max-distance-m M (2.0)
 *
 * Build: gcc -O2 -Wall -o bt_test bt_test.c bt_link.c -lbluetooth -lm
 */
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "bt_link.h"

#define IO_TIMEOUT_S 10
#define MAX_ROUNDS 1000
#define MSG_SIZE 4

enum { MSG_PING = 1, MSG_PONG = 2, MSG_REPORT = 3 };

/* Every message on the channel: type | seq (big-endian u16) | rssi (i8). */
typedef struct {
    uint8_t type;
    uint16_t seq;
    int8_t rssi;
} msg;

typedef struct {
    int initiator;
    const char* peer;
    int rounds;
    int interval_ms;
    unsigned psm;
    double rssi_at_1m;
    double path_loss;
    double max_distance_m;
} options;

static int send_msg(int sock, const msg* m) {
    uint8_t b[MSG_SIZE] = {m->type, (uint8_t)(m->seq >> 8), (uint8_t)m->seq,
                           (uint8_t)m->rssi};
    return write(sock, b, sizeof(b)) == (ssize_t)sizeof(b) ? 0 : -1;
}

/* The channel is a byte stream, so a message may arrive in pieces. */
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
    m->seq = (uint16_t)(b[1] << 8 | b[2]);
    m->rssi = (int8_t)b[3];
    return 0;
}

static int set_io_timeout(int sock) {
    struct timeval tv = {.tv_sec = IO_TIMEOUT_S};
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ||
                   setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))
               ? -1
               : 0;
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

/* Initiator: PING, then sample. Responder: sample, then PONG. Either way
 * one sample per round per side, spaced by the initiator's interval. */
static int run_rounds(const options* o, int sock, int8_t* samples) {
    for (int i = 0; i < o->rounds; ++i) {
        msg m = {0};
        if (o->initiator) {
            m = (msg){MSG_PING, (uint16_t)i, 0};
            if (send_msg(sock, &m) || recv_msg(sock, MSG_PONG, &m) ||
                m.seq != i)
                return -1;
        } else if (recv_msg(sock, MSG_PING, &m) || m.seq != i) {
            return -1;
        }
        if (bt_link_read_rssi(sock, &samples[i])) return -1;
        if (!o->initiator) {
            m = (msg){MSG_PONG, (uint16_t)i, samples[i]};
            if (send_msg(sock, &m)) return -1;
        }
        printf("LOG: round %d rssi=%d dBm\n", i, samples[i]);
        if (o->initiator && i + 1 < o->rounds) usleep(o->interval_ms * 1000);
    }
    return 0;
}

static int run(const options* o) {
    int sock;
    if (o->initiator) {
        printf("LOG: connecting to %s on LE PSM 0x%02x...\n", o->peer, o->psm);
        sock = bt_link_connect(o->peer, o->psm);
    } else {
        printf(
            "LOG: advertising; waiting for the initiator on LE PSM "
            "0x%02x...\n",
            o->psm);
        sock = bt_link_accept(o->psm);
    }
    if (sock < 0) return 1;
    printf("LOG: connected\n");
    int status = 1;
    int8_t samples[MAX_ROUNDS];
    if (set_io_timeout(sock) || run_rounds(o, sock, samples)) goto out;

    double mine = median(samples, o->rounds);
    double d = distance_m(o, mine);
    int pass = d <= o->max_distance_m;
    /* Initiator reports first: median rounded to dBm, distance in cm
     * (saturating at 655.35 m). */
    msg me = {MSG_REPORT, (uint16_t)fmin(lround(d * 100), 65535),
              (int8_t)lround(mine)};
    msg peer;
    if (o->initiator ? send_msg(sock, &me) || recv_msg(sock, MSG_REPORT, &peer)
                     : recv_msg(sock, MSG_REPORT, &peer) || send_msg(sock, &me))
        goto out;

    printf(
        "LOG: BT RANGE: local median_rssi=%.1f dBm distance_m=%.2f "
        "max_distance_m=%.2f result=%s\n",
        mine, d, o->max_distance_m, pass ? "PASS" : "FAIL");
    printf("LOG: BT RANGE: peer median_rssi=%d dBm distance_m=%.2f\n",
           peer.rssi, peer.seq / 100.0);
    printf("LOG: BT RANGE: model rssi_at_1m=%.1f path_loss=%.2f rounds=%d\n",
           o->rssi_at_1m, o->path_loss, o->rounds);
    status = pass ? 0 : 2;
out:
    close(sock);
    return status;
}

static void usage(const char* p) {
    fprintf(stderr,
            "Usage: %s --role initiator|responder [--peer BDADDR]\n"
            "  [--rounds N] [--interval-ms N] [--psm N] [--rssi-at-1m DBM]\n"
            "  [--path-loss N] [--max-distance-m M]\n",
            p);
}

int main(int argc, char** argv) {
    options o = {.initiator = -1,
                 .rounds = 20,
                 .interval_ms = 100,
                 .psm = BT_LINK_DEFAULT_PSM,
                 .rssi_at_1m = -60,
                 .path_loss = 2.0,
                 .max_distance_m = 2.0};
    for (int i = 1; i < argc; ++i) {
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) {
            usage(argv[0]);
            return 1;
        }
        if (!strcmp(argv[i], "--role"))
            o.initiator = !strcmp(v, "initiator")   ? 1
                          : !strcmp(v, "responder") ? 0
                                                    : -1;
        else if (!strcmp(argv[i], "--peer"))
            o.peer = v;
        else if (!strcmp(argv[i], "--rounds"))
            o.rounds = atoi(v);
        else if (!strcmp(argv[i], "--interval-ms"))
            o.interval_ms = atoi(v);
        else if (!strcmp(argv[i], "--psm"))
            o.psm = (unsigned)strtoul(v, NULL, 0);
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
        ++i;
    }
    /* LE dynamic PSMs are 0x80..0xff. */
    if (o.initiator < 0 || (o.initiator && !o.peer) || o.rounds < 1 ||
        o.rounds > MAX_ROUNDS || o.interval_ms < 0 || o.psm < 0x80 ||
        o.psm > 0xff || o.path_loss <= 0 || o.max_distance_m <= 0) {
        usage(argv[0]);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    return run(&o);
}
