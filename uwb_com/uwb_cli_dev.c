#include "uwb_cli_dev.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../src/c_common.h"

#define DEVICE_GLOB \
    "/dev/serial/by-id/usb-Nordic_Semiconductor_nRF52_USB_Product_*"
#define CMD_TIMEOUT_MS 3000
/* FiRa DS-TWR, BPRF set 4, 2400 rstu slots, 200 ms ranging period, 25-slot
 * rounds, deferred DS-TWR, unicast, no round hopping, initiator 0,
 * responder 1. The session ID and vupper64 are filled in per direction. */
#define FIRA_FMT "%s 4 2400 200 25 2 %u %s 0 0 0 1"

struct uwb_cli {
    int fd;
    char buf[1024];
    size_t len;
    /* While responding, the board keeps printing results nobody waits
     * for; this drains them so the USB serial buffer never fills up. */
    pthread_t drain;
    int draining;
    volatile int stop_drain;
};

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int send_line(uwb_cli* c, const char* line) {
    char out[160];
    int n = snprintf(out, sizeof(out), "%s\r\n", line);
    if (n < 0 || (size_t)n >= sizeof(out)) return -1;
    for (int off = 0; off < n;) {
        ssize_t w = write(c->fd, out + off, (size_t)(n - off));
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            SST_print_error("UWB CLI: write failed.");
            return -1;
        }
        off += (int)w;
    }
    return 0;
}

/* Next complete line (without CR/LF) into `line`, waiting until deadline.
 * @return 1 for a line, 0 on timeout, -1 on error. */
static int read_line(uwb_cli* c, char* line, size_t cap, uint64_t deadline) {
    for (;;) {
        char* nl = memchr(c->buf, '\n', c->len);
        if (nl) {
            size_t n = (size_t)(nl - c->buf);
            size_t keep = n < cap - 1 ? n : cap - 1;
            memcpy(line, c->buf, keep);
            line[keep] = 0;
            if (keep && line[keep - 1] == '\r') line[keep - 1] = 0;
            memmove(c->buf, nl + 1, c->len - n - 1);
            c->len -= n + 1;
            return 1;
        }
        if (c->len == sizeof(c->buf)) c->len = 0; /* overlong line: drop */
        uint64_t t = now_ms();
        if (t >= deadline) return 0;
        struct pollfd p = {.fd = c->fd, .events = POLLIN};
        int r = poll(&p, 1, (int)(deadline - t));
        if (r < 0 && errno != EINTR) return -1;
        if (r <= 0) continue;
        ssize_t got = read(c->fd, c->buf + c->len, sizeof(c->buf) - c->len);
        if (got < 0 && errno != EAGAIN && errno != EINTR) return -1;
        if (got == 0) return -1; /* device gone */
        if (got > 0) c->len += (size_t)got;
    }
}

#define CMD_REJECTED (-2)
/* Sends a command and waits for the CLI's "ok".
 * @return 0, CMD_REJECTED for an "error ..." reply, or -1. */
static int command(uwb_cli* c, const char* cmd) {
    char line[512];
    if (send_line(c, cmd)) return -1;
    uint64_t deadline = now_ms() + CMD_TIMEOUT_MS;
    while (read_line(c, line, sizeof(line), deadline) == 1) {
        if (!strcmp(line, "ok")) return 0;
        if (!strncmp(line, "error", 5)) return CMD_REJECTED;
    }
    SST_print_error("UWB CLI: no \"ok\" for \"%s\".", cmd);
    return -1;
}

/* "stop" is acknowledged at once, but the FiRa session only ends ~100 ms
 * later ({"Session Stopped":...}); until then a new INITF/RESPF is refused
 * with "error incompatible mode", so it is retried for a while. */
#define START_RETRY_MS 100
#define START_RETRIES 20

static int fira_command(uwb_cli* c, const char* app,
                        const uwb_range_session* s) {
    char vupper[3 * UWB_RANGE_VUPPER64_SIZE], cmd[160];
    for (int i = 0; i < UWB_RANGE_VUPPER64_SIZE; ++i)
        snprintf(vupper + 3 * i, 4, "%02x%s", s->vupper64[i],
                 i + 1 < UWB_RANGE_VUPPER64_SIZE ? ":" : "");
    snprintf(cmd, sizeof(cmd), FIRA_FMT, app, (unsigned)s->session_id, vupper);
    if (command(c, "stop")) return -1;
    for (int i = 0; i < START_RETRIES; ++i) {
        int rc = command(c, cmd);
        if (rc != CMD_REJECTED) return rc;
        struct timespec ts = {0, START_RETRY_MS * 1000000L};
        nanosleep(&ts, NULL);
    }
    SST_print_error("UWB CLI: \"%s\" kept being refused.", cmd);
    return -1;
}

static void* drain(void* ctx) {
    uwb_cli* c = ctx;
    char line[512];
    while (!c->stop_drain) {
        if (read_line(c, line, sizeof(line), now_ms() + 100) < 0) break;
    }
    return NULL;
}

static int stop(void* ctx) {
    uwb_cli* c = ctx;
    if (c->draining) {
        c->stop_drain = 1;
        pthread_join(c->drain, NULL);
        c->draining = 0;
    }
    return command(c, "stop");
}

static int respond(void* ctx, const uwb_range_session* s) {
    uwb_cli* c = ctx;
    if (fira_command(c, "respf", s)) return -1;
    c->stop_drain = 0;
    if (pthread_create(&c->drain, NULL, drain, c)) return -1;
    c->draining = 1;
    return 0;
}

/* Collects distances from result lines such as
 * {"Block":3, "results":[{"Addr":"0x0001","Status":"Ok","D_cm":62,...}]} */
static int initiate(void* ctx, const uwb_range_session* s, unsigned samples,
                    unsigned timeout_ms, int* distances_cm) {
    uwb_cli* c = ctx;
    uint64_t deadline = now_ms() + timeout_ms;
    if (fira_command(c, "initf", s)) return -1;
    char line[512];
    unsigned n = 0;
    int r = 0;
    while (n < samples &&
           (r = read_line(c, line, sizeof(line), deadline)) == 1) {
        const char* d = strstr(line, "\"D_cm\":");
        if (!strstr(line, "\"Block\"") || !strstr(line, "\"Status\":\"Ok\"") ||
            !d)
            continue;
        char* end;
        long v = strtol(d + 7, &end, 10);
        if (end != d + 7) distances_cm[n++] = (int)v;
    }
    return r < 0 && n < samples ? -1 : (int)n;
}

uwb_cli* uwb_cli_open(const char* device) {
    glob_t g = {0};
    if (!device) {
        if (glob(DEVICE_GLOB, 0, NULL, &g) != 0 || g.gl_pathc != 1) {
            SST_print_error("UWB CLI: expected exactly one %s.", DEVICE_GLOB);
            globfree(&g);
            return NULL;
        }
        device = g.gl_pathv[0];
    }
    int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        SST_print_error("UWB CLI: cannot open %s.", device);
        globfree(&g);
        return NULL;
    }
    globfree(&g);
    struct termios t;
    if (tcgetattr(fd, &t) == 0) {
        cfmakeraw(&t);
        cfsetispeed(&t, B115200);
        cfsetospeed(&t, B115200);
        t.c_cflag |= CLOCAL | CREAD;
        tcsetattr(fd, TCSANOW, &t);
    }
    tcflush(fd, TCIOFLUSH);
    uwb_cli* c = calloc(1, sizeof(*c));
    if (!c) {
        close(fd);
        return NULL;
    }
    c->fd = fd;
    if (command(c, "stop")) {
        uwb_cli_close(c);
        return NULL;
    }
    return c;
}

void uwb_cli_close(uwb_cli* c) {
    if (!c) return;
    if (c->draining) stop(c);
    close(c->fd);
    free(c);
}

void uwb_cli_bind(uwb_cli* c, uwb_range_radio* radio) {
    radio->ctx = c;
    radio->respond = respond;
    radio->initiate = initiate;
    radio->stop = stop;
}
