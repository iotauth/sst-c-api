/* Mutual Bluetooth RSSI proximity check: plan parsing and the sampling and
 * report exchange over an SST session. Plan reading uses the same bounded
 * tokenizer as ultrasonic_com/ultrasonic_echo_plan.c; fields are looked up
 * only in their owning object, never by substring search. */
#include "bt_rssi.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#include "../src/c_common.h"

typedef struct {
    const char *start, *end;
    int next;
    char type;
} token;
typedef struct {
    const char* p;
    token t[256];
    int count;
} parser;
static void space(parser* p) {
    while (isspace((unsigned char)*p->p)) ++p->p;
}
static int value(parser* p, unsigned depth) {
    space(p);
    if (depth > 16 || p->count == 256 || !*p->p) return -1;
    int i = p->count++;
    token* t = &p->t[i];
    t->start = p->p;
    t->type = *p->p;
    if (*p->p == '{' || *p->p == '[') {
        char close = *p->p++ == '{' ? '}' : ']';
        space(p);
        if (*p->p != close)
            for (;;) {
                if (close == '}') {
                    space(p);
                    if (*p->p != '"' || value(p, depth + 1) < 0) return -1;
                    space(p);
                    if (*p->p++ != ':') return -1;
                }
                if (value(p, depth + 1) < 0) return -1;
                space(p);
                if (*p->p == close) break;
                if (*p->p++ != ',') return -1;
            }
        ++p->p;
    } else if (*p->p == '"') {
        ++p->p;
        while (*p->p && *p->p != '"') {
            if ((unsigned char)*p->p < 32) return -1;
            if (*p->p++ == '\\') {
                if (*p->p == 'u') {
                    ++p->p;
                    for (int j = 0; j < 4; ++j)
                        if (!isxdigit((unsigned char)*p->p++)) return -1;
                } else if (*p->p && strchr("\"\\/bfnrt", *p->p))
                    ++p->p;
                else
                    return -1;
            }
        }
        if (*p->p++ != '"') return -1;
    } else if (*p->p == '-' || isdigit((unsigned char)*p->p)) {
        t->type = 'n';
        if (*p->p == '-') ++p->p;
        if (*p->p == '0')
            ++p->p;
        else {
            if (!isdigit((unsigned char)*p->p)) return -1;
            while (isdigit((unsigned char)*p->p)) ++p->p;
        }
        if (*p->p == '.') {
            ++p->p;
            if (!isdigit((unsigned char)*p->p)) return -1;
            while (isdigit((unsigned char)*p->p)) ++p->p;
        }
        if (*p->p == 'e' || *p->p == 'E') {
            ++p->p;
            if (*p->p == '+' || *p->p == '-') ++p->p;
            if (!isdigit((unsigned char)*p->p)) return -1;
            while (isdigit((unsigned char)*p->p)) ++p->p;
        }
    } else {
        const char* word = *p->p == 't'   ? "true"
                           : *p->p == 'f' ? "false"
                                          : "null";
        if (strncmp(p->p, word, strlen(word))) return -1;
        p->p += strlen(word);
    }
    t->end = p->p;
    t->next = p->count;
    return i;
}
static int eq(const token* t, const char* s) {
    return t->type == '"' && (size_t)(t->end - t->start) == strlen(s) + 2 &&
           !memcmp(t->start + 1, s, strlen(s));
}
static int field(const parser* p, int object, const char* name) {
    if (object < 0 || p->t[object].type != '{') return -1;
    int found = -1;
    for (int i = object + 1; i < p->t[object].next;) {
        int v = i + 1;
        if (eq(&p->t[i], name)) {
            if (found >= 0) return -2;
            found = v;
        }
        i = p->t[v].next;
    }
    return found;
}
/* JSON integer (optionally negative) within [min, max]; fractions and
 * exponents reject. */
static int integer(const parser* p, int i, long min, long max, long* out) {
    if (i < 0 || p->t[i].type != 'n') return -1;
    const char* s = p->t[i].start;
    int negative = *s == '-';
    if (negative) ++s;
    if (s == p->t[i].end) return -1;
    long v = 0;
    for (; s < p->t[i].end; ++s) {
        if (!isdigit((unsigned char)*s)) return -1;
        v = v * 10 + (*s - '0');
        if (v > 1000000) return -1;
    }
    if (negative) v = -v;
    if (v < min || v > max) return -1;
    *out = v;
    return 0;
}

int bt_rssi_config_valid(const bt_rssi_config* c) {
    return c && c->min_rssi_dbm >= BT_RSSI_MIN_DBM_LIMIT &&
           c->min_rssi_dbm <= BT_RSSI_MAX_DBM_LIMIT && c->samples >= 1 &&
           c->samples <= BT_RSSI_MAX_SAMPLES &&
           c->interval_ms <= BT_RSSI_MAX_INTERVAL_MS;
}

int bt_rssi_plan_config(const char* plan, bt_rssi_config* c) {
    if (!plan || !c || strlen(plan) >= MAX_CHALLENGE_LENGTH) return -1;
    parser p = {.p = plan, .count = 0};
    if (value(&p, 0) != 0) return -1;
    space(&p);
    if (*p.p || p.t[0].type != '{') return -1;
    int required = field(&p, 0, "requiredChecks"), required_co = 0;
    if (required < 0 || p.t[required].type != '[') return -1;
    for (int i = required + 1; i < p.t[required].next; i = p.t[i].next) {
        if (p.t[i].type != '"') return -1;
        if (eq(&p.t[i], "CO_LOCATION")) required_co = 1;
    }
    int checks = field(&p, 0, "verificationPlan");
    if (checks < 0 || p.t[checks].type != '{') return -1;
    int co = field(&p, checks, "CO_LOCATION");
    if (co == -1 && !required_co) return 0;
    if (co < 0) return -1;
    int selected = field(&p, co, "selectedMethod");
    int method = field(&p, selected, "method");
    if (method < 0) return -1;
    if (eq(&p.t[method], "DUMMY")) return 0;
    int topology = field(&p, co, "topology");
    if (!eq(&p.t[method], "BLE_RSSI") || topology < 0 ||
        !eq(&p.t[topology], "MUTUAL"))
        return -1;
    int params = field(&p, selected, "parameters");
    if (params < 0 || p.t[params].type != '{') return -1;
    long min_rssi, samples, interval;
    if (integer(&p, field(&p, params, "min_rssi_dbm"), BT_RSSI_MIN_DBM_LIMIT,
                BT_RSSI_MAX_DBM_LIMIT, &min_rssi) ||
        integer(&p, field(&p, params, "samples"), 1, BT_RSSI_MAX_SAMPLES,
                &samples) ||
        integer(&p, field(&p, params, "interval_ms"), 0,
                BT_RSSI_MAX_INTERVAL_MS, &interval))
        return -1;
    c->min_rssi_dbm = (int)min_rssi;
    c->samples = (unsigned)samples;
    c->interval_ms = (unsigned)interval;
    return bt_rssi_config_valid(c) ? 1 : -1;
}

/* REPORT, inside a secure message: 'B' 'R' version | pass | median (i8). */
#define REPORT_SIZE 5
/* Bounds the wait for the peer's report beyond its own sampling time. */
#define CONTROL_SLACK_MS 15000u

static void sleep_ms(unsigned ms) {
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0) {
    }
}

static int cmp_i8(const void* a, const void* b) {
    return *(const int8_t*)a - *(const int8_t*)b;
}

static int send_report(SST_session_ctx_t* s, const bt_rssi_result* r) {
    long m = r->median_rssi_dbm < 0 ? (long)(r->median_rssi_dbm - 0.5)
                                    : (long)(r->median_rssi_dbm + 0.5);
    unsigned char msg[REPORT_SIZE] = {'B', 'R', BT_RSSI_VERSION,
                                      (unsigned char)r->local_pass,
                                      (unsigned char)(int8_t)m};
    return send_secure_message((char*)msg, sizeof(msg), s) < 0 ? -1 : 0;
}

static int recv_report(SST_session_ctx_t* s, bt_rssi_result* r) {
    unsigned char buf[MAX_SECURE_COMM_MSG_LENGTH];
    int n = read_secure_message(buf, s);
    if (n != REPORT_SIZE || buf[0] != 'B' || buf[1] != 'R' ||
        buf[2] != BT_RSSI_VERSION || buf[3] > 1) {
        SST_print_error(
            "BLE RSSI: peer report not received or malformed (timeout, "
            "disconnect or error).");
        return -1;
    }
    r->peer_reported = 1;
    r->peer_reported_pass = buf[3];
    r->peer_median_rssi_dbm = (int8_t)buf[4];
    return 0;
}

int bt_rssi_run(SST_session_ctx_t* session, const bt_rssi_config* c,
                int initiator, bt_rssi_reader read_rssi, void* reader_ctx,
                bt_rssi_result* r) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!session || session->sock < 0 || !bt_rssi_config_valid(c) || !read_rssi)
        return -1;
    int8_t samples[BT_RSSI_MAX_SAMPLES];
    for (unsigned i = 0; i < c->samples; ++i) {
        if (i && c->interval_ms) sleep_ms(c->interval_ms);
        if (read_rssi(reader_ctx, &samples[i])) {
            SST_print_error("BLE RSSI: reading RSSI failed.");
            return -1;
        }
        r->samples = i + 1;
    }
    qsort(samples, c->samples, sizeof(*samples), cmp_i8);
    unsigned n = c->samples;
    r->median_rssi_dbm =
        n % 2 ? samples[n / 2] : (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
    r->local_pass = r->median_rssi_dbm >= c->min_rssi_dbm;

    /* The peer may still be sampling, for up to as long as this side did. */
    unsigned wait_ms = c->samples * c->interval_ms + CONTROL_SLACK_MS;
    struct timeval saved,
        tv = {(time_t)(wait_ms / 1000), (suseconds_t)(wait_ms % 1000) * 1000};
    socklen_t saved_len = sizeof(saved);
    int restore = getsockopt(session->sock, SOL_SOCKET, SO_RCVTIMEO, &saved,
                             &saved_len) == 0;
    if (setsockopt(session->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
        return -1;
    int rc = initiator ? send_report(session, r) || recv_report(session, r)
                       : recv_report(session, r) || send_report(session, r);
    if (restore)
        setsockopt(session->sock, SOL_SOCKET, SO_RCVTIMEO, &saved,
                   sizeof(saved));
    if (rc) return -1;
    return r->local_pass ? 1 : 0;
}
