/* Mutual UWB ranging check: plan parsing and the two-direction exchange
 * over an SST session. Plan reading uses the same bounded tokenizer as
 * bluetooth_com/bt_rssi.c; fields are looked up only in their owning
 * object, never by substring search. */
#include "uwb_range.h"

#include <ctype.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

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

int uwb_range_config_valid(const uwb_range_config* c) {
    return c && c->max_distance_cm >= 1 &&
           c->max_distance_cm <= UWB_RANGE_MAX_DISTANCE_CM_LIMIT &&
           c->samples >= 1 && c->samples <= UWB_RANGE_MAX_SAMPLES &&
           c->timeout_ms >= 1 && c->timeout_ms <= UWB_RANGE_TIMEOUT_MS_LIMIT;
}

int uwb_range_plan_config(const char* plan, uwb_range_config* c) {
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
    if (!eq(&p.t[method], "UWB") || topology < 0 ||
        !eq(&p.t[topology], "MUTUAL"))
        return -1;
    int params = field(&p, selected, "parameters");
    if (params < 0 || p.t[params].type != '{') return -1;
    long distance, samples, timeout;
    if (integer(&p, field(&p, params, "max_distance_cm"), 1,
                UWB_RANGE_MAX_DISTANCE_CM_LIMIT, &distance) ||
        integer(&p, field(&p, params, "samples"), 1, UWB_RANGE_MAX_SAMPLES,
                &samples) ||
        integer(&p, field(&p, params, "timeout_ms"), 1,
                UWB_RANGE_TIMEOUT_MS_LIMIT, &timeout))
        return -1;
    c->max_distance_cm = (unsigned)distance;
    c->samples = (unsigned)samples;
    c->timeout_ms = (unsigned)timeout;
    return uwb_range_config_valid(c) ? 1 : -1;
}

int uwb_range_session_params(const session_key_t* key, unsigned direction,
                             uwb_range_session* out) {
    if (!key || !out ||
        (direction != UWB_RANGE_DIR_REQUESTER_MEASURES &&
         direction != UWB_RANGE_DIR_TARGET_MEASURES))
        return -1;
    static const char kLabel[] = "IoTAuth UWB FiRa session v1";
    unsigned char input[sizeof(kLabel)], digest[32];
    memcpy(input, kLabel, sizeof(kLabel) - 1);
    input[sizeof(kLabel) - 1] = (unsigned char)direction;
    unsigned dl = 0;
    if (!HMAC(EVP_sha256(), key->mac_key, key->mac_key_size, input,
              sizeof(input), digest, &dl) ||
        dl != sizeof(digest))
        return -1;
    memcpy(out->vupper64, digest, UWB_RANGE_VUPPER64_SIZE);
    uint32_t id = (uint32_t)digest[8] << 24 | (uint32_t)digest[9] << 16 |
                  (uint32_t)digest[10] << 8 | digest[11];
    out->session_id = (id & 0x7fffffffu) | 1u; /* nonzero, positive */
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

/* Control messages, inside secure messages: 'U' 'R' version type | body.
 * START/READY: direction. DONE: direction | verdict | median_cm (i16 BE). */
enum { MSG_START = 1, MSG_READY = 2, MSG_DONE = 3 };
#define MSG_HEADER 4
#define MSG_DIR_SIZE (MSG_HEADER + 1)
#define MSG_DONE_SIZE (MSG_HEADER + 1 + 1 + 2)
/* Beyond one side's collection window: radio start-up and control I/O. */
#define CONTROL_SLACK_MS 15000u

static int send_msg(SST_session_ctx_t* s, unsigned char type,
                    const unsigned char* body, unsigned len) {
    unsigned char m[MSG_DONE_SIZE] = {'U', 'R', UWB_RANGE_VERSION, type};
    memcpy(m + MSG_HEADER, body, len);
    return send_secure_message((char*)m, MSG_HEADER + len, s) < 0 ? -1 : 0;
}

/* Reads exactly one secure message of `type` for `direction`. */
static int recv_msg(SST_session_ctx_t* s, unsigned char type,
                    unsigned direction, unsigned char* m, unsigned len) {
    unsigned char buf[MAX_SECURE_COMM_MSG_LENGTH];
    int n = read_secure_message(buf, s);
    if (n != (int)len || buf[0] != 'U' || buf[1] != 'R' ||
        buf[2] != UWB_RANGE_VERSION || buf[3] != type ||
        buf[MSG_HEADER] != direction) {
        SST_print_error(
            "UWB range: control message not received or unexpected "
            "(timeout, disconnect or error).");
        return -1;
    }
    memcpy(m, buf, len);
    return 0;
}

static int cmp_int(const void* a, const void* b) {
    int x = *(const int*)a, y = *(const int*)b;
    return (x > y) - (x < y);
}

/* This side initiates and measures for `dir`; the peer responds. */
static int measure(SST_session_ctx_t* s, const uwb_range_config* c,
                   const uwb_range_radio* radio, unsigned dir,
                   uwb_range_result* r) {
    uwb_range_session params;
    unsigned char d = (unsigned char)dir, m[MSG_DIR_SIZE];
    int distances[UWB_RANGE_MAX_SAMPLES];
    if (uwb_range_session_params(&s->s_key, dir, &params) ||
        send_msg(s, MSG_START, &d, 1) ||
        recv_msg(s, MSG_READY, dir, m, sizeof(m)))
        return -1;
    int n = radio->initiate(radio->ctx, &params, c->samples, c->timeout_ms,
                            distances);
    radio->stop(radio->ctx);
    if (n < 0 || n > (int)c->samples) {
        SST_print_error("UWB range: ranging failed.");
        return -1;
    }
    r->samples = (unsigned)n;
    if (n > 0) {
        qsort(distances, (size_t)n, sizeof(*distances), cmp_int);
        r->median_cm = n % 2 ? distances[n / 2]
                             : (distances[n / 2 - 1] + distances[n / 2]) / 2;
    }
    /* Fewer ranges than required is a completed, failed check. */
    r->local_pass =
        n == (int)c->samples && r->median_cm <= (int)c->max_distance_cm;
    int16_t med = (int16_t)(r->median_cm < -32768  ? -32768
                            : r->median_cm > 32767 ? 32767
                                                   : r->median_cm);
    unsigned char done[4] = {d, (unsigned char)r->local_pass,
                             (unsigned char)((uint16_t)med >> 8),
                             (unsigned char)med};
    return send_msg(s, MSG_DONE, done, sizeof(done));
}

/* The peer initiates and measures for `dir`; this side responds. */
static int respond(SST_session_ctx_t* s, const uwb_range_radio* radio,
                   unsigned dir, uwb_range_result* r) {
    uwb_range_session params;
    unsigned char d = (unsigned char)dir, m[MSG_DONE_SIZE];
    if (recv_msg(s, MSG_START, dir, m, MSG_DIR_SIZE) ||
        uwb_range_session_params(&s->s_key, dir, &params))
        return -1;
    if (radio->respond(radio->ctx, &params)) {
        SST_print_error("UWB range: could not start responding.");
        return -1;
    }
    int rc = send_msg(s, MSG_READY, &d, 1) ||
                     recv_msg(s, MSG_DONE, dir, m, MSG_DONE_SIZE) ||
                     m[MSG_HEADER + 1] > 1
                 ? -1
                 : 0;
    radio->stop(radio->ctx);
    if (rc) return -1;
    r->peer_reported = 1;
    r->peer_reported_pass = m[MSG_HEADER + 1];
    r->peer_median_cm =
        (int16_t)((uint16_t)m[MSG_HEADER + 2] << 8 | m[MSG_HEADER + 3]);
    return 0;
}

int uwb_range_run(SST_session_ctx_t* session, const uwb_range_config* c,
                  int initiator, const uwb_range_radio* radio,
                  uwb_range_result* r) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!session || session->sock < 0 || !uwb_range_config_valid(c) || !radio ||
        !radio->respond || !radio->initiate || !radio->stop)
        return -1;
    /* The peer may be collecting for up to timeout_ms before it replies. */
    unsigned wait_ms = c->timeout_ms + CONTROL_SLACK_MS;
    struct timeval saved,
        tv = {(time_t)(wait_ms / 1000), (suseconds_t)(wait_ms % 1000) * 1000};
    socklen_t saved_len = sizeof(saved);
    int restore = getsockopt(session->sock, SOL_SOCKET, SO_RCVTIMEO, &saved,
                             &saved_len) == 0;
    if (setsockopt(session->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
        return -1;
    int rc = -1;
    for (unsigned dir = UWB_RANGE_DIR_REQUESTER_MEASURES;
         dir <= UWB_RANGE_DIR_TARGET_MEASURES; ++dir) {
        int mine = (dir == UWB_RANGE_DIR_REQUESTER_MEASURES) == !!initiator;
        if (mine ? measure(session, c, radio, dir, r)
                 : respond(session, radio, dir, r))
            goto out;
    }
    rc = r->local_pass ? 1 : 0;
out:
    if (restore)
        setsockopt(session->sock, SOL_SOCKET, SO_RCVTIMEO, &saved,
                   sizeof(saved));
    return rc;
}
