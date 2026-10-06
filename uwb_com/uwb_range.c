/* Mutual UWB ranging check: plan parsing and the two-direction exchange
 * over an SST session. */
#include "uwb_range.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

#include "../physical_com/freshness.h"
#include "../physical_com/plan_json.h"
#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

int uwb_range_config_valid(const uwb_range_config* c) {
    return c && c->max_distance_cm >= 1 &&
           c->max_distance_cm <= UWB_RANGE_MAX_DISTANCE_CM_LIMIT &&
           c->samples >= 1 && c->samples <= UWB_RANGE_MAX_SAMPLES &&
           c->timeout_ms >= 1 && c->timeout_ms <= UWB_RANGE_TIMEOUT_MS_LIMIT;
}

int uwb_range_plan_config(const char* plan, uwb_range_config* c) {
    plan_json j;
    int params;
    if (!c) return -1;
    int rc = plan_co_location(plan, "UWB", &j, &params);
    if (rc != 1) return rc;
    if (params < 0 || j.t[params].type != '{') return -1;
    long distance, samples, timeout;
    if (plan_json_int(&j, plan_json_field(&j, params, "max_distance_cm"), 1,
                      UWB_RANGE_MAX_DISTANCE_CM_LIMIT, &distance) ||
        plan_json_int(&j, plan_json_field(&j, params, "samples"), 1,
                      UWB_RANGE_MAX_SAMPLES, &samples) ||
        plan_json_int(&j, plan_json_field(&j, params, "timeout_ms"), 1,
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
    return session_ctl_send(s, m, MSG_HEADER + len);
}

/* Reads exactly one secure message of `type` for `direction`. */
static int recv_msg(SST_session_ctx_t* s, unsigned char type,
                    unsigned direction, unsigned char* m, unsigned len) {
    const unsigned char prefix[MSG_HEADER + 1] = {
        'U', 'R', UWB_RANGE_VERSION, type, (unsigned char)direction};
    return session_ctl_recv(s, prefix, sizeof(prefix), m, len, "UWB range");
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
    /* Before the radio starts this session: initiate() only counts reports
     * that follow its start command's "ok". */
    if (freshness_now_us(&r->observed_not_before_us)) return -1;
    int n = radio->initiate(radio->ctx, &params, c->samples, c->timeout_ms,
                            distances);
    radio->stop(radio->ctx);
    if (freshness_now_us(&r->collection_completed_us)) return -1;
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
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock, c->timeout_ms + CONTROL_SLACK_MS,
                                &saved))
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
    session_ctl_timeout_restore(session->sock, &saved);
    return rc;
}
