/* UWB absolute-position check: plan parsing, trilateration and the
 * requester-locates exchange over an SST session. See uwb_locate.h. */
#include "uwb_locate.h"

#include <math.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

#include "../physical_com/freshness.h"
#include "../physical_com/plan_json.h"
#include "../physical_com/session_ctl.h"
#include "../src/c_common.h"

int uwb_locate_config_valid(const uwb_locate_config* c) {
    if (!c || c->n_anchors < UWB_LOCATE_MIN_ANCHORS ||
        c->n_anchors > UWB_LOCATE_MAX_ANCHORS)
        return 0;
    if (c->tolerance_cm < 1 || c->tolerance_cm > UWB_LOCATE_TOLERANCE_LIMIT)
        return 0;
    if (c->samples < 1 || c->samples > UWB_RANGE_MAX_SAMPLES) return 0;
    if (c->timeout_ms < 1 || c->timeout_ms > UWB_RANGE_TIMEOUT_MS_LIMIT)
        return 0;
    return 1;
}

static int coord(const plan_json* j, int object, const char* name, int* out) {
    long v;
    if (plan_json_int(j, plan_json_field(j, object, name), -UWB_LOCATE_COORD_LIMIT,
                      UWB_LOCATE_COORD_LIMIT, &v))
        return -1;
    *out = (int)v;
    return 0;
}

int uwb_locate_plan_config(const char* plan, uwb_locate_config* c) {
    plan_json j;
    int params;
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    /* POSITION_IN_REGION is the requirement; UWB_POSITION ranges one way, so
     * the topology is ANCHORED rather than the mutual proximity topology. */
    int rc = plan_check(plan, "POSITION_IN_REGION", "UWB_POSITION", "ANCHORED",
                        &j, &params);
    if (rc != 1) return rc;
    if (params < 0 || j.t[params].type != '{') return -1;

    int anchors = plan_json_field(&j, params, "anchors");
    if (anchors < 0 || j.t[anchors].type != '[') return -1;
    int n = 0;
    for (int a = anchors + 1; a < j.t[anchors].next; a = j.t[a].next) {
        if (n >= UWB_LOCATE_MAX_ANCHORS || j.t[a].type != '{') return -1;
        if (coord(&j, a, "x_cm", &c->anchor_x_cm[n]) ||
            coord(&j, a, "y_cm", &c->anchor_y_cm[n]))
            return -1;
        ++n;
    }
    c->n_anchors = n;

    int expected = plan_json_field(&j, params, "expected");
    long tol, samples, timeout;
    if (expected < 0 || j.t[expected].type != '{' ||
        coord(&j, expected, "x_cm", &c->expected_x_cm) ||
        coord(&j, expected, "y_cm", &c->expected_y_cm) ||
        plan_json_int(&j, plan_json_field(&j, params, "tolerance_cm"), 1,
                      UWB_LOCATE_TOLERANCE_LIMIT, &tol) ||
        plan_json_int(&j, plan_json_field(&j, params, "samples"), 1,
                      UWB_RANGE_MAX_SAMPLES, &samples) ||
        plan_json_int(&j, plan_json_field(&j, params, "timeout_ms"), 1,
                      UWB_RANGE_TIMEOUT_MS_LIMIT, &timeout))
        return -1;
    c->tolerance_cm = (unsigned)tol;
    c->samples = (unsigned)samples;
    c->timeout_ms = (unsigned)timeout;
    return uwb_locate_config_valid(c) ? 1 : -1;
}

int uwb_locate_session_params(const session_key_t* key, unsigned anchor_index,
                              uwb_range_session* out) {
    if (!key || !out || anchor_index >= UWB_LOCATE_MAX_ANCHORS) return -1;
    static const char kLabel[] = "IoTAuth UWB locate session v1";
    unsigned char input[sizeof(kLabel)], digest[32];
    memcpy(input, kLabel, sizeof(kLabel) - 1);
    input[sizeof(kLabel) - 1] = (unsigned char)anchor_index;
    unsigned dl = 0;
    if (!HMAC(EVP_sha256(), key->mac_key, key->mac_key_size, input,
              sizeof(input), digest, &dl) ||
        dl != sizeof(digest))
        return -1;
    memcpy(out->vupper64, digest, UWB_RANGE_VUPPER64_SIZE);
    uint32_t id = (uint32_t)digest[8] << 24 | (uint32_t)digest[9] << 16 |
                  (uint32_t)digest[10] << 8 | digest[11];
    out->session_id = (id & 0x7fffffffu) | 1u;
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

/* Linearized least-squares trilateration: subtracting anchor 0's circle
 * equation from each other anchor's leaves the linear system A[x;y] = b, which
 * is solved by the 2x2 normal equations (A^T A)[x;y] = A^T b. */
int uwb_locate_trilaterate(const uwb_locate_config* c, const int* dist_cm,
                           int* x_cm, int* y_cm) {
    if (!c || !dist_cm || c->n_anchors < UWB_LOCATE_MIN_ANCHORS) return -1;
    double x0 = c->anchor_x_cm[0], y0 = c->anchor_y_cm[0], d0 = dist_cm[0];
    double a11 = 0, a12 = 0, a22 = 0, b1 = 0, b2 = 0;
    for (int i = 1; i < c->n_anchors; ++i) {
        double xi = c->anchor_x_cm[i], yi = c->anchor_y_cm[i], di = dist_cm[i];
        double ax = 2 * (xi - x0), ay = 2 * (yi - y0);
        double bi = (xi * xi - x0 * x0) + (yi * yi - y0 * y0) -
                    (di * di - d0 * d0);
        a11 += ax * ax;
        a12 += ax * ay;
        a22 += ay * ay;
        b1 += ax * bi;
        b2 += ay * bi;
    }
    double det = a11 * a22 - a12 * a12;
    if (fabs(det) < 1e-6) return -1; /* anchors collinear/coincident */
    double x = (a22 * b1 - a12 * b2) / det;
    double y = (-a12 * b1 + a11 * b2) / det;
    *x_cm = (int)lround(x);
    *y_cm = (int)lround(y);
    return 0;
}

/* Control messages inside secure messages: 'U' 'P' version type | body.
 * START/READY carry no body; DONE carries verdict | x | y | error (i32 BE). */
enum { MSG_START = 1, MSG_READY = 2, MSG_DONE = 3 };
#define MSG_HEADER 4
#define MSG_DONE_SIZE (MSG_HEADER + 1 + 4 + 4 + 4)
/* Beyond the ranging windows: radio start-up and control I/O. */
#define CONTROL_SLACK_MS 15000u

static void put_i32(unsigned char* p, int32_t v) {
    uint32_t u = (uint32_t)v;
    p[0] = (unsigned char)(u >> 24);
    p[1] = (unsigned char)(u >> 16);
    p[2] = (unsigned char)(u >> 8);
    p[3] = (unsigned char)u;
}
static int32_t get_i32(const unsigned char* p) {
    return (int32_t)((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | p[3]);
}

static int send_ctl(SST_session_ctx_t* s, unsigned char type,
                    const unsigned char* body, unsigned len) {
    unsigned char m[MSG_DONE_SIZE] = {'U', 'P', UWB_LOCATE_VERSION, type};
    if (body) memcpy(m + MSG_HEADER, body, len);
    return session_ctl_send(s, m, MSG_HEADER + len);
}
static int recv_ctl(SST_session_ctx_t* s, unsigned char type, unsigned char* m,
                    unsigned len) {
    const unsigned char prefix[MSG_HEADER] = {'U', 'P', UWB_LOCATE_VERSION,
                                              type};
    return session_ctl_recv(s, prefix, sizeof(prefix), m, len, "UWB locate");
}

static int cmp_int(const void* a, const void* b) {
    int x = *(const int*)a, y = *(const int*)b;
    return (x > y) - (x < y);
}

int uwb_locate_run_tag(SST_session_ctx_t* session, const uwb_locate_config* c,
                       const uwb_range_radio* tag, uwb_locate_result* r) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!session || session->sock < 0 || !uwb_locate_config_valid(c) || !tag ||
        !tag->initiate || !tag->stop)
        return -1;
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock, CONTROL_SLACK_MS, &saved))
        return -1;
    int rc = -1;
    if (send_ctl(session, MSG_START, NULL, 0)) goto out;
    unsigned char m[MSG_DONE_SIZE];
    if (recv_ctl(session, MSG_READY, m, MSG_HEADER)) goto out;

    if (freshness_now_us(&r->observed_not_before_us)) goto out;
    int all_ranged = 1;
    for (int i = 0; i < c->n_anchors; ++i) {
        uwb_range_session params;
        int dist[UWB_RANGE_MAX_SAMPLES];
        if (uwb_locate_session_params(&session->s_key, (unsigned)i, &params))
            goto out;
        int n = tag->initiate(tag->ctx, &params, c->samples, c->timeout_ms,
                              dist);
        tag->stop(tag->ctx);
        if (n < 0 || n > (int)c->samples) {
            SST_print_error("UWB locate: ranging anchor %d failed.", i);
            goto out;
        }
        if (n == (int)c->samples) {
            qsort(dist, (size_t)n, sizeof(*dist), cmp_int);
            r->dist_cm[i] = n % 2 ? dist[n / 2]
                                  : (dist[n / 2 - 1] + dist[n / 2]) / 2;
            r->ranged[i] = 1;
        } else {
            all_ranged = 0;
        }
    }
    if (freshness_now_us(&r->collection_completed_us)) goto out;

    if (all_ranged &&
        uwb_locate_trilaterate(c, r->dist_cm, &r->x_cm, &r->y_cm) == 0) {
        r->solved = 1;
        double dx = r->x_cm - c->expected_x_cm, dy = r->y_cm - c->expected_y_cm;
        r->error_cm = (int)lround(sqrt(dx * dx + dy * dy));
        r->local_pass = r->error_cm <= (int)c->tolerance_cm;
    }

    unsigned char body[1 + 4 + 4 + 4] = {(unsigned char)r->local_pass};
    put_i32(body + 1, r->x_cm);
    put_i32(body + 5, r->y_cm);
    put_i32(body + 9, r->error_cm);
    if (send_ctl(session, MSG_DONE, body, sizeof(body))) goto out;
    rc = r->local_pass ? 1 : 0;
out:
    session_ctl_timeout_restore(session->sock, &saved);
    return rc;
}

int uwb_locate_run_anchors(SST_session_ctx_t* session,
                           const uwb_locate_config* c,
                           const uwb_range_radio* const* anchor_radios,
                           uwb_locate_result* r) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!session || session->sock < 0 || !uwb_locate_config_valid(c) ||
        !anchor_radios)
        return -1;
    for (int i = 0; i < c->n_anchors; ++i)
        if (!anchor_radios[i] || !anchor_radios[i]->respond ||
            !anchor_radios[i]->stop)
            return -1;
    /* The tag ranges every anchor in turn before reporting, so this side may
     * wait that whole span for DONE. */
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock,
                                c->timeout_ms * (unsigned)c->n_anchors +
                                    CONTROL_SLACK_MS,
                                &saved))
        return -1;
    int rc = -1, started = 0;
    unsigned char m[MSG_DONE_SIZE];
    if (recv_ctl(session, MSG_START, m, MSG_HEADER)) goto out;
    if (freshness_now_us(&r->observed_not_before_us)) goto out;
    for (; started < c->n_anchors; ++started) {
        uwb_range_session params;
        const uwb_range_radio* a = anchor_radios[started];
        if (uwb_locate_session_params(&session->s_key, (unsigned)started,
                                      &params) ||
            a->respond(a->ctx, &params)) {
            SST_print_error("UWB locate: anchor %d could not respond.", started);
            goto out;
        }
    }
    if (send_ctl(session, MSG_READY, NULL, 0) ||
        recv_ctl(session, MSG_DONE, m, MSG_DONE_SIZE))
        goto out;
    if (freshness_now_us(&r->collection_completed_us)) goto out;
    /* The requester's authenticated verdict and solved position. */
    r->local_pass = m[MSG_HEADER] ? 1 : 0;
    r->x_cm = get_i32(m + MSG_HEADER + 1);
    r->y_cm = get_i32(m + MSG_HEADER + 5);
    r->error_cm = get_i32(m + MSG_HEADER + 9);
    r->solved = r->local_pass; /* a pass implies the requester solved a point */
    rc = r->local_pass;
out:
    for (int i = 0; i < started; ++i) anchor_radios[i]->stop(anchor_radios[i]->ctx);
    session_ctl_timeout_restore(session->sock, &saved);
    return rc;
}
