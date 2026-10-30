/* Portable test for the UWB position check: real SST secure messages over a
 * socketpair, with simulated radios where each anchor responds at a fixed
 * distance from a chosen true tag position. Checks plan parsing, trilateration
 * and protocol logic only, not radio behaviour. */
#include "uwb_locate.h"

#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Shared "air": each responding anchor registers its FiRa params and the
 * distance the tag should measure to it. */
typedef struct {
    pthread_mutex_t lock;
    int in_use[UWB_LOCATE_MAX_ANCHORS];
    uwb_range_session params[UWB_LOCATE_MAX_ANCHORS];
    int distance_cm[UWB_LOCATE_MAX_ANCHORS];
    int fail_initiate, fail_respond, short_anchor; /* -1 = none */
} air;

typedef struct {
    air* air;
    int index; /* anchor slot this radio owns (anchor side) */
} radio_ctx;

static air shared_air;

static int anchor_respond(void* ctx, const uwb_range_session* s) {
    radio_ctx* rc = ctx;
    if (rc->air->fail_respond) return -1;
    pthread_mutex_lock(&rc->air->lock);
    rc->air->params[rc->index] = *s;
    rc->air->in_use[rc->index] = 1;
    pthread_mutex_unlock(&rc->air->lock);
    return 0;
}
static int anchor_stop(void* ctx) {
    radio_ctx* rc = ctx;
    pthread_mutex_lock(&rc->air->lock);
    rc->air->in_use[rc->index] = 0;
    pthread_mutex_unlock(&rc->air->lock);
    return 0;
}

static int tag_initiate(void* ctx, const uwb_range_session* s, unsigned samples,
                        unsigned timeout_ms, int* distances_cm) {
    air* a = ctx;
    (void)timeout_ms;
    if (a->fail_initiate) return -1;
    pthread_mutex_lock(&a->lock);
    int slot = -1;
    for (int i = 0; i < UWB_LOCATE_MAX_ANCHORS; ++i)
        if (a->in_use[i] && !memcmp(&a->params[i], s, sizeof(*s))) slot = i;
    int dist = slot >= 0 ? a->distance_cm[slot] : 0;
    int shortfall = slot >= 0 && slot == a->short_anchor;
    pthread_mutex_unlock(&a->lock);
    if (slot < 0) return 0;
    unsigned n = shortfall ? samples - 1 : samples;
    for (unsigned i = 0; i < n; ++i) distances_cm[i] = dist + (int)(i % 3) - 1;
    return (int)n;
}
static int tag_stop(void* ctx) {
    (void)ctx;
    return 0;
}

typedef struct {
    SST_session_ctx_t session;
    uwb_locate_config config;
    int is_tag, rc;
    uwb_locate_result result;
} endpoint;

static void set_distances(const uwb_locate_config* c, double tx, double ty) {
    for (int i = 0; i < c->n_anchors; ++i) {
        double dx = tx - c->anchor_x_cm[i], dy = ty - c->anchor_y_cm[i];
        shared_air.distance_cm[i] = (int)lround(sqrt(dx * dx + dy * dy));
    }
}

static void* run_tag(void* ctx) {
    endpoint* e = ctx;
    uwb_range_radio radio = {&shared_air, NULL, tag_initiate, tag_stop};
    e->rc = uwb_locate_run_tag(&e->session, &e->config, &radio, &e->result);
    if (e->rc < 0) shutdown(e->session.sock, SHUT_RDWR);
    return NULL;
}

static radio_ctx anchor_ctx[UWB_LOCATE_MAX_ANCHORS];
static uwb_range_radio anchor_radio[UWB_LOCATE_MAX_ANCHORS];

static void* run_anchors(void* ctx) {
    endpoint* e = ctx;
    const uwb_range_radio* radios[UWB_LOCATE_MAX_ANCHORS];
    for (int i = 0; i < e->config.n_anchors; ++i) {
        anchor_ctx[i] = (radio_ctx){&shared_air, i};
        anchor_radio[i] = (uwb_range_radio){&anchor_ctx[i], anchor_respond, NULL,
                                            anchor_stop};
        radios[i] = &anchor_radio[i];
    }
    e->rc = uwb_locate_run_anchors(&e->session, &e->config, radios, &e->result);
    if (e->rc < 0) shutdown(e->session.sock, SHUT_RDWR);
    return NULL;
}

static void init(endpoint e[2], const uwb_locate_config* c) {
    memset(e, 0, sizeof(endpoint) * 2);
    memset(&shared_air, 0, sizeof(shared_air));
    shared_air.short_anchor = -1;
    pthread_mutex_init(&shared_air.lock, NULL);
    int sock[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sock) == 0);
    for (int i = 0; i < 2; ++i) {
        session_key_t* k = &e[i].session.s_key;
        memset(k->key_id, 7, SESSION_KEY_ID_SIZE);
        memset(k->mac_key, 42, MAC_KEY_SIZE);
        memset(k->cipher_key, 9, 16);
        k->mac_key_size = MAC_KEY_SIZE;
        k->cipher_key_size = 16;
        k->enc_mode = AES_128_CBC;
        k->abs_validity = UINT64_MAX;
        e[i].session.sock = sock[i];
        e[i].config = *c;
    }
    e[0].is_tag = 1;
}

static void exchange(endpoint e[2]) {
    pthread_t t[2];
    assert(pthread_create(&t[0], NULL, run_tag, &e[0]) == 0);
    assert(pthread_create(&t[1], NULL, run_anchors, &e[1]) == 0);
    pthread_join(t[0], NULL);
    pthread_join(t[1], NULL);
    for (int i = 0; i < 2; ++i) close(e[i].session.sock);
}

static const char* plan_with(const char* topology, const char* method,
                             const char* params) {
    static char plan[1024];
    snprintf(plan, sizeof(plan),
             "{\"requester\":\"net1.robot1\",\"targets\":[\"net1.locker1\"],"
             "\"requiredChecks\":[\"POSITION_IN_REGION\"],\"verificationPlan\":{"
             "\"POSITION_IN_REGION\":{\"topology\":\"%s\",\"selectedMethod\":{"
             "\"method\":\"%s\",\"parameters\":%s}}}}",
             topology, method, params);
    return plan;
}

#define GOOD_PARAMS                                                       \
    "{\"anchors\":[{\"x_cm\":0,\"y_cm\":0},{\"x_cm\":84,\"y_cm\":-89},"   \
    "{\"x_cm\":84,\"y_cm\":97}],\"expected\":{\"x_cm\":107,\"y_cm\":41}," \
    "\"tolerance_cm\":15,\"samples\":5,\"timeout_ms\":8000}"

static void plan_tests(void) {
    uwb_locate_config c;
    assert(uwb_locate_plan_config(
               plan_with("ANCHORED", "UWB_POSITION", GOOD_PARAMS), &c) == 1);
    assert(c.n_anchors == 3 && c.anchor_x_cm[1] == 84 &&
           c.anchor_y_cm[1] == -89 && c.expected_x_cm == 107 &&
           c.tolerance_cm == 15 && c.samples == 5 && c.timeout_ms == 8000);
    /* DUMMY and absent/not-required are "nothing to do". */
    assert(uwb_locate_plan_config(plan_with("ANCHORED", "DUMMY", "{}"), &c) ==
           0);
    assert(uwb_locate_plan_config(
               "{\"requiredChecks\":[],\"verificationPlan\":{}}", &c) == 0);
    /* Another method or the mutual topology is not ours. */
    assert(uwb_locate_plan_config(plan_with("ANCHORED", "UWB", GOOD_PARAMS),
                                  &c) == -1);
    assert(uwb_locate_plan_config(
               plan_with("MUTUAL", "UWB_POSITION", GOOD_PARAMS), &c) == -1);
    const char* bad[] = {
        /* two anchors: fewer than the minimum */
        "{\"anchors\":[{\"x_cm\":0,\"y_cm\":0},{\"x_cm\":84,\"y_cm\":-89}],"
        "\"expected\":{\"x_cm\":1,\"y_cm\":1},\"tolerance_cm\":15,"
        "\"samples\":5,\"timeout_ms\":8000}",
        /* missing expected */
        "{\"anchors\":[{\"x_cm\":0,\"y_cm\":0},{\"x_cm\":84,\"y_cm\":-89},"
        "{\"x_cm\":84,\"y_cm\":97}],\"tolerance_cm\":15,\"samples\":5,"
        "\"timeout_ms\":8000}",
        /* tolerance 0, samples 0, timeout 0, fractional coord */
        "{\"anchors\":[{\"x_cm\":0,\"y_cm\":0},{\"x_cm\":84,\"y_cm\":-89},"
        "{\"x_cm\":84,\"y_cm\":97}],\"expected\":{\"x_cm\":1,\"y_cm\":1},"
        "\"tolerance_cm\":0,\"samples\":5,\"timeout_ms\":8000}",
        "{\"anchors\":[{\"x_cm\":0,\"y_cm\":0},{\"x_cm\":84,\"y_cm\":-89},"
        "{\"x_cm\":84,\"y_cm\":97}],\"expected\":{\"x_cm\":1,\"y_cm\":1},"
        "\"tolerance_cm\":15,\"samples\":0,\"timeout_ms\":8000}",
        "{\"anchors\":[{\"x_cm\":0,\"y_cm\":0},{\"x_cm\":84,\"y_cm\":-89},"
        "{\"x_cm\":84.5,\"y_cm\":97}],\"expected\":{\"x_cm\":1,\"y_cm\":1},"
        "\"tolerance_cm\":15,\"samples\":5,\"timeout_ms\":8000}",
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(uwb_locate_plan_config(
                   plan_with("ANCHORED", "UWB_POSITION", bad[i]), &c) == -1);
}

static void trilaterate_tests(void) {
    uwb_locate_config c = {0};
    c.n_anchors = 3;
    c.anchor_x_cm[0] = 0;   c.anchor_y_cm[0] = 0;
    c.anchor_x_cm[1] = 84;  c.anchor_y_cm[1] = -89;
    c.anchor_x_cm[2] = 84;  c.anchor_y_cm[2] = 97;
    /* Exact distances from (107, 41) recover it within rounding. */
    int d[3];
    for (int i = 0; i < 3; ++i) {
        double dx = 107 - c.anchor_x_cm[i], dy = 41 - c.anchor_y_cm[i];
        d[i] = (int)lround(sqrt(dx * dx + dy * dy));
    }
    int x, y;
    assert(uwb_locate_trilaterate(&c, d, &x, &y) == 0);
    assert(abs(x - 107) <= 2 && abs(y - 41) <= 2);
    /* Collinear anchors are rejected. */
    uwb_locate_config col = c;
    col.anchor_x_cm[0] = 0; col.anchor_y_cm[0] = 0;
    col.anchor_x_cm[1] = 10; col.anchor_y_cm[1] = 0;
    col.anchor_x_cm[2] = 20; col.anchor_y_cm[2] = 0;
    assert(uwb_locate_trilaterate(&col, d, &x, &y) == -1);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    plan_tests();
    trilaterate_tests();

    uwb_locate_config c;
    assert(uwb_locate_plan_config(
               plan_with("ANCHORED", "UWB_POSITION", GOOD_PARAMS), &c) == 1);
    endpoint e[2];

    /* Tag at the expected point: within tolerance, both sides succeed. */
    init(e, &c);
    set_distances(&c, 107, 41);
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 1); /* anchors take the tag's verdict */
    assert(e[0].result.solved && e[0].result.local_pass);
    assert(abs(e[0].result.x_cm - 107) <= 3 &&
           abs(e[0].result.y_cm - 41) <= 3 && e[0].result.error_cm <= 15);
    /* The anchor side reports the tag's authenticated position and verdict. */
    assert(e[1].result.local_pass &&
           e[1].result.x_cm == e[0].result.x_cm &&
           e[1].result.error_cm == e[0].result.error_cm);

    /* Tag far from the expected point: solved but out of tolerance. */
    init(e, &c);
    set_distances(&c, 10, 10);
    exchange(e);
    assert(e[0].rc == 0 && e[1].rc == 0);
    assert(e[0].result.solved && !e[0].result.local_pass &&
           e[0].result.error_cm > 15);

    /* One anchor returns too few ranges: completed without a position. */
    init(e, &c);
    set_distances(&c, 107, 41);
    shared_air.short_anchor = 1;
    exchange(e);
    assert(e[0].rc == 0 && e[1].rc == 0);
    assert(!e[0].result.solved && !e[0].result.ranged[1] &&
           e[0].result.ranged[0]);

    /* Radio failures abort, and the peer is not left waiting. */
    init(e, &c);
    shared_air.fail_initiate = 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);
    init(e, &c);
    shared_air.fail_respond = 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);

    puts(
        "UWB locate: plan, trilateration, within tolerance, out of tolerance, "
        "too few ranges and radio failure tests passed.");
    return 0;
}
