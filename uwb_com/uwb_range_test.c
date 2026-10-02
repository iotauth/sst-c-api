/* Portable test for the mutual UWB ranging check: real SST secure messages
 * over a socketpair, with a simulated radio pair that ranges only while the
 * peer is responding with the same FiRa parameters. Checks plan parsing and
 * protocol logic only, not radio behaviour. */
#include "uwb_range.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* What both simulated radios share: who is responding, with what. */
typedef struct {
    pthread_mutex_t lock;
    int responding;
    uwb_range_session params;
} air;

typedef struct {
    SST_session_ctx_t session;
    uwb_range_config config;
    air* air;
    int initiator, rc;
    int distance_cm; /* what this side measures when ranging works */
    int short_by;    /* returns this many fewer ranges than asked */
    int fail_initiate, fail_respond;
    uwb_range_result result;
} endpoint;

static int respond(void* ctx, const uwb_range_session* s) {
    endpoint* e = ctx;
    if (e->fail_respond) return -1;
    pthread_mutex_lock(&e->air->lock);
    e->air->responding = 1;
    e->air->params = *s;
    pthread_mutex_unlock(&e->air->lock);
    return 0;
}

static int initiate(void* ctx, const uwb_range_session* s, unsigned samples,
                    unsigned timeout_ms, int* distances_cm) {
    endpoint* e = ctx;
    (void)timeout_ms;
    if (e->fail_initiate) return -1;
    pthread_mutex_lock(&e->air->lock);
    int match = e->air->responding && !memcmp(&e->air->params, s, sizeof(*s));
    pthread_mutex_unlock(&e->air->lock);
    if (!match) return 0;
    int n = (int)samples - e->short_by;
    for (int i = 0; i < n; ++i) distances_cm[i] = e->distance_cm + i % 3 - 1;
    return n;
}

static int stop(void* ctx) {
    endpoint* e = ctx;
    pthread_mutex_lock(&e->air->lock);
    e->air->responding = 0;
    pthread_mutex_unlock(&e->air->lock);
    return 0;
}

static void* run_endpoint(void* ctx) {
    endpoint* e = ctx;
    uwb_range_radio radio = {e, respond, initiate, stop};
    e->rc = uwb_range_run(&e->session, &e->config, e->initiator, &radio,
                          &e->result);
    /* An aborting side must not leave its peer waiting on the socket. */
    if (e->rc < 0) shutdown(e->session.sock, SHUT_RDWR);
    return NULL;
}

static air shared_air;

static void init(endpoint e[2]) {
    memset(e, 0, sizeof(endpoint) * 2);
    memset(&shared_air, 0, sizeof(shared_air));
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
        e[i].initiator = i == 0;
        e[i].config = (uwb_range_config){100, 5, 1000};
        e[i].air = &shared_air;
        e[i].distance_cm = 60;
    }
}

static void exchange(endpoint e[2]) {
    pthread_t t[2];
    for (int i = 0; i < 2; ++i)
        assert(pthread_create(&t[i], NULL, run_endpoint, &e[i]) == 0);
    for (int i = 0; i < 2; ++i) pthread_join(t[i], NULL);
    for (int i = 0; i < 2; ++i) close(e[i].session.sock);
}

static const char* plan_in(const char* topology, const char* method,
                           const char* params) {
    static char plan[1024];
    snprintf(plan, sizeof(plan),
             "{\"requester\":\"net1.robot1\",\"targets\":[\"net1.locker1\"],"
             "\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{"
             "\"CO_LOCATION\":{\"topology\":\"%s\",\"selectedMethod\":{"
             "\"method\":\"%s\",\"parameters\":%s}}}}",
             topology, method, params);
    return plan;
}

static const char* plan_with(const char* method, const char* params) {
    return plan_in("MUTUAL", method, params);
}

static void plan_tests(void) {
    uwb_range_config c;
    assert(uwb_range_plan_config(
               plan_with("UWB",
                         "{\"max_distance_cm\":150,\"samples\":20,"
                         "\"timeout_ms\":10000}"),
               &c) == 1);
    assert(c.max_distance_cm == 150 && c.samples == 20 &&
           c.timeout_ms == 10000);
    assert(uwb_range_plan_config(plan_with("DUMMY", "{}"), &c) == 0);
    assert(uwb_range_plan_config(
               "{\"requiredChecks\":[],\"verificationPlan\":{}}", &c) == 0);
    /* Another medium's method is not ours to accept. */
    assert(
        uwb_range_plan_config(plan_with("BLE_RSSI",
                                        "{\"min_rssi_dbm\":-60,\"samples\":20,"
                                        "\"interval_ms\":100}"),
                              &c) == -1);
    const char* bad[] = {
        "{\"samples\":20,\"timeout_ms\":10000}",
        "{\"max_distance_cm\":150.5,\"samples\":20,\"timeout_ms\":10000}",
        "{\"max_distance_cm\":0,\"samples\":20,\"timeout_ms\":10000}",
        "{\"max_distance_cm\":10001,\"samples\":20,\"timeout_ms\":10000}",
        "{\"max_distance_cm\":150,\"samples\":0,\"timeout_ms\":10000}",
        "{\"max_distance_cm\":150,\"samples\":101,\"timeout_ms\":10000}",
        "{\"max_distance_cm\":150,\"samples\":20,\"timeout_ms\":0}",
        "{\"max_distance_cm\":150,\"samples\":20,\"timeout_ms\":60001}",
        "{\"max_distance_cm\":\"150\",\"samples\":20,\"timeout_ms\":10000}",
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(uwb_range_plan_config(plan_with("UWB", bad[i]), &c) == -1);
    assert(
        uwb_range_plan_config(plan_in("LOCAL", "UWB",
                                      "{\"max_distance_cm\":150,\"samples\":20,"
                                      "\"timeout_ms\":10000}"),
                              &c) == -1);
}

static void params_tests(void) {
    endpoint e[2];
    init(e);
    uwb_range_session a, b;
    const session_key_t* k = &e[0].session.s_key;
    assert(!uwb_range_session_params(k, 1, &a));
    assert(!uwb_range_session_params(k, 1, &b) && !memcmp(&a, &b, sizeof(a)));
    assert(a.session_id >= 1 && a.session_id <= 0x7fffffffu);
    assert(!uwb_range_session_params(k, 2, &b) && memcmp(&a, &b, sizeof(a)));
    session_key_t other = *k;
    other.mac_key[0] ^= 1;
    assert(!uwb_range_session_params(&other, 1, &b) &&
           memcmp(&a, &b, sizeof(a)));
    assert(uwb_range_session_params(k, 3, &b) == -1);
    for (int i = 0; i < 2; ++i) close(e[i].session.sock);
}

int main(void) {
    /* A side writing to a peer that already aborted must see EPIPE. */
    signal(SIGPIPE, SIG_IGN);
    plan_tests();
    params_tests();
    endpoint e[2];

    /* Both near: both pass, each sees the other's report. */
    init(e);
    e[1].distance_cm = 80;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 1);
    assert(e[0].result.samples == 5 && e[0].result.median_cm == 60);
    assert(e[1].result.median_cm == 80);
    assert(e[0].result.peer_reported && e[0].result.peer_reported_pass &&
           e[0].result.peer_median_cm == 80);
    assert(e[1].result.peer_median_cm == 60);

    /* One side measures too far: only that side fails. */
    init(e);
    e[1].distance_cm = 300;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 0);
    assert(!e[0].result.peer_reported_pass && e[1].result.peer_reported_pass);

    /* Exactly at the limit passes. */
    init(e);
    e[0].distance_cm = e[1].distance_cm = 100; /* median 100, limit 100 */
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 1);

    /* Too few ranges in time: a completed, failed check, not an abort. */
    init(e);
    e[0].short_by = 2;
    exchange(e);
    assert(e[0].rc == 0 && e[0].result.samples == 3 && e[1].rc == 1);

    /* A radio failure aborts that side, and its peer is not left waiting. */
    init(e);
    e[0].fail_initiate = 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);
    init(e);
    e[1].fail_respond = 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);

    /* Invalid config is rejected before anything is sent. */
    init(e);
    e[0].config.samples = e[1].config.samples = 0;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);

    puts(
        "UWB range: plan, session params, mutual pass, one-sided fail, "
        "limit, too few ranges, radio failure and invalid config tests "
        "passed.");
    return 0;
}
