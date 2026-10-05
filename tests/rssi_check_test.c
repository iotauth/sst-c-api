/* Portable test for the mutual RSSI check (BLE_RSSI and WIFI_RSSI): real SST
 * secure messages over a socketpair, with RSSI readings scripted per endpoint.
 * Checks plan parsing and protocol logic only, not radio behaviour. */
#include "../physical_com/rssi_check.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    SST_session_ctx_t session;
    rssi_config config;
    int initiator, rc;
    int8_t rssi;    /* every reading returns this */
    int fail_after; /* 0: never; n: the n-th read fails */
    int reads;
    rssi_result result;
} endpoint;

static int read_rssi(void* ctx, int8_t* rssi) {
    endpoint* e = ctx;
    if (e->fail_after && ++e->reads >= e->fail_after) return -1;
    *rssi = e->rssi;
    return 0;
}

static void* run_endpoint(void* ctx) {
    endpoint* e = ctx;
    e->rc = rssi_run(&e->session, &e->config, e->initiator, read_rssi, e,
                     &e->result);
    /* An aborting side must not leave its peer waiting on the socket. */
    if (e->rc < 0) shutdown(e->session.sock, SHUT_RDWR);
    return NULL;
}

static void init(endpoint e[2]) {
    memset(e, 0, sizeof(endpoint) * 2);
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
        e[i].config = (rssi_config){-60, 5, 1};
        e[i].rssi = -40;
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

/* Each RSSI method reads only its own plan entry. */
static void plan_tests(const char* method, const char* other) {
    static const char good[] =
        "{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":100}";
    rssi_config c;
    assert(rssi_plan_config(plan_with(method, good), method, &c) == 1);
    assert(c.min_rssi_dbm == -60 && c.samples == 20 && c.interval_ms == 100);
    assert(rssi_plan_config(plan_with("DUMMY", "{}"), method, &c) == 0);
    assert(rssi_plan_config("{\"requiredChecks\":[],\"verificationPlan\":{}}",
                            method, &c) == 0);
    /* Another medium's method is not ours to accept, even another RSSI one. */
    assert(rssi_plan_config(plan_with(other, good), method, &c) == -1);
    assert(rssi_plan_config(
               plan_with("ULTRASOUND",
                         "{\"max_response_us\":1,\"response_timeout_ms\":1}"),
               method, &c) == -1);
    const char* bad[] = {
        "{\"samples\":20,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-60.5,\"samples\":20,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-128,\"samples\":20,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":21,\"samples\":20,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-60,\"samples\":0,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-60,\"samples\":1001,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":1001}",
        "{\"min_rssi_dbm\":\"-60\",\"samples\":20,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-60,\"min_rssi_dbm\":-50,\"samples\":20,"
        "\"interval_ms\":100}",
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(rssi_plan_config(plan_with(method, bad[i]), method, &c) == -1);
    /* Required but missing, and a non-mutual topology, both reject. */
    assert(rssi_plan_config(
               "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{}}",
               method, &c) == -1);
    assert(rssi_plan_config(plan_in("LOCAL", method, good), method, &c) == -1);
}

int main(void) {
    /* A side writing to a peer that already aborted must see EPIPE. */
    signal(SIGPIPE, SIG_IGN);
    plan_tests("BLE_RSSI", "WIFI_RSSI");
    plan_tests("WIFI_RSSI", "BLE_RSSI");
    endpoint e[2];

    /* Both near: both pass, each sees the other's report. */
    init(e);
    e[1].rssi = -45;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 1);
    assert(e[0].result.median_rssi_dbm == -40 && e[0].result.samples == 5);
    assert(e[0].result.peer_reported && e[0].result.peer_reported_pass &&
           e[0].result.peer_median_rssi_dbm == -45);
    assert(e[1].result.peer_median_rssi_dbm == -40);

    /* One side weak: only that side fails; the other's own check stands. */
    init(e);
    e[1].rssi = -75;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 0);
    assert(!e[0].result.peer_reported_pass && e[1].result.peer_reported_pass);

    /* Exactly at the threshold passes. */
    init(e);
    e[0].rssi = e[1].rssi = -60;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 1);

    /* An RSSI read failure aborts that side, and its peer is not left
     * waiting forever. */
    init(e);
    e[1].fail_after = 3;
    exchange(e);
    assert(e[1].rc == -1 && e[1].result.samples == 2 && e[0].rc == -1);

    /* Invalid config is rejected before anything is sent. */
    init(e);
    e[0].config.samples = 0;
    e[1].config.samples = 0;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);

    puts(
        "RSSI check: BLE/Wi-Fi plans, mutual pass, one-sided fail, threshold, "
        "read "
        "failure and invalid config tests passed.");
    return 0;
}
