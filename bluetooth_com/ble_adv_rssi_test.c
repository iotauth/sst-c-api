/* Portable test for the mutual BLE advertising-RSSI check: real SST secure
 * messages over a socketpair, with a simulated radio pair in which a
 * scanner hears only what the peer is currently advertising. Checks plan
 * parsing, the protocol and its timing evidence, not radio behaviour. */
#include "ble_adv_rssi.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../physical_com/freshness.h"

/* What both simulated radios share: what is being advertised, by whom. */
typedef struct {
    pthread_mutex_t lock;
    int advertising;
    unsigned char tag[BLE_ADV_RSSI_TAG_SIZE];
    int8_t rssi; /* as heard by the scanner */
} air;

typedef struct endpoint {
    SST_session_ctx_t session;
    ble_adv_rssi_config config;
    air* air;
    struct endpoint* peer;
    int initiator, rc;
    int8_t heard_as;          /* RSSI the peer measures of this side */
    int wrong_key;            /* advertises tags under another key */
    const unsigned char* replay; /* advertises this tag instead */
    int fail_advertise;
    uint64_t first_sample_at;
    ble_adv_rssi_result result;
} endpoint;

static int advertise(void* ctx, const unsigned char* tag) {
    endpoint* e = ctx;
    if (e->fail_advertise) return -1;
    unsigned char t[BLE_ADV_RSSI_TAG_SIZE];
    memcpy(t, e->replay ? e->replay : tag, sizeof(t));
    if (e->wrong_key) t[0] ^= 1; /* any other key gives another tag */
    pthread_mutex_lock(&e->air->lock);
    e->air->advertising = 1;
    memcpy(e->air->tag, t, sizeof(t));
    e->air->rssi = e->heard_as;
    pthread_mutex_unlock(&e->air->lock);
    return 0;
}

static int stop_advertising(void* ctx) {
    endpoint* e = ctx;
    pthread_mutex_lock(&e->air->lock);
    e->air->advertising = 0;
    pthread_mutex_unlock(&e->air->lock);
    return 0;
}

static int scan_begin(void* ctx) {
    (void)ctx;
    return 0;
}

/* One report per millisecond while the matching tag is on the air. */
static int scan_next(void* ctx, const unsigned char* tag, uint64_t deadline,
                     int8_t* rssi) {
    endpoint* e = ctx;
    for (;;) {
        uint64_t now;
        assert(freshness_now_us(&now) == 0);
        if (now >= deadline) return 0;
        usleep(1000);
        pthread_mutex_lock(&e->air->lock);
        int hit = e->air->advertising &&
                  !memcmp(e->air->tag, tag, BLE_ADV_RSSI_TAG_SIZE);
        *rssi = e->air->rssi;
        pthread_mutex_unlock(&e->air->lock);
        if (hit) {
            if (!e->first_sample_at) freshness_now_us(&e->first_sample_at);
            return 1;
        }
    }
}

static int scan_stop(void* ctx) {
    (void)ctx;
    return 0;
}

static void* run_endpoint(void* ctx) {
    endpoint* e = ctx;
    ble_adv_radio radio = {e, advertise, stop_advertising, scan_begin,
                           scan_next, scan_stop};
    e->rc = ble_adv_rssi_run(&e->session, &e->config, e->initiator, &radio,
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
        e[i].config = (ble_adv_rssi_config){-60, 5, 300};
        e[i].air = &shared_air;
        e[i].peer = &e[1 - i];
        e[i].heard_as = -30;
    }
}

static void exchange(endpoint e[2]) {
    pthread_t t[2];
    for (int i = 0; i < 2; ++i)
        assert(pthread_create(&t[i], NULL, run_endpoint, &e[i]) == 0);
    for (int i = 0; i < 2; ++i) pthread_join(t[i], NULL);
    for (int i = 0; i < 2; ++i) close(e[i].session.sock);
}

static const char* plan_with(const char* params) {
    static char plan[1024];
    snprintf(plan, sizeof(plan),
             "{\"requiredChecks\":[\"CO_LOCATION\"],\"verificationPlan\":{"
             "\"CO_LOCATION\":{\"topology\":\"MUTUAL\",\"freshness_ms\":1000,"
             "\"selectedMethod\":{\"method\":\"BLE_RSSI\",\"parameters\":%s}}}"
             "}",
             params);
    return plan;
}

static void plan_tests(void) {
    ble_adv_rssi_config c;
    assert(ble_adv_rssi_plan_config(
               plan_with("{\"min_rssi_dbm\":-60,\"samples\":20,"
                         "\"timeout_ms\":10000}"),
               &c) == 1);
    assert(c.min_rssi_dbm == -60 && c.samples == 20 && c.timeout_ms == 10000);
    const char* bad[] = {
        /* the connection-RSSI parameters are no longer enough */
        "{\"min_rssi_dbm\":-60,\"samples\":20,\"interval_ms\":100}",
        "{\"min_rssi_dbm\":-60,\"samples\":0,\"timeout_ms\":10000}",
        "{\"min_rssi_dbm\":-60,\"samples\":101,\"timeout_ms\":10000}",
        "{\"min_rssi_dbm\":-128,\"samples\":20,\"timeout_ms\":10000}",
        "{\"min_rssi_dbm\":-60,\"samples\":20,\"timeout_ms\":60001}",
        "{\"min_rssi_dbm\":-60.5,\"samples\":20,\"timeout_ms\":10000}",
        "{\"samples\":20,\"timeout_ms\":10000}",
        "[]"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(ble_adv_rssi_plan_config(plan_with(bad[i]), &c) == -1);
    /* Another method, and an absent check. */
    assert(ble_adv_rssi_plan_config(
               "{\"requiredChecks\":[],\"verificationPlan\":{}}", &c) == 0);
}

static void tag_tests(void) {
    session_key_t k;
    memset(&k, 0, sizeof(k));
    memset(k.mac_key, 42, MAC_KEY_SIZE);
    k.mac_key_size = MAC_KEY_SIZE;
    unsigned char n1[BLE_ADV_RSSI_NONCE_SIZE] = {1}, n2[BLE_ADV_RSSI_NONCE_SIZE] = {2};
    unsigned char a[BLE_ADV_RSSI_TAG_SIZE], b[BLE_ADV_RSSI_TAG_SIZE];
    assert(ble_adv_rssi_tag(&k, 1, n1, a) == 0 && ble_adv_rssi_tag(&k, 1, n2, b) == 0);
    assert(memcmp(a, b, sizeof(a))); /* per nonce */
    assert(ble_adv_rssi_tag(&k, 2, n1, b) == 0 && memcmp(a, b, sizeof(a)));
    assert(ble_adv_rssi_tag(&k, 3, n1, b) == -1);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    plan_tests();
    tag_tests();
    endpoint e[2];

    /* Both near: both pass, each sees the other's report. */
    init(e);
    e[0].heard_as = -40; /* the target hears the requester at -40 */
    uint64_t before;
    assert(freshness_now_us(&before) == 0);
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 1);
    assert(e[0].result.samples == 5 && e[0].result.median_rssi_dbm == -30);
    assert(e[1].result.median_rssi_dbm == -40);
    assert(e[0].result.peer_reported && e[0].result.peer_reported_pass &&
           e[0].result.peer_median_rssi_dbm == -40);
    assert(e[1].result.peer_median_rssi_dbm == -30);
    /* Each side's samples follow its own challenge; the requester's
     * evidence is not moved by the target's later direction. */
    for (int i = 0; i < 2; ++i) {
        const ble_adv_rssi_result* r = &e[i].result;
        assert(before <= r->observed_not_before_us &&
               r->observed_not_before_us < e[i].first_sample_at &&
               e[i].first_sample_at <= r->collection_completed_us);
    }
    assert(e[0].result.collection_completed_us <=
           e[1].result.observed_not_before_us);

    /* Exactly at the threshold passes; below it fails, only for that side. */
    init(e);
    e[1].heard_as = -60;
    e[0].heard_as = -61;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 0);

    /* A prover without the session key, or replaying an earlier run's tag,
     * is never heard: a completed check with no samples. */
    init(e);
    e[1].wrong_key = 1;
    exchange(e);
    assert(e[0].rc == 0 && e[0].result.samples == 0 && e[1].rc == 1);
    static const unsigned char old_tag[BLE_ADV_RSSI_TAG_SIZE] = {9, 9, 9};
    init(e);
    e[0].replay = old_tag;
    exchange(e);
    assert(e[0].rc == 1 && e[1].rc == 0 && e[1].result.samples == 0);

    /* A radio failure aborts that side, and its peer is not left waiting. */
    init(e);
    e[1].fail_advertise = 1;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);

    /* Invalid config is rejected before anything is sent. */
    init(e);
    e[0].config.samples = e[1].config.samples = 0;
    exchange(e);
    assert(e[0].rc == -1 && e[1].rc == -1);

    puts(
        "BLE adv RSSI: plan, tag, mutual pass, threshold, wrong key, replay, "
        "radio failure, invalid config and timing tests passed.");
    return 0;
}
