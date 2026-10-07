/* Mutual BLE advertising-RSSI check; see ble_adv_rssi.h. */
#include "ble_adv_rssi.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

#include "../physical_com/freshness.h"
#include "../physical_com/plan_json.h"
#include "../physical_com/session_ctl.h"

int ble_adv_rssi_config_valid(const ble_adv_rssi_config* c) {
    return c && c->min_rssi_dbm >= -127 && c->min_rssi_dbm <= 20 &&
           c->samples >= 1 && c->samples <= BLE_ADV_RSSI_MAX_SAMPLES &&
           c->timeout_ms >= 1 && c->timeout_ms <= BLE_ADV_RSSI_TIMEOUT_MS_LIMIT;
}

int ble_adv_rssi_plan_config(const char* plan, ble_adv_rssi_config* c) {
    plan_json j;
    int params;
    if (!c) return -1;
    int rc = plan_co_location(plan, "BLE_RSSI", &j, &params);
    if (rc != 1) return rc;
    if (params < 0 || j.t[params].type != '{') return -1;
    long min_rssi, samples, timeout;
    if (plan_json_int(&j, plan_json_field(&j, params, "min_rssi_dbm"), -127, 20,
                      &min_rssi) ||
        plan_json_int(&j, plan_json_field(&j, params, "samples"), 1,
                      BLE_ADV_RSSI_MAX_SAMPLES, &samples) ||
        plan_json_int(&j, plan_json_field(&j, params, "timeout_ms"), 1,
                      BLE_ADV_RSSI_TIMEOUT_MS_LIMIT, &timeout))
        return -1;
    c->min_rssi_dbm = (int)min_rssi;
    c->samples = (unsigned)samples;
    c->timeout_ms = (unsigned)timeout;
    return ble_adv_rssi_config_valid(c) ? 1 : -1;
}

int ble_adv_rssi_tag(const session_key_t* key, unsigned direction,
                     const unsigned char* nonce, unsigned char* tag) {
    static const char kLabel[] = "IoTAuth BLE adv RSSI v1";
    unsigned char input[sizeof(kLabel) + BLE_ADV_RSSI_NONCE_SIZE], digest[32];
    unsigned dl = 0;
    if (!key || !nonce || !tag || key->mac_key_size != MAC_KEY_SIZE ||
        (direction != BLE_ADV_RSSI_DIR_REQUESTER_VERIFIES &&
         direction != BLE_ADV_RSSI_DIR_TARGET_VERIFIES))
        return -1;
    memcpy(input, kLabel, sizeof(kLabel) - 1);
    input[sizeof(kLabel) - 1] = (unsigned char)direction;
    memcpy(input + sizeof(kLabel), nonce, BLE_ADV_RSSI_NONCE_SIZE);
    if (!HMAC(EVP_sha256(), key->mac_key, (int)key->mac_key_size, input,
              sizeof(input), digest, &dl) ||
        dl != sizeof(digest))
        return -1;
    memcpy(tag, digest, BLE_ADV_RSSI_TAG_SIZE);
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

/* Control messages, inside secure messages: 'B' 'A' version type | body.
 * CHALLENGE: direction | nonce. DONE: direction | verdict | median (i8). */
enum { MSG_CHALLENGE = 1, MSG_DONE = 2 };
#define MSG_HEADER 4
#define MSG_CHALLENGE_SIZE (MSG_HEADER + 1 + BLE_ADV_RSSI_NONCE_SIZE)
#define MSG_DONE_SIZE (MSG_HEADER + 1 + 1 + 1)
/* Beyond one side's collection window: radio start-up and control I/O. */
#define CONTROL_SLACK_MS 15000u

static int send_msg(SST_session_ctx_t* s, unsigned char type,
                    const unsigned char* body, unsigned len) {
    unsigned char m[MSG_CHALLENGE_SIZE] = {'B', 'A', BLE_ADV_RSSI_VERSION,
                                           type};
    memcpy(m + MSG_HEADER, body, len);
    return session_ctl_send(s, m, MSG_HEADER + len);
}

/* Reads exactly one secure message of `type` for `direction`. */
static int recv_msg(SST_session_ctx_t* s, unsigned char type,
                    unsigned direction, unsigned char* m, unsigned len) {
    const unsigned char prefix[MSG_HEADER + 1] = {
        'B', 'A', BLE_ADV_RSSI_VERSION, type, (unsigned char)direction};
    return session_ctl_recv(s, prefix, sizeof(prefix), m, len, "BLE RSSI");
}

static int cmp_i8(const void* a, const void* b) {
    return *(const int8_t*)a - *(const int8_t*)b;
}

/* This side challenges and measures for `dir`; the peer advertises. */
static int verify(SST_session_ctx_t* s, const ble_adv_rssi_config* c,
                  const ble_adv_radio* radio, unsigned dir,
                  ble_adv_rssi_result* r) {
    unsigned char body[1 + BLE_ADV_RSSI_NONCE_SIZE];
    unsigned char tag[BLE_ADV_RSSI_TAG_SIZE];
    int8_t samples[BLE_ADV_RSSI_MAX_SAMPLES];
    unsigned n = 0;
    int got = 1, rc = -1;
    body[0] = (unsigned char)dir;
    if (RAND_bytes(body + 1, BLE_ADV_RSSI_NONCE_SIZE) != 1 ||
        ble_adv_rssi_tag(&s->s_key, dir, body + 1, tag))
        return -1;
    /* Scanning before the challenge exists, so no answer is missed; no
     * answer can predate the challenge, so none is stale. */
    if (radio->scan_begin(radio->ctx)) return -1;
    if (freshness_now_us(&r->observed_not_before_us) ||
        send_msg(s, MSG_CHALLENGE, body, sizeof(body)))
        goto stop;
    const uint64_t deadline =
        r->observed_not_before_us + (uint64_t)c->timeout_ms * 1000u;
    while (n < c->samples &&
           (got = radio->scan_next(radio->ctx, tag, deadline, &samples[n])) ==
               1)
        ++n;
    if (got >= 0) rc = 0;
    r->samples = n;
stop:
    radio->scan_stop(radio->ctx);
    if (rc || freshness_now_us(&r->collection_completed_us)) return -1;
    if (n > 0) {
        qsort(samples, n, sizeof(*samples), cmp_i8);
        r->median_rssi_dbm = n % 2 ? samples[n / 2]
                                   : (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
    }
    /* Fewer reports than required is a completed, failed check. */
    r->local_pass = n == c->samples && r->median_rssi_dbm >= c->min_rssi_dbm;
    int median = n ? (int)(r->median_rssi_dbm + (r->median_rssi_dbm < 0
                                                     ? -0.5
                                                     : 0.5))
                   : -128;
    unsigned char done[3] = {(unsigned char)dir, (unsigned char)r->local_pass,
                             (unsigned char)(int8_t)median};
    return send_msg(s, MSG_DONE, done, sizeof(done));
}

/* The peer challenges and measures for `dir`; this side advertises. */
static int prove(SST_session_ctx_t* s, const ble_adv_radio* radio,
                 unsigned dir, ble_adv_rssi_result* r) {
    unsigned char m[MSG_CHALLENGE_SIZE], tag[BLE_ADV_RSSI_TAG_SIZE];
    if (recv_msg(s, MSG_CHALLENGE, dir, m, sizeof(m)) ||
        ble_adv_rssi_tag(&s->s_key, dir, m + MSG_HEADER + 1, tag))
        return -1;
    if (radio->advertise(radio->ctx, tag)) {
        SST_print_error("BLE RSSI: could not start advertising.");
        return -1;
    }
    int rc = recv_msg(s, MSG_DONE, dir, m, MSG_DONE_SIZE) ||
                     m[MSG_HEADER + 1] > 1
                 ? -1
                 : 0;
    radio->stop_advertising(radio->ctx);
    if (rc) return -1;
    r->peer_reported = 1;
    r->peer_reported_pass = m[MSG_HEADER + 1];
    r->peer_median_rssi_dbm = (int8_t)m[MSG_HEADER + 2];
    return 0;
}

int ble_adv_rssi_run(SST_session_ctx_t* session, const ble_adv_rssi_config* c,
                     int initiator, const ble_adv_radio* radio,
                     ble_adv_rssi_result* r) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));
    if (!session || session->sock < 0 || !ble_adv_rssi_config_valid(c) ||
        !radio || !radio->advertise || !radio->stop_advertising ||
        !radio->scan_begin || !radio->scan_next || !radio->scan_stop ||
        !session_key_fresh(&session->s_key))
        return -1;
    /* The peer may be collecting for up to timeout_ms before it replies. */
    session_ctl_timeout saved;
    if (session_ctl_timeout_set(session->sock, c->timeout_ms + CONTROL_SLACK_MS,
                                &saved))
        return -1;
    int rc = -1;
    for (unsigned dir = BLE_ADV_RSSI_DIR_REQUESTER_VERIFIES;
         dir <= BLE_ADV_RSSI_DIR_TARGET_VERIFIES; ++dir) {
        int mine = (dir == BLE_ADV_RSSI_DIR_REQUESTER_VERIFIES) == !!initiator;
        if (mine ? verify(session, c, radio, dir, r)
                 : prove(session, radio, dir, r))
            goto out;
    }
    r->local_pass = r->local_pass && session_key_fresh(&session->s_key);
    rc = r->local_pass ? 1 : 0;
out:
    session_ctl_timeout_restore(session->sock, &saved);
    return rc;
}
