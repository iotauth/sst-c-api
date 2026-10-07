#ifndef BLE_ADV_RSSI_H
#define BLE_ADV_RSSI_H
#include <stdint.h>

#include "../src/c_api.h"

/* Mutual BLE RSSI proximity check (CO_LOCATION method BLE_RSSI), run over an
 * authenticated SST session after its handshake. The RSSI comes from
 * advertising packets that answer a fresh challenge, not from the
 * controller's connection RSSI, whose age cannot be told:
 *
 *   the verifier starts scanning, notes the time, and sends a fresh 16-byte
 *   nonce over the session; the prover advertises (non-connectable) a
 *   16-byte tag = HMAC-SHA256(session MAC key, label | direction | nonce);
 *   the verifier takes the RSSI of each received advertising report that
 *   carries exactly that tag, until `samples` reports or `timeout_ms`.
 *
 * Only the session peer can make the tag, and only after the nonce went
 * out, so every sample is a packet the peer sent after the noted time: that
 * time is a lower bound on every observation used. Each received report is
 * its own packet with its own RSSI; nothing is cached.
 *
 * The check runs twice with the roles swapped (requester verifies first).
 * Each side judges only its own median against Auth's threshold and reports
 * it to the peer (informational). RSSI is signal strength, not a distance
 * bound: amplifying or relaying the advertisements can make a far peer look
 * near.
 *
 * Portable: the radio is passed in, so this builds without BlueZ. */

#define BLE_ADV_RSSI_VERSION 1
#define BLE_ADV_RSSI_NONCE_SIZE 16
#define BLE_ADV_RSSI_TAG_SIZE 16
#define BLE_ADV_RSSI_MAX_SAMPLES 100
#define BLE_ADV_RSSI_TIMEOUT_MS_LIMIT 60000
#define BLE_ADV_RSSI_DIR_REQUESTER_VERIFIES 1
#define BLE_ADV_RSSI_DIR_TARGET_VERIFIES 2

typedef struct {
    int min_rssi_dbm;    /* PASS when the median is at least this */
    unsigned samples;    /* reports needed, 1..BLE_ADV_RSSI_MAX_SAMPLES */
    unsigned timeout_ms; /* to collect them, 1..BLE_ADV_RSSI_TIMEOUT_MS_LIMIT */
} ble_adv_rssi_config;

typedef struct {
    void* ctx;
    /* Starts advertising `tag`; returns once advertising. */
    int (*advertise)(void* ctx, const unsigned char* tag);
    int (*stop_advertising)(void* ctx);
    /* Starts scanning; returns once scanning. */
    int (*scan_begin)(void* ctx);
    /* Waits for the next advertising report carrying `tag`.
     * @return 1 with its RSSI, 0 once deadline_us (freshness_now_us clock)
     * passes, -1 on error. */
    int (*scan_next)(void* ctx, const unsigned char* tag, uint64_t deadline_us,
                     int8_t* rssi);
    int (*scan_stop)(void* ctx);
} ble_adv_radio;

typedef struct {
    unsigned samples;       /* matching reports this side received */
    double median_rssi_dbm; /* of those, if samples > 0 */
    int local_pass;
    int peer_reported; /* the peer's report arrived */
    int peer_reported_pass;
    int peer_median_rssi_dbm; /* rounded, as the peer reported it */
    /* This side's own verification: just before its challenge went out,
     * and once it stopped collecting. 0 if not reached. The peer's
     * direction and report never move them. */
    uint64_t observed_not_before_us, collection_completed_us;
} ble_adv_rssi_result;

int ble_adv_rssi_config_valid(const ble_adv_rssi_config* config);
/* 1: CO_LOCATION selects BLE_RSSI (config filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int ble_adv_rssi_plan_config(const char* plan, ble_adv_rssi_config* config);
/* The tag the prover advertises for `direction` and `nonce`. */
int ble_adv_rssi_tag(const session_key_t* key, unsigned direction,
                     const unsigned char* nonce, unsigned char* tag);
/* Runs both directions over session->sock. Bounds every read on it with
 * SO_RCVTIMEO, restored after. @return 1 when this side's own check
 * passes, 0 when it completed without passing, -1 when it aborted (radio,
 * socket or protocol failure). */
int ble_adv_rssi_run(SST_session_ctx_t* session,
                     const ble_adv_rssi_config* config, int initiator,
                     const ble_adv_radio* radio, ble_adv_rssi_result* result);

#endif
