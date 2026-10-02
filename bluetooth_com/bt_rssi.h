#ifndef BT_RSSI_H
#define BT_RSSI_H

#include <stdint.h>

#include "../src/c_api.h"

/* Mutual Bluetooth RSSI proximity check (CO_LOCATION method BLE_RSSI), run
 * over the SST session after a Bluetooth handshake. Each side samples the
 * RSSI of the very LE link that carries the authenticated session from its
 * own controller, judges its own median against Auth's threshold, and
 * reports its verdict to the peer over secure messages (informational: each
 * side's result covers only its own measurement).
 *
 * RSSI is signal strength, not a distance bound: an attacker who relays or
 * amplifies the link can make a far peer look near. Treat a PASS as "the
 * link looks close", never as proof of co-location on its own.
 *
 * Portable: the RSSI source is passed in, so this builds without BlueZ. */

#define BT_RSSI_VERSION 1
#define BT_RSSI_MIN_DBM_LIMIT (-127)
#define BT_RSSI_MAX_DBM_LIMIT 20
#define BT_RSSI_MAX_SAMPLES 1000
#define BT_RSSI_MAX_INTERVAL_MS 1000

typedef struct {
    int min_rssi_dbm;     /* PASS when the median is at least this */
    unsigned samples;     /* RSSI reads per side, 1..BT_RSSI_MAX_SAMPLES */
    unsigned interval_ms; /* between reads, 0..BT_RSSI_MAX_INTERVAL_MS */
} bt_rssi_config;

typedef struct {
    unsigned samples;       /* reads completed */
    double median_rssi_dbm; /* of this side's reads, if samples > 0 */
    int local_pass;
    int peer_reported; /* the peer's report arrived */
    int peer_reported_pass;
    int peer_median_rssi_dbm; /* rounded, as the peer reported it */
} bt_rssi_result;

/* Reads one RSSI sample (dBm). @return 0, or -1 on failure. */
typedef int (*bt_rssi_reader)(void* ctx, int8_t* rssi);

int bt_rssi_config_valid(const bt_rssi_config* config);
/* 1: CO_LOCATION selects BLE_RSSI (config filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int bt_rssi_plan_config(const char* plan, bt_rssi_config* config);
/* Samples, judges and swaps reports over session (initiator reports first).
 * Bounds every read on session->sock with SO_RCVTIMEO, restored after.
 * @return 1 when this side's own check passes, 0 when it completed without
 * passing, -1 when it aborted (RSSI read, socket or protocol failure). */
int bt_rssi_run(SST_session_ctx_t* session, const bt_rssi_config* config,
                int initiator, bt_rssi_reader read_rssi, void* reader_ctx,
                bt_rssi_result* result);
#endif
