#ifndef PHYSICAL_RSSI_CHECK_H
#define PHYSICAL_RSSI_CHECK_H

#include <stdint.h>

#include "../src/c_api.h"

/* Mutual RSSI proximity check over an authenticated SST session, shared by
 * the CO_LOCATION methods BLE_RSSI (the session's Bluetooth LE link) and
 * WIFI_RSSI (the session's direct Wi-Fi link). Each side samples the RSSI of
 * the very link that carries the session from its own radio, judges its own
 * median against Auth's threshold, and reports its verdict to the peer over
 * secure messages (informational: each side's result covers only its own
 * measurement).
 *
 * RSSI is signal strength, not a distance bound: an attacker who relays or
 * amplifies the link can make a far peer look near. Treat a PASS as "the
 * link looks close", never as proof of co-location on its own.
 *
 * Portable: the RSSI source is passed in, so this builds without the radio
 * libraries. */

#define RSSI_VERSION 1
#define RSSI_MIN_DBM_LIMIT (-127)
#define RSSI_MAX_DBM_LIMIT 20
#define RSSI_MAX_SAMPLES 1000
#define RSSI_MAX_INTERVAL_MS 1000

typedef struct {
    int min_rssi_dbm;     /* PASS when the median is at least this */
    unsigned samples;     /* RSSI reads per side, 1..RSSI_MAX_SAMPLES */
    unsigned interval_ms; /* between reads, 0..RSSI_MAX_INTERVAL_MS */
} rssi_config;

typedef struct {
    unsigned samples;       /* reads completed */
    double median_rssi_dbm; /* of this side's reads, if samples > 0 */
    int local_pass;
    int peer_reported; /* the peer's report arrived */
    int peer_reported_pass;
    int peer_median_rssi_dbm; /* rounded, as the peer reported it */
} rssi_result;

/* Reads one RSSI sample (dBm). @return 0, or -1 on failure. */
typedef int (*rssi_reader)(void* ctx, int8_t* rssi);

int rssi_config_valid(const rssi_config* config);
/* 1: CO_LOCATION selects `method` (BLE_RSSI or WIFI_RSSI; config filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int rssi_plan_config(const char* plan, const char* method, rssi_config* config);
/* Samples, judges and swaps reports over session (initiator reports first).
 * Bounds every read on session->sock with SO_RCVTIMEO, restored after.
 * @return 1 when this side's own check passes, 0 when it completed without
 * passing, -1 when it aborted (RSSI read, socket or protocol failure). */
int rssi_run(SST_session_ctx_t* session, const rssi_config* config,
             int initiator, rssi_reader read_rssi, void* reader_ctx,
             rssi_result* result);
#endif
