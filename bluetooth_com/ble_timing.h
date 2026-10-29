#ifndef BLE_TIMING_H
#define BLE_TIMING_H

#include <stdint.h>

#include "../src/c_api.h"

/* Authenticated challenge--response response-time check over a BLE LE L2CAP
 * connection-oriented channel (bt_link.c), a connection-based alternative to
 * the advertising-RSSI BLE mechanism. The measurement channel is the BLE
 * link; it is kept separate from the SST handshake/control transport (TCP),
 * so a relay bridging the BLE link adds its forwarding delay here.
 *
 *   verifier -> fresh nonce (challenge)  -> prover   (over the BLE L2CAP sock)
 *   verifier <- keyed response (tag)     <- prover
 *   response_time = (recv+verify complete) - (just before send), verifier clock
 *
 * Each round uses a fresh nonce; the response is a truncated HMAC-SHA-256 over
 * a BLE-timing domain label, the verification direction, round, and nonce,
 * keyed with the MAC key of the existing SST session. The relay never gets the
 * session/MAC key, so it can only forward -- its delay shows up in the RTT.
 * Mirrors wifi_timing.c; distinct domain label so wifi and BLE tags never
 * collide. This is an application-level response time (crypto + host stack +
 * BLE controller + connection-event scheduling + peer processing), not RF
 * airtime; it rejects relays slower than the deadline, not a distance bound. */

#define BLE_TIMING_MODE_DISABLED 0
#define BLE_TIMING_MODE_MEASURE 1
#define BLE_TIMING_MODE_ENFORCE 2

#define BLE_TIMING_MAX_ROUNDS 128
#define BLE_TIMING_NONCE_SIZE 16
#define BLE_TIMING_TAG_SIZE 16
#define BLE_TIMING_DIR_REQUESTER_VERIFIES 1
#define BLE_TIMING_DIR_TARGET_VERIFIES 2

typedef struct {
    int mode;                 /* disabled / measure / enforce */
    unsigned rounds;          /* 1..BLE_TIMING_MAX_ROUNDS */
    uint64_t deadline_us;     /* enforce: per-round acceptance deadline (0 if none) */
    uint64_t recv_timeout_us; /* bound on waiting for each response (>0) */
    uint64_t prover_delay_us; /* artificial prover delay per response (relay-delay sweep) */
} ble_timing_config;

typedef struct {
    unsigned rounds_completed;   /* rounds this side measured as verifier */
    unsigned valid;              /* authenticated and matched the challenge */
    unsigned within_deadline;    /* of the valid, within the deadline */
    uint64_t rtt_us[BLE_TIMING_MAX_ROUNDS]; /* per-round response times */
    uint64_t min_rtt_us, median_rtt_us, max_rtt_us;
    int local_pass;              /* enforce verdict for this side */
} ble_timing_result;

/* Runs the mutual authenticated timing exchange over `sock` (a connected BLE
 * L2CAP channel), authenticated with `key` (the existing SST session's keys).
 * initiator = handshake client (verifies first). `role_name` is only for the
 * per-round logs. @return 1 pass (enforce: every round valid and timely;
 * measure: every round valid), 0 completed-without-passing (enforce: a valid
 * response exceeded the deadline), -1 abort (mismatch, auth failure, I/O,
 * receive timeout, or bad configuration). */
int ble_timing_run(int sock, const session_key_t* key, int initiator,
                   const char* role_name, const ble_timing_config* config,
                   ble_timing_result* result);

/* Requests a connection interval of `want_units` (units of 1.25 ms, e.g. 6 =
 * 7.5 ms) on the LE link carrying `sock`, from the central (initiator) side,
 * and reads back the negotiated interval via the LE Connection Update Complete
 * event. @return 0 with *got_units set, or -1 if it could not be requested or
 * read. Peripheral side: not supported here, pass through and read-only is not
 * available, so the central performs the update. */
int ble_timing_request_interval(int sock, uint16_t want_units,
                                uint16_t* got_units);

#endif /* BLE_TIMING_H */
