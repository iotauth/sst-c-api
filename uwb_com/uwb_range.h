#ifndef UWB_RANGE_H
#define UWB_RANGE_H

#include <stdint.h>

#include "../src/c_api.h"

/* Mutual UWB ranging check (CO_LOCATION method UWB), run over the TCP SST
 * session after its handshake. The UWB radios only range; they carry no
 * session data. Only the side that initiates a FiRa DS-TWR session computes
 * the distance (the responder merely receives the initiator's result), so
 * the check runs twice with the roles swapped:
 *   direction 1: the requester initiates and measures, the target responds;
 *   direction 2: the target initiates and measures, the requester responds.
 * Each side judges only its own measurement and reports its verdict to the
 * peer over secure messages (informational).
 *
 * Both radios are configured with a FiRa session ID and static-STS vupper64
 * derived from the SST session's MAC key, per direction, so they range only
 * with a peer holding the same session key (static STS: an 8-byte value,
 * weaker than a dynamic STS key).
 *
 * Portable: the radio is passed in, so this builds without the hardware. */

#define UWB_RANGE_VERSION 1
#define UWB_RANGE_VUPPER64_SIZE 8
#define UWB_RANGE_MAX_DISTANCE_CM_LIMIT 10000
#define UWB_RANGE_MAX_SAMPLES 100
#define UWB_RANGE_TIMEOUT_MS_LIMIT 60000
#define UWB_RANGE_DIR_REQUESTER_MEASURES 1
#define UWB_RANGE_DIR_TARGET_MEASURES 2

typedef struct {
    unsigned max_distance_cm; /* PASS when the median is at most this */
    unsigned samples;         /* successful ranges needed, 1..MAX_SAMPLES */
    unsigned timeout_ms;      /* to collect them, 1..TIMEOUT_MS_LIMIT */
} uwb_range_config;

/* The FiRa parameters both radios use for one direction. */
typedef struct {
    uint32_t session_id; /* 1..0x7fffffff */
    unsigned char vupper64[UWB_RANGE_VUPPER64_SIZE];
} uwb_range_session;

typedef struct {
    void* ctx;
    /* Starts responding to the peer's ranging; returns once listening. */
    int (*respond)(void* ctx, const uwb_range_session* s);
    /* Initiates ranging until `samples` successful ranges or timeout_ms.
     * @return the number of distances written (0..samples), or -1. */
    int (*initiate)(void* ctx, const uwb_range_session* s, unsigned samples,
                    unsigned timeout_ms, int* distances_cm);
    /* Stops any ranging. */
    int (*stop)(void* ctx);
} uwb_range_radio;

typedef struct {
    unsigned samples; /* successful ranges this side measured */
    int median_cm;    /* of those, if samples > 0 */
    /* CLOCK_MONOTONIC (freshness_now_us) just before this side started its
     * own initiator session, and once it stopped; the responder direction
     * and the peer's report never move them. 0 if not reached. */
    uint64_t observed_not_before_us, collection_completed_us;
    int local_pass;
    int peer_reported; /* the peer's report arrived */
    int peer_reported_pass;
    int peer_median_cm;
} uwb_range_result;

int uwb_range_config_valid(const uwb_range_config* config);
/* 1: CO_LOCATION selects UWB (config filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int uwb_range_plan_config(const char* plan, uwb_range_config* config);
/* FiRa parameters for one direction, from the session's MAC key. */
int uwb_range_session_params(const session_key_t* key, unsigned direction,
                             uwb_range_session* out);
/* Runs both directions over session->sock. Bounds every read on it with
 * SO_RCVTIMEO, restored after. @return 1 when this side's own check
 * passes, 0 when it completed without passing, -1 when it aborted (radio,
 * socket or protocol failure). */
int uwb_range_run(SST_session_ctx_t* session, const uwb_range_config* config,
                  int initiator, const uwb_range_radio* radio,
                  uwb_range_result* result);
#endif
