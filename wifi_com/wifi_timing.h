#ifndef WIFI_TIMING_H
#define WIFI_TIMING_H

#include <stdint.h>

#include "../src/c_api.h"

/* Authenticated challenge--response response-time check layered on top of the
 * Wi-Fi RSSI CO_LOCATION mechanism. It runs over the same authenticated SST
 * session that carries the Wi-Fi link (so the exchange traverses the measured
 * Wi-Fi interface, and a relay bridging that link adds its forwarding delay).
 *
 *   verifier -> fresh nonce (challenge)  -> prover
 *   verifier <- keyed response (tag)     <- prover
 *   response_time = (recv+verify complete) - (just before send), verifier clock
 *
 * Each round uses a fresh nonce; the response is a truncated HMAC-SHA-256 over
 * a label, verification direction, round, and that nonce, carried inside the
 * SST secure message. A near relay without the session key cannot forge a
 * response; it can only forward the protected exchange, so its forwarding
 * delay shows up in the measured response time. The check runs mutually, once
 * per direction, and each endpoint judges only its own measurements.
 *
 * This is an application-level response time (SST crypto, host stack, radio,
 * and peer processing), not RF airtime or time-of-flight. It rejects relays
 * slower than the configured deadline; it is not a distance bound. */

#define WIFI_TIMING_MODE_DISABLED 0
#define WIFI_TIMING_MODE_MEASURE 1
#define WIFI_TIMING_MODE_ENFORCE 2

#define WIFI_TIMING_MAX_ROUNDS 128
#define WIFI_TIMING_NONCE_SIZE 16
#define WIFI_TIMING_TAG_SIZE 16
#define WIFI_TIMING_DIR_REQUESTER_VERIFIES 1
#define WIFI_TIMING_DIR_TARGET_VERIFIES 2

typedef struct {
    int mode;                 /* disabled / measure / enforce */
    unsigned rounds;          /* 1..WIFI_TIMING_MAX_ROUNDS */
    uint64_t deadline_us;     /* enforce: per-round acceptance deadline (0 if none) */
    uint64_t recv_timeout_us; /* bound on waiting for each response (>0) */
} wifi_timing_config;

typedef struct {
    unsigned rounds_completed;   /* rounds this side measured as verifier */
    unsigned valid;              /* authenticated and matched the challenge */
    unsigned within_deadline;    /* of the valid, within the deadline */
    uint64_t rtt_us[WIFI_TIMING_MAX_ROUNDS]; /* per-round response times */
    uint64_t min_rtt_us, median_rtt_us, max_rtt_us;
    int local_pass;              /* enforce verdict for this side */
} wifi_timing_result;

/* Runs the mutual authenticated timing exchange over `session`.
 * initiator = handshake client (verifies first). The context strings are only
 * for the per-round logs. @return 1 pass (enforce: every round valid and
 * timely; measure: every round valid), 0 completed-without-passing (enforce:
 * a valid response exceeded the deadline), -1 abort (response mismatch, SST
 * authentication failure, I/O error, receive timeout, or bad configuration). */
int wifi_timing_run(SST_session_ctx_t* session, int initiator,
                    const char* role_name, const char* iface,
                    const char* local_addr, const char* peer_addr,
                    const wifi_timing_config* config, wifi_timing_result* result);

#endif  /* WIFI_TIMING_H */
