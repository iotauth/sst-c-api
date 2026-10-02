#ifndef SST_ULTRASONIC_ECHO_H
#define SST_ULTRASONIC_ECHO_H
#include <stdint.h>

#include "../src/c_api.h"

/* Mutual acoustic keyed echo for CO_LOCATION, run after a TCP SST handshake.
 * Each direction: the verifier sends a fresh 16-byte nonce over the
 * authenticated TCP session, the prover answers with a session-bound MAC
 * over its speaker, and the verifier times challenge-send to response-decode
 * on its own CLOCK_MONOTONIC. Robot (handshake initiator) verifies first. */

#define ULTRASONIC_ECHO_VERSION 1
#define ULTRASONIC_ECHO_NONCE_SIZE 16
#define ULTRASONIC_ECHO_TAG_SIZE 16
/* Acoustic payload: version(1) | direction(1) | tag(16). */
#define ULTRASONIC_ECHO_PAYLOAD_SIZE (2 + ULTRASONIC_ECHO_TAG_SIZE)
#define ULTRASONIC_ECHO_MAX_RESPONSE_US_LIMIT 60000000u
#define ULTRASONIC_ECHO_TIMEOUT_MS_LIMIT 60000u
/* Direction 1: requester (initiator) verifies target; 2: the reverse. */
#define ULTRASONIC_ECHO_DIR_REQUESTER_VERIFIES 1
#define ULTRASONIC_ECHO_DIR_TARGET_VERIFIES 2

typedef struct {
    unsigned max_response_us;     /* longest elapsed time accepted as PASS */
    unsigned response_timeout_ms; /* when the verifier stops listening */
} ultrasonic_echo_config;

/* Both names come from Auth's plan, for the caller to cross-check against
 * what it knows locally; never from a peer's TCP message. */
typedef struct {
    char requester[MAX_ENTITY_NAME_LENGTH + 1];
    char target[MAX_ENTITY_NAME_LENGTH + 1];
} ultrasonic_echo_identity;

typedef enum {
    ULTRASONIC_ECHO_OK = 0,
    ULTRASONIC_ECHO_NOT_RUN,
    ULTRASONIC_ECHO_NO_RESPONSE,
    ULTRASONIC_ECHO_BAD_PAYLOAD,
    ULTRASONIC_ECHO_BAD_MAC,
    ULTRASONIC_ECHO_LATE,
    ULTRASONIC_ECHO_KEY_EXPIRED,
    ULTRASONIC_ECHO_ABORTED,
} ultrasonic_echo_failure;

/* This endpoint's own measurement, as its peer's verifier. */
typedef struct {
    unsigned direction;      /* the direction this side verified */
    int response_valid;      /* decoded, well-formed and MAC-verified */
    int decoded;             /* anything decoded before the deadline */
    uint64_t elapsed_us;     /* challenge send -> response decode */
    int timing_accepted;     /* response_valid && elapsed <= max_response_us */
    uint64_t verified_at_us; /* CLOCK_MONOTONIC at decode, if valid */
    int local_pass;
    ultrasonic_echo_failure failure;
    int peer_reported_pass; /* peer's verdict on us: logging only */
} ultrasonic_echo_result;

/* Audio callbacks return -1 on a device error. */
typedef struct {
    void* ctx;
    /* Drops buffered capture and decoder state and starts capturing, so
     * the next rx_until sees only audio from this point on. */
    int (*rx_begin)(void* ctx);
    /* Returns the decoded length (>0), or 0 once deadline_us (from
     * ultrasonic_echo_now_us()) passes without a decode. */
    int (*rx_until)(void* ctx, unsigned char* buf, unsigned capacity,
                    uint64_t deadline_us);
    /* Returns after the payload has finished playing. */
    int (*tx)(void* ctx, const unsigned char* buf, unsigned len);
} ultrasonic_echo_audio;

uint64_t ultrasonic_echo_now_us(void);
const char* ultrasonic_echo_failure_name(ultrasonic_echo_failure failure);
int ultrasonic_echo_config_valid(const ultrasonic_echo_config* config);
/* 1: CO_LOCATION selects ULTRASOUND (config and identity filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int ultrasonic_echo_plan_config(const char* plan,
                                ultrasonic_echo_config* config,
                                ultrasonic_echo_identity* identity);
/* Session-bound response tag for one direction's challenge nonce. */
int ultrasonic_echo_tag(const session_key_t* key, unsigned direction,
                        const unsigned char nonce[ULTRASONIC_ECHO_NONCE_SIZE],
                        unsigned char tag[ULTRASONIC_ECHO_TAG_SIZE]);
/* Runs both directions over session->sock (a TCP SST session) and audio.
 * Bounds every TCP read with SO_RCVTIMEO, restored before returning.
 * prover_delay_ms delays this side's acoustic answer (timing tests only).
 * @return 1 when this side's own verification passes, 0 when it completed
 * without passing, -1 when the exchange aborted (TCP/audio/protocol). */
int ultrasonic_echo_run(SST_session_ctx_t* session,
                        const ultrasonic_echo_config* config,
                        int initiator, const ultrasonic_echo_audio* audio,
                        unsigned prover_delay_ms,
                        ultrasonic_echo_result* result);
#endif
