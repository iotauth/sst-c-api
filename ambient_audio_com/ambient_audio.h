#ifndef SST_AMBIENT_AUDIO_H
#define SST_AMBIENT_AUDIO_H
#include <stdint.h>

#include "../src/c_api.h"

/* Sound-Proof-inspired ambient-audio co-location for CO_LOCATION, run after a
 * TCP SST handshake. Both endpoints record their surroundings over the same
 * agreed wall-clock window, exchange the recordings over the authenticated TCP
 * session, and each compares its own recording with the peer's. Unlike the
 * keyed echo, this is a passive comparison, not a timed challenge--response:
 * the similarity score is evidence of a shared acoustic environment, not a
 * distance bound. The DSP (1/3-octave normalized cross-correlation) runs in
 * the Python ambient_audio tool, invoked through the compare callback. */

#define AMBIENT_AUDIO_VERSION 1
#define AMBIENT_AUDIO_RECORDING_MS_LIMIT 10000u
#define AMBIENT_AUDIO_MAX_LAG_MS_LIMIT 1000u
#define AMBIENT_AUDIO_THRESHOLD_MILLI_LIMIT 1000u
/* Both endpoints agree to start recording this far in the future, leaving
 * time for the INIT/READY/START control exchange before capture begins. */
#define AMBIENT_AUDIO_START_DELAY_MS 3000u

typedef struct {
    unsigned recording_ms;               /* capture length per endpoint */
    unsigned similarity_threshold_milli; /* accept when score*1000 exceeds this */
    unsigned max_lag_ms;                 /* alignment tolerance, not an RTT bound */
    int min_power_dbfs;                  /* reject recordings quieter than this */
} ambient_audio_config;

/* Both names come from Auth's plan, for the caller to cross-check against what
 * it knows locally; never from a peer's TCP message. */
typedef struct {
    char requester[MAX_ENTITY_NAME_LENGTH + 1];
    char target[MAX_ENTITY_NAME_LENGTH + 1];
} ambient_audio_identity;

typedef enum {
    AMBIENT_AUDIO_OK = 0,
    AMBIENT_AUDIO_NOT_RUN,
    AMBIENT_AUDIO_RECORD_FAILED,
    AMBIENT_AUDIO_EXCHANGE_FAILED,
    AMBIENT_AUDIO_COMPARE_FAILED,
    AMBIENT_AUDIO_INVALID_INPUT,   /* a recording was too quiet or too short */
    AMBIENT_AUDIO_BELOW_THRESHOLD, /* valid but similarity below threshold */
    AMBIENT_AUDIO_KEY_EXPIRED,
    AMBIENT_AUDIO_ABORTED,
} ambient_audio_failure;

/* This endpoint's own comparison of the two recordings. */
typedef struct {
    int inputs_valid;     /* both recordings valid per the compare tool */
    int similarity_milli; /* final score * 1000 (0..1000) */
    int accepted;         /* inputs_valid && similarity exceeds threshold */
    int local_power_dbfs; /* this side's recording power */
    int peer_power_dbfs;  /* the peer's recording power */
    /* CLOCK_MONOTONIC just before this side started capturing; a conservative
     * lower bound on when the compared audio was observed. 0 if never set. */
    uint64_t observed_not_before_us;
    uint64_t collection_completed_us; /* after the comparison finished */
    int local_pass;
    ambient_audio_failure failure;
} ambient_audio_result;

/* Device callbacks (ALSA capture + Python compare). Return 0, or -1 on error. */
typedef struct {
    void* ctx;
    /* Records `duration_ms` of mono 16-bit PCM at 48 kHz starting at wall-clock
     * `start_realtime_us` (CLOCK_REALTIME microseconds) into a WAV at
     * `out_path`, and sets *observed_not_before_us to CLOCK_MONOTONIC captured
     * just before recording begins. */
    int (*record)(void* ctx, uint64_t start_realtime_us, unsigned duration_ms,
                  const char* out_path, uint64_t* observed_not_before_us);
    /* Compares the two recordings with `cfg` and fills the similarity score
     * (milli), input validity, acceptance, and each side's power (dBFS). */
    int (*compare)(void* ctx, const char* local_path, const char* peer_path,
                   const ambient_audio_config* cfg, int* similarity_milli,
                   int* inputs_valid, int* accepted, int* local_power_dbfs,
                   int* peer_power_dbfs);
} ambient_audio_io;

uint64_t ambient_audio_now_us(void);          /* CLOCK_MONOTONIC */
uint64_t ambient_audio_now_realtime_us(void); /* CLOCK_REALTIME */
const char* ambient_audio_failure_name(ambient_audio_failure failure);
int ambient_audio_config_valid(const ambient_audio_config* config);
/* 1: CO_LOCATION selects AMBIENT_AUDIO (config and identity filled);
 * 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, other method, invalid config. */
int ambient_audio_plan_config(const char* plan, ambient_audio_config* config,
                              ambient_audio_identity* identity);
/* Runs the recording exchange over session->sock (a TCP SST session) and the
 * device callbacks. Bounds every TCP read with SO_RCVTIMEO, restored before
 * returning.
 * @return 1 when this side accepts the peer, 0 when it completed without
 * accepting, -1 when the exchange aborted (TCP/device/protocol). */
int ambient_audio_run(SST_session_ctx_t* session,
                      const ambient_audio_config* config, int initiator,
                      const ambient_audio_io* io, ambient_audio_result* result);
#endif
