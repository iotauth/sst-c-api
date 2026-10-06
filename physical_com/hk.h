#ifndef PHYSICAL_HK_H
#define PHYSICAL_HK_H
#include <stdint.h>

#include "../src/c_api.h"

/* Mutual Hancke-Kuhn-style timed bit exchange, shared by the IR and LiFi
 * CO_LOCATION methods: the protocol is identical over both media; only the
 * register-derivation label (domain separation) and the pacing differ, and
 * those come from an hk_medium. */
#define HK_MAX_ROUNDS 128
#define HK_NONCE_SIZE 8
#define HK_TAG_SIZE 32
/* INIT: type(1) + session key ID(SESSION_KEY_ID_SIZE) + nonce_A(8) + tag(32).
 * READY: type(1) + nonce_B(8) + tag(32). nonce_A isn't resent in READY --
 * it's already known locally by both sides after INIT -- but the READY tag
 * is still computed over it, binding READY to this specific INIT (replay
 * protection) without spending wire bytes on it. */
#define HK_INIT_SIZE (1 + SESSION_KEY_ID_SIZE + HK_NONCE_SIZE + HK_TAG_SIZE)
#define HK_READY_SIZE (1 + HK_NONCE_SIZE + HK_TAG_SIZE)
#define HK_READY_GUARD_US 2000

typedef struct {
    const char* method; /* the plan's CO_LOCATION method, e.g. "IR" */
    const char* name;   /* for logs, e.g. "IR" or "LiFi" */
    char label[8];      /* register-derivation label, not NUL-terminated */
    /* Pause between a response and the next challenge, outside the measured
     * interval. */
    unsigned inter_bit_us;
} hk_medium;

extern const hk_medium HK_IR;
extern const hk_medium HK_LIFI;

typedef struct {
    unsigned rounds;
    unsigned threshold_ppm; /* Auth's success_threshold * 1,000,000, exactly. */
    unsigned max_delay_us;
} hk_config;

typedef struct {
    unsigned completed, successes, required;
    uint32_t rtt_us[HK_MAX_ROUNDS];
    unsigned char correct[HK_MAX_ROUNDS];
    int local_pass;
    /* freshness_now_us() after this run's nonces were exchanged and before
     * its first timed bit, so every scored response came after it; and once
     * the last round completed. 0 when not reached or unreadable. */
    uint64_t observed_not_before_us, collection_completed_us;
} hk_result;

/* All IO callbacks return 0 on success, -1 on timeout/framing/IO failure.
 * Bits are serialized response first, then a new challenge. Timestamps use
 * the same monotonic microsecond clock (uint32 wrap is intentional).
 * recv_bit timestamps completion of decoding, NOT the leading edge. */
typedef struct {
    void* ctx;
    int (*send_control)(void*, const unsigned char*, unsigned);
    int (*recv_control)(void*, unsigned char*, unsigned);
    int (*send_bit)(void*, unsigned char, uint32_t*);
    int (*recv_bit)(void*, unsigned char*, uint32_t*);
    void (*pause_us)(void*, unsigned);
} hk_io;

int hk_config_valid(const hk_config* config);
unsigned hk_required(const hk_config* config);
/* 1: CO_LOCATION selects medium->method; 0: absent/not required or explicit
 * DUMMY; -1: malformed, missing required check, unsupported method/config. */
int hk_plan_config(const char* plan, const hk_medium* medium,
                   hk_config* config);
/* Invoke only after authenticated SST handshake. initiator = handshake client.
 * Each side judges only its own measurement of the peer (no cross-reported
 * verdict exchange): returns 1 when this side's local check passes; 0 for a
 * local rejection; -1 for setup/framing/IO failure. Never resumes a run. */
int hk_run(const session_key_t* key, const hk_medium* medium,
           const hk_config* config, int initiator, const hk_io* io,
           hk_result* result);
#endif
