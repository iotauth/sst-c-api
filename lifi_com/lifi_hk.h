#ifndef SST_LIFI_HK_H
#define SST_LIFI_HK_H
#include <stdint.h>

#include "../src/c_api.h"

/* Mutual HK-style check over visible light. Private copy of ../ir_com/ir_hk.h
 * so lifi_com stands alone; the protocol is identical, only the pacing
 * constants differ because a phototransistor has no AGC to recover. */
#define LIFI_HK_MAX_ROUNDS 128
#define LIFI_HK_NONCE_SIZE 8
#define LIFI_HK_TAG_SIZE 32
/* INIT: type(1) + session key ID(SESSION_KEY_ID_SIZE) + nonce_A(8) + tag(32).
 * READY: type(1) + nonce_B(8) + tag(32). nonce_A isn't resent in READY --
 * it's already known locally by both sides after INIT -- but the READY tag
 * is still computed over it, binding READY to this specific INIT (replay
 * protection) without spending wire bytes on it. */
#define LIFI_HK_INIT_SIZE \
    (1 + SESSION_KEY_ID_SIZE + LIFI_HK_NONCE_SIZE + LIFI_HK_TAG_SIZE)
#define LIFI_HK_READY_SIZE (1 + LIFI_HK_NONCE_SIZE + LIFI_HK_TAG_SIZE)
#define LIFI_HK_READY_GUARD_US 2000
/* Pause between a response and the next challenge, outside the measured
 * interval. IR needs 50 ms here for the demodulating receiver's AGC; the
 * TEMT6000 only needs its own rise time (a few hundred us on the bench), so
 * this could be much shorter -- but 50 ms is the round gap the clean
 * 600/1200 us bench run used, and the one 5 ms run also had unworkable
 * symbol widths, so nothing shorter is validated yet. */
#define LIFI_HK_INTER_BIT_US 50000

typedef struct {
    unsigned rounds;
    unsigned threshold_ppm; /* Auth's success_threshold * 1,000,000, exactly. */
    unsigned max_delay_us;
} lifi_hk_config;

typedef struct {
    unsigned completed, successes, required;
    uint32_t rtt_us[LIFI_HK_MAX_ROUNDS];
    unsigned char correct[LIFI_HK_MAX_ROUNDS];
    int local_pass;
} lifi_hk_result;

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
} lifi_hk_io;

int lifi_hk_config_valid(const lifi_hk_config* config);
unsigned lifi_hk_required(const lifi_hk_config* config);
/* 1: CO_LOCATION selects LIFI; 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, unsupported method/config. */
int lifi_hk_plan_config(const char* plan, lifi_hk_config* config);
/* Invoke only after authenticated SST handshake. initiator = handshake client.
 * Each side judges only its own measurement of the peer (no cross-reported
 * verdict exchange): returns 1 when this side's local check passes; 0 for a
 * local rejection; -1 for setup/framing/IO failure. Never resumes a run. */
int lifi_hk_run(const session_key_t* key, const lifi_hk_config* config,
                int initiator, const lifi_hk_io* io, lifi_hk_result* result);
/* Linux/pigpio adapter, built with the physical-presence examples only. Uses
 * the wiring set by lifi_configure() in lifi_sst_handshake.h. */
int lifi_hk_run_gpio(const session_key_t* key, const lifi_hk_config* config,
                     int initiator, lifi_hk_result* result);
#endif
