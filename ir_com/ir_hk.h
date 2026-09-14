#ifndef SST_IR_HK_H
#define SST_IR_HK_H
#include <stdint.h>

#include "../src/c_api.h"

#define IR_HK_MAX_ROUNDS 128
#define IR_HK_CONTROL_SIZE 86
#define IR_HK_READY_GUARD_US 2000
#define IR_HK_INTER_BIT_US 50000

typedef struct {
    unsigned rounds;
    unsigned threshold_ppm; /* Auth's success_threshold * 1,000,000, exactly. */
    unsigned max_delay_us;
} ir_hk_config;

typedef struct {
    unsigned completed, successes, required;
    uint32_t rtt_us[IR_HK_MAX_ROUNDS];
    unsigned char correct[IR_HK_MAX_ROUNDS];
    int local_pass, peer_pass;
} ir_hk_result;

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
} ir_hk_io;

int ir_hk_config_valid(const ir_hk_config* config);
unsigned ir_hk_required(const ir_hk_config* config);
/* 1: CO_LOCATION selects IR; 0: absent/not required or explicit DUMMY;
 * -1: malformed, missing required check, unsupported method/config. */
int ir_hk_plan_config(const char* plan, ir_hk_config* config);
/* Invoke only after authenticated SST handshake. initiator = handshake client.
 * Returns 1 only when both authenticated local decisions pass; 0 for a
 * completed rejection, -1 for setup/framing/IO failure. Never resumes a run. */
int ir_hk_run(const session_key_t* key, const ir_hk_config* config,
              int initiator, const ir_hk_io* io, ir_hk_result* result);
/* Linux/pigpio adapter, built with the physical-presence examples only. */
int ir_hk_run_gpio(const session_key_t* key, const ir_hk_config* config,
                   int initiator, ir_hk_result* result);
#endif
