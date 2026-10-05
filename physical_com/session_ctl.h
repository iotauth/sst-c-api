#ifndef PHYSICAL_SESSION_CTL_H
#define PHYSICAL_SESSION_CTL_H

#include <stdint.h>
#include <sys/time.h>

#include "../src/c_api.h"

/* Plumbing shared by the CO_LOCATION checks that coordinate over an
 * authenticated SST session (ultrasound echo, BLE RSSI, UWB ranging). Each
 * check keeps its own wire format; these helpers only move and validate
 * whole control messages. */

/* 1 while the session key is still valid. */
int session_key_fresh(const session_key_t* key);

void session_ctl_sleep_ms(unsigned ms);

/* Sends one control message as one secure message. @return 0 or -1. */
int session_ctl_send(SST_session_ctx_t* s, const unsigned char* msg,
                     unsigned len);

/* Reads one secure message, which must be exactly `len` bytes starting with
 * the `prefix_len` bytes of `prefix`; anything else (timeout, EOF, wrong
 * size or prefix) is logged under `who` and fails. @return 0 or -1. */
int session_ctl_recv(SST_session_ctx_t* s, const unsigned char* prefix,
                     unsigned prefix_len, unsigned char* msg, unsigned len,
                     const char* who);

/* Bounds every read on `sock` by `ms`, remembering the previous bound. */
typedef struct {
    struct timeval previous;
    int saved;
} session_ctl_timeout;
int session_ctl_timeout_set(int sock, unsigned ms, session_ctl_timeout* t);
void session_ctl_timeout_restore(int sock, const session_ctl_timeout* t);

#endif
