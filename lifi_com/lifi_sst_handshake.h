#ifndef LIFI_SST_HANDSHAKE_H
#define LIFI_SST_HANDSHAKE_H

#include "../src/c_api.h"

// Wiring for both the LiFi handshake and lifi_hk_run_gpio(). Unlike the IR
// pins, these are runtime settings because the two bench Pis are not wired
// identically. Defaults (BCM TX 23 / RX 22, LED active HIGH) are the pi42
// wiring; pi43 is the reverse (TX 22 / RX 23). Call before any LiFi function;
// safe to skip to keep the defaults.
// @param led_active_low Nonzero when the LED lights on GPIO LOW (KS0016
// between its + rail and S); zero for a module driven from the GPIO (KS0032).
void lifi_configure(int tx_gpio, int rx_gpio, int led_active_low);

// Performs the SST secure-session handshake (SKEY_HANDSHAKE_1/2/3) over
// visible light -- an LED driven by pigpio waves on one side, a TEMT6000
// phototransistor read as a digital level on the other -- instead of a TCP
// socket. This is the client/requester side, mirroring
// secure_connect_to_server(). Fetching the session key from Auth still
// happens over TCP beforehand; only the handshake with the peer entity goes
// over light. Requires root (pigpio needs direct GPIO access).
//
// The returned session_ctx has no usable socket (sock is left at -1);
// send_secure_message()/receive_thread_read_one_each() are not supported on
// it, since they are hard-coded to socket I/O.
// @param s_key Session key to use for the handshake (already obtained from
// Auth over TCP).
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* secure_connect_to_server_via_lifi(session_key_t* s_key);

// Server/target side of the SST handshake over light, mirroring
// server_secure_comm_setup(). Waits for a handshake1 (the peer's LED must be
// lit and aimed at our sensor before anything can be received; a dark line
// is reported and waited out, not treated as an error), then fetches the
// named session key from Auth over TCP before completing the handshake over
// light. Same session_ctx caveat as secure_connect_to_server_via_lifi().
// @param ctx SST context, used to fetch the session key by ID from Auth.
// @param existing_s_key_list Session key cache, as in
// server_secure_comm_setup().
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* server_secure_comm_setup_via_lifi(
    SST_ctx_t* ctx, session_key_list_t* existing_s_key_list);

#endif  // LIFI_SST_HANDSHAKE_H
