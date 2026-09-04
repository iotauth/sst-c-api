#ifndef IR_SST_HANDSHAKE_H
#define IR_SST_HANDSHAKE_H

#include "../src/c_api.h"

// Performs the SST secure-session handshake (SKEY_HANDSHAKE_1/2/3) over
// infrared via pigpio-driven 38kHz bursts, instead of a TCP socket. This is
// the client/requester side, mirroring secure_connect_to_server(). Fetching
// the session key from Auth still happens over TCP beforehand, unaffected by
// this call -- only the handshake with the peer entity (e.g. robot to
// locker) goes over IR. Requires root (pigpio needs direct GPIO access).
//
// The returned session_ctx has no usable socket (sock is left at -1);
// send_secure_message()/receive_thread_read_one_each() are not supported on
// it yet, since they are hard-coded to socket I/O. Use this only to
// establish and verify the handshake for now.
// @param s_key Session key to use for the handshake (already obtained from
// Auth over TCP).
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* secure_connect_to_server_via_ir(session_key_t* s_key);

// Performs the server/target side of the SST secure-session handshake over
// IR, mirroring server_secure_comm_setup(). Waits for a handshake1 to arrive
// over IR, then fetches the named session key from Auth over TCP (as
// server_secure_comm_setup() does) before completing the handshake over IR.
// Requires root (pigpio needs direct GPIO access).
//
// Same caveat as secure_connect_to_server_via_ir(): the returned
// session_ctx's sock is not usable for send_secure_message()/
// receive_thread_read_one_each() yet.
// @param ctx SST context, used to fetch the session key by ID from Auth.
// @param existing_s_key_list Session key cache, as in server_secure_comm_setup().
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* server_secure_comm_setup_via_ir(
    SST_ctx_t* ctx, session_key_list_t* existing_s_key_list);

#endif  // IR_SST_HANDSHAKE_H
