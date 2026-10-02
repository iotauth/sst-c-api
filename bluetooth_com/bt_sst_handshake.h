#ifndef BT_SST_HANDSHAKE_H
#define BT_SST_HANDSHAKE_H

#include "../src/c_api.h"

// Performs the SST secure-session handshake (SKEY_HANDSHAKE_1/2/3) over a
// Bluetooth LE L2CAP channel (bt_link.h) instead of a TCP socket. This is
// the client/requester side, mirroring secure_connect_to_server(). Fetching
// the session key from Auth still happens over TCP beforehand.
//
// Unlike the IR/LiFi/ultrasound transports, the channel is a real stream
// socket: the returned session_ctx's sock is the Bluetooth socket, so
// send_secure_message()/read_secure_message() keep working over Bluetooth
// after the handshake. Requires root (advertising and raw HCI commands).
// @param s_key Session key to use for the handshake (already obtained from
// Auth over TCP).
// @param peer Public LE address of the target, e.g. "D8:3A:DD:2B:3A:03".
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* secure_connect_to_server_via_bt(session_key_t* s_key,
                                                   const char* peer);

// Server/target side, mirroring server_secure_comm_setup(): advertises until
// the requester connects over Bluetooth, then runs the same handshake
// (fetching the named session key from Auth over TCP).
// @param ctx SST context, used to fetch the session key by ID from Auth.
// @param existing_s_key_list Session key cache, as in
// server_secure_comm_setup().
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* server_secure_comm_setup_via_bt(
    SST_ctx_t* ctx, session_key_list_t* existing_s_key_list);

#endif  // BT_SST_HANDSHAKE_H
