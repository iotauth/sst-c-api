#ifndef GGWAVE_SST_HANDSHAKE_H
#define GGWAVE_SST_HANDSHAKE_H

#include "../src/c_api.h"

// Performs the SST secure-session handshake (SKEY_HANDSHAKE_1/2/3) over
// ultrasound via ggwave/ALSA, instead of a TCP socket. This is the
// client/requester side, mirroring secure_connect_to_server(). Fetching the
// session key from Auth still happens over TCP beforehand, unaffected by
// this call -- only the handshake with the peer entity (e.g. robot to
// locker) goes over ultrasound.
//
// The returned session_ctx has no usable socket (sock is left at -1);
// send_secure_message()/receive_thread_read_one_each() are not supported on
// it yet, since they are hard-coded to socket I/O. Use this only to
// establish and verify the handshake for now.
// @param s_key Session key to use for the handshake (already obtained from
// Auth over TCP).
// @param mic_device ALSA capture device, e.g. "plughw:3,0".
// @param spk_device ALSA playback device, e.g. "plughw:4,0".
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* secure_connect_to_server_via_ggwave(
    session_key_t* s_key, const char* mic_device, const char* spk_device);

// Performs the server/target side of the SST secure-session handshake over
// ultrasound via ggwave/ALSA, mirroring server_secure_comm_setup(). Waits
// for a handshake1 to arrive over ultrasound, then fetches the named
// session key from Auth over TCP (as server_secure_comm_setup() does) before
// completing the handshake over ultrasound.
//
// Same caveat as secure_connect_to_server_via_ggwave(): the returned
// session_ctx's sock is not usable for send_secure_message()/
// receive_thread_read_one_each() yet.
// @param ctx SST context, used to fetch the session key by ID from Auth.
// @param mic_device ALSA capture device.
// @param spk_device ALSA playback device.
// @param existing_s_key_list Session key cache, as in server_secure_comm_setup().
// @return Connected session_ctx, or NULL on failure.
SST_session_ctx_t* server_secure_comm_setup_via_ggwave(
    SST_ctx_t* ctx, const char* mic_device, const char* spk_device,
    session_key_list_t* existing_s_key_list);

#endif  // GGWAVE_SST_HANDSHAKE_H
