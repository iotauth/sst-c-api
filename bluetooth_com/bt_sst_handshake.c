// SST handshake carried over a Bluetooth LE L2CAP stream socket. The socket
// behaves like TCP, so this only replaces how the connection is made and
// reuses the socket-based handshake in c_api.c unchanged.

#include "bt_sst_handshake.h"

#include <unistd.h>

#include "../src/c_common.h"
#include "bt_link.h"

SST_session_ctx_t* secure_connect_to_server_via_bt(session_key_t* s_key,
                                                   const char* peer) {
    SST_print_log("Bluetooth handshake: connecting to %s...", peer);
    int sock = bt_link_connect(peer, BT_LINK_DEFAULT_PSM);
    if (sock < 0) {
        SST_print_error("Bluetooth handshake: cannot connect to %s.", peer);
        return NULL;
    }
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server_with_socket(s_key, sock);
    if (session_ctx == NULL) {
        SST_print_error("Failed secure_connect_to_server_with_socket().");
        close(sock);
        return NULL;
    }
    SST_print_log("Bluetooth handshake: connected and authenticated.");
    return session_ctx;
}

SST_session_ctx_t* server_secure_comm_setup_via_bt(
    SST_ctx_t* ctx, session_key_list_t* existing_s_key_list) {
    SST_print_log("Bluetooth handshake: advertising, waiting for a peer...");
    int sock = bt_link_accept(BT_LINK_DEFAULT_PSM);
    if (sock < 0) {
        SST_print_error("Bluetooth handshake: no peer connected.");
        return NULL;
    }
    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, sock, existing_s_key_list);
    if (session_ctx == NULL) {
        SST_print_error("Failed server_secure_comm_setup().");
        close(sock);
        return NULL;
    }
    SST_print_log("Bluetooth handshake: peer authenticated.");
    return session_ctx;
}
