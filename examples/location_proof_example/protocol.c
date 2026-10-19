/**
 *  Shared helpers for the location verification protocol.
 */

#include "protocol.h"

#include <stdio.h>
#include <string.h>

int read_exact_message(SST_session_ctx_t* session_ctx, void* out, size_t len,
                       const char* message_name) {
    unsigned char recv_buf[MAX_SECURE_COMM_MSG_LENGTH];

    int bytes_read = read_secure_message(recv_buf, session_ctx);

    if (bytes_read < 0) {
        fprintf(stderr, "Failed to read %s.\n", message_name);
        return -1;
    }

    if (bytes_read == 0) {
        fprintf(stderr, "Connection closed while reading %s.\n", message_name);
        return -1;
    }

    if ((size_t)bytes_read != len) {
        fprintf(stderr, "Invalid %s size.\n", message_name);
        return -1;
    }

    memcpy(out, recv_buf, len);

    return 0;
}