#include "session_ctl.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "../src/c_common.h"

int session_key_fresh(const session_key_t* key) {
    time_t now = time(NULL);
    return key && now >= 0 && (uint64_t)now * 1000 < key->abs_validity;
}

void session_ctl_sleep_ms(unsigned ms) {
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

int session_ctl_send(SST_session_ctx_t* s, const unsigned char* msg,
                     unsigned len) {
    return send_secure_message((char*)msg, len, s) < 0 ? -1 : 0;
}

int session_ctl_recv(SST_session_ctx_t* s, const unsigned char* prefix,
                     unsigned prefix_len, unsigned char* msg, unsigned len,
                     const char* who) {
    unsigned char buf[MAX_SECURE_COMM_MSG_LENGTH];
    int n = read_secure_message(buf, s);
    if (n <= 0) {
        SST_print_error(
            "%s: control message not received (timeout, disconnect or "
            "error).",
            who);
        return -1;
    }
    if ((unsigned)n != len || len < prefix_len ||
        memcmp(buf, prefix, prefix_len)) {
        SST_print_error("%s: unexpected control message.", who);
        return -1;
    }
    memcpy(msg, buf, len);
    return 0;
}

int session_ctl_timeout_set(int sock, unsigned ms, session_ctl_timeout* t) {
    socklen_t len = sizeof(t->previous);
    t->saved =
        getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t->previous, &len) == 0;
    struct timeval tv = {(time_t)(ms / 1000),
                         (suseconds_t)((ms % 1000) * 1000)};
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ? -1 : 0;
}

void session_ctl_timeout_restore(int sock, const session_ctl_timeout* t) {
    if (t->saved)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t->previous,
                   sizeof(t->previous));
}
