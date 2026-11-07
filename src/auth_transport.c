#include "auth_transport.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "c_common.h"

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int sst_auth_open(sst_auth_connection_t* connection, const char* ip, int port,
                  const char* protocol, int timeout_ms) {
    connection->sock = -1;
    connection->deadline_ms = 0;
    connection->use_tcp = strcmp(protocol, "TCP") == 0;
    if ((!connection->use_tcp && strcmp(protocol, "UDP") != 0) ||
        timeout_ms <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (connect_as_client(ip, port, &connection->sock, connection->use_tcp) < 0)
        return -1;
    if (connection->use_tcp) return 0;

    int64_t now = monotonic_ms();
    struct timeval timeout = {.tv_sec = timeout_ms / 1000,
                              .tv_usec = (timeout_ms % 1000) * 1000};
    const unsigned char hello = ENTITY_HELLO;
    if (now >= 0 && setsockopt(connection->sock, SOL_SOCKET, SO_SNDTIMEO,
                               &timeout, sizeof(timeout)) == 0) {
        connection->deadline_ms = now + timeout_ms;
        if (sst_write_to_socket(connection->sock, &hello, sizeof(hello)) ==
            sizeof(hello))
            return 0;
    }
    int saved_errno = errno;
    close(connection->sock);
    connection->sock = -1;
    errno = saved_errno;
    return -1;
}

int sst_auth_read(const sst_auth_connection_t* connection, unsigned char* buf,
                  unsigned int capacity) {
    if (connection->use_tcp)
        return sst_read_from_socket(connection->sock, buf, capacity);
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0) return -1;
        int64_t remaining = connection->deadline_ms - now;
        if (remaining <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct timeval timeout = {.tv_sec = remaining / 1000,
                                  .tv_usec = (remaining % 1000) * 1000};
        if (setsockopt(connection->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) < 0)
            return -1;
        int length = sst_read_from_socket(connection->sock, buf, capacity);
        if (length > 0) return length;
        if (length == 0 || errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) errno = ETIMEDOUT;
        return -1;
    }
}
