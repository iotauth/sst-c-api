#ifndef SST_AUTH_TRANSPORT_H
#define SST_AUTH_TRANSPORT_H

#include <stdbool.h>
#include <stdint.h>

// One deadline covers the UDP kickoff, AUTH_HELLO and final Auth response.
#define SST_AUTH_TIMEOUT_MS 5000

typedef struct {
    int sock;
    bool use_tcp;
    int64_t deadline_ms;
} sst_auth_connection_t;

// On failure the socket is closed and sock is -1. The caller owns it on
// success.
int sst_auth_open(sst_auth_connection_t* connection, const char* ip, int port,
                  const char* protocol, int timeout_ms);

// Ignores empty UDP datagrams without extending the exchange deadline.
int sst_auth_read(const sst_auth_connection_t* connection, unsigned char* buf,
                  unsigned int capacity);

#endif
