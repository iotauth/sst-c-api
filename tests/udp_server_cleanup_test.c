#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/c_api.h"

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
            abort();                                                        \
        }                                                                   \
    } while (0)

enum failure { NONE, INIT, ALLOCATE, SOCKET, BIND, HANDSHAKE, THREAD, SEND };
static enum failure failure;
static SST_ctx_t context;
static session_key_list_t keys;
static SST_session_ctx_t session;
static int closes;
static int contexts_freed;
static int keys_freed;
static int sessions_freed;
static int sends;
static int cancelled;
static int joined;
static const int listener = 42;

static SST_ctx_t* fake_init(const char* path) {
    CHECK(strcmp(path, "udp.config") == 0);
    return failure == INIT ? NULL : &context;
}

static session_key_list_t* fake_keys(void) {
    return failure == ALLOCATE ? NULL : &keys;
}

static int fake_socket(int domain, int type, int protocol) {
    CHECK(domain == AF_INET && type == SOCK_DGRAM && protocol == 0);
    if (failure == SOCKET) {
        errno = EMFILE;
        return -1;
    }
    return listener;
}

static int fake_bind(int sock, const struct sockaddr* address,
                     socklen_t length) {
    CHECK(sock == listener && length == sizeof(struct sockaddr_in));
    struct sockaddr_in ipv4;
    memcpy(&ipv4, address, sizeof(ipv4));
    CHECK(ntohs(ipv4.sin_port) == 23456);
    if (failure == BIND) {
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

static int fake_close(int sock) {
    CHECK(sock == listener);
    CHECK(++closes == 1);
    return 0;
}

static SST_session_ctx_t* fake_handshake(const SST_ctx_t* ctx, int sock,
                                         const session_key_list_t* list) {
    CHECK(ctx == &context && sock == listener && list == &keys);
    return failure == HANDSHAKE ? NULL : &session;
}

static int fake_thread(pthread_t* thread, const pthread_attr_t* attributes,
                       void* (*entry)(void*), void* argument) {
    CHECK(attributes == NULL && entry == receive_thread_read_one_each);
    CHECK(argument == &session);
    if (failure == THREAD) return EAGAIN;
    *thread = pthread_self();
    return 0;
}

// No worker is actually started; ignore the unused pthread_t value.
#define fake_cancel(thread) ((void)++cancelled)
#define fake_join(thread, result) ((void)++joined)
#define fake_sleep(seconds) ((void)0)

static int fake_send(const char* message, unsigned int length,
                     const SST_session_ctx_t* ctx) {
    CHECK(ctx == &session && length == strlen(message));
    ++sends;
    return failure == SEND ? -1 : (int)length;
}

static void fake_free_context(const SST_ctx_t* ctx) {
    CHECK(ctx == &context);
    ++contexts_freed;
}

static void fake_free_keys(const session_key_list_t* list) {
    CHECK(list == NULL || list == &keys);
    if (list != NULL) ++keys_freed;
}

static void fake_free_session(const SST_session_ctx_t* ctx) {
    CHECK(ctx == NULL || ctx == &session);
    if (ctx != NULL) ++sessions_freed;
}

// Exercise the example's ownership paths without Auth, threads or network I/O.
#define main udp_server_main
#define init_SST fake_init
#define init_empty_session_key_list fake_keys
#define socket fake_socket
#define bind fake_bind
#define close fake_close
#define server_secure_comm_setup fake_handshake
#define pthread_create fake_thread
#define pthread_cancel fake_cancel
#define pthread_join fake_join
#define sleep fake_sleep
#define send_secure_message fake_send
#define free_SST_ctx_t fake_free_context
#define free_session_key_list_t fake_free_keys
#define free_session_ctx fake_free_session
#include "../examples/server_client_example/entity_server_udp.c"
#undef main

int main(void) {
    char program[] = "entity_server_udp";
    char config[] = "udp.config";
    char* argv[] = {program, config, NULL};
    strcpy(context.config.network_protocol, "UDP");
    context.config.entity_server_port_num = 23456;
    for (int scenario = NONE; scenario <= SEND; ++scenario) {
        failure = (enum failure)scenario;
        closes = 0;
        contexts_freed = 0;
        keys_freed = 0;
        sessions_freed = 0;
        sends = 0;
        cancelled = 0;
        joined = 0;
        errno = 0;
        CHECK(udp_server_main(2, argv) ==
              (failure == NONE ? EXIT_SUCCESS : EXIT_FAILURE));
        CHECK(contexts_freed == (failure != INIT));
        CHECK(keys_freed == (failure != INIT && failure != ALLOCATE));
        CHECK(closes == (failure == NONE || failure >= BIND));
        CHECK(sessions_freed == (failure == NONE || failure >= THREAD));
        CHECK(cancelled == (failure == NONE || failure == SEND));
        CHECK(joined == cancelled);
        CHECK(sends == (failure == NONE ? 2 : failure == SEND ? 1 : 0));
    }
    puts("UDP server cleanup regression tests passed.");
    return 0;
}
