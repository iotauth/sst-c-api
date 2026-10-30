#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/c_api.h"
#include "src/c_common.h"
#include "src/c_crypto.h"
#include "src/c_secure_comm.h"
#include "src/load_config.h"

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
            abort();                                                        \
        }                                                                   \
    } while (0)

static int next_descriptor(void) {
    int fd = open("/dev/null", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    return fd;
}

static void test_integer_decoding(void) {
    unsigned char bytes[] = {0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};
    unsigned char zeros[8] = {0};
    CHECK(read_unsigned_int_BE(bytes, 4) == UINT32_C(0x89abcdef));
    CHECK(read_unsigned_int_BE(bytes, 8) == UINT32_C(0xfedcba98));
    CHECK(read_unsigned_long_int_BE(bytes, 8) == UINT64_C(0x89abcdeffedcba98));
    CHECK(read_unsigned_long_int_BE(zeros, 8) == 0);
}

struct handshake_client {
    int sock;
    session_key_t key;
    SST_session_ctx_t* session;
};

static void* connect_client(void* opaque) {
    struct handshake_client* client = opaque;
    client->session =
        secure_connect_to_server_with_socket(&client->key, client->sock);
    return NULL;
}

static void test_handshake_cleanup(void) {
    int sockets[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    struct handshake_client client = {0};
    client.sock = sockets[0];
    client.key.key_id[7] = 42;
    client.key.abs_validity = UINT64_MAX;
    client.key.rel_validity = 60000;
    client.key.cipher_key_size = 16;
    client.key.mac_key_size = 32;
    client.key.enc_mode = AES_128_CBC;
    client.key.hmac_mode = USE_HMAC;
    session_key_list_t* keys = init_empty_session_key_list();
    CHECK(keys != NULL);
    CHECK(add_session_key_to_list(&client.key, keys) >= 0);
    SST_ctx_t ctx = {0};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, connect_client, &client) == 0);
    SST_session_ctx_t* server =
        server_secure_comm_setup(&ctx, sockets[1], keys);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(server != NULL && client.session != NULL);
    free_session_ctx(server);
    free_session_ctx(client.session);
    CHECK(close(sockets[0]) == 0);
    CHECK(close(sockets[1]) == 0);

    // An aborted handshake must not allocate or retain a session context.
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(shutdown(sockets[0], SHUT_WR) == 0);
    CHECK(server_secure_comm_setup(&ctx, sockets[1], keys) == NULL);
    CHECK(close(sockets[0]) == 0);
    CHECK(close(sockets[1]) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(shutdown(sockets[1], SHUT_WR) == 0);
    CHECK(secure_connect_to_server_with_socket(&client.key, sockets[0]) ==
          NULL);
    CHECK(close(sockets[0]) == 0);
    CHECK(close(sockets[1]) == 0);
    free_session_key_list_t(keys);
    free_session_key_list_t(NULL);
}

int main(void) {
    test_integer_decoding();
    char directory[] = "/tmp/sst-resource-test-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char path[256];
    CHECK(snprintf(path, sizeof(path), "%s/invalid", directory) > 0);
    FILE* file = fopen(path, "w");
    CHECK(file != NULL);
    CHECK(fputs("unknown.setting=value\n", file) >= 0);
    CHECK(fclose(file) == 0);

    int before = next_descriptor();
    CHECK(load_auth_public_key(path) == NULL);
    CHECK(next_descriptor() == before);
    config_t config = {0};
    CHECK(load_config(&config, path) < 0);
    CHECK(next_descriptor() == before);
    CHECK(unlink(path) == 0);
    CHECK(rmdir(directory) == 0);
    test_handshake_cleanup();
    puts("Resource cleanup regression tests passed.");
    return 0;
}
