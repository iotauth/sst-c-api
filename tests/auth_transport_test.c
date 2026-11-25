#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "src/c_common.h"
#include "src/c_crypto.h"
#include "src/c_secure_comm.h"

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
            abort();                                                        \
        }                                                                   \
    } while (0)

enum response_kind { VALID_KEYS, WRONG_KEY_ID, WRONG_NONCE, TRUNCATED, ALERT };

struct auth_fixture {
    int socket;
    int use_tcp;
    enum response_kind response;
    // The server owns a copy so it never races with the client context.
    distribution_key_t key;
};

static int next_descriptor(void) {
    int fd = open("/dev/null", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    return fd;
}

static void send_frame(int sock, unsigned char type, unsigned char* body,
                       unsigned int length) {
    unsigned char frame[MAX_AUTH_COMM_LENGTH];
    unsigned int frame_length;
    make_sender_buf(body, length, type, frame, &frame_length);
    CHECK(sst_write_to_socket(sock, frame, frame_length) == (int)frame_length);
}

static void* serve_auth(void* opaque) {
    struct auth_fixture* fixture = opaque;
    int sock = fixture->socket;
    if (fixture->use_tcp) {
        sock = accept(fixture->socket, NULL, NULL);
        CHECK(sock >= 0);
    } else {
        unsigned char kickoff[2];
        CHECK(sst_read_from_socket(sock, kickoff, sizeof(kickoff)) == 1);
        CHECK(kickoff[0] == ENTITY_HELLO);
        // A UDP empty datagram must not be interpreted as EOF.
        CHECK(send(sock, "", 0, 0) == 0);
    }
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    CHECK(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                     sizeof(timeout)) == 0);

    if (fixture->response == TRUNCATED) {
        const unsigned char truncated[] = {AUTH_HELLO, AUTH_ID_LEN + NONCE_SIZE,
                                           0};
        CHECK(sst_write_to_socket(sock, truncated, sizeof(truncated)) ==
              (int)sizeof(truncated));
    } else if (fixture->response == ALERT) {
        const unsigned char alert[] = {AUTH_ALERT, INVALID_SESSION_KEY_REQ};
        CHECK(sst_write_to_socket(sock, alert, sizeof(alert)) ==
              (int)sizeof(alert));
    } else {
        unsigned char hello[AUTH_ID_LEN + NONCE_SIZE] = {0};
        write_in_n_bytes(101, AUTH_ID_LEN, hello);
        memset(hello + AUTH_ID_LEN, 0xa5, NONCE_SIZE);
        send_frame(sock, AUTH_HELLO, hello, sizeof(hello));

        unsigned char type;
        unsigned char request[MAX_AUTH_COMM_LENGTH];
        int length = read_header_return_data_buf_pointer(sock, &type, request,
                                                         sizeof(request));
        CHECK(length > 0 && type == SESSION_KEY_REQ);
        unsigned int prefix_length = 1 + request[0];
        CHECK(prefix_length < (unsigned int)length);
        unsigned char* plaintext = NULL;
        unsigned int plaintext_length;
        CHECK(symmetric_decrypt_authenticate(
                  request + prefix_length, length - prefix_length,
                  fixture->key.mac_key, fixture->key.mac_key_size,
                  fixture->key.cipher_key, fixture->key.cipher_key_size,
                  AES_128_CBC_IV_SIZE, AES_128_CBC, USE_HMAC, &plaintext,
                  &plaintext_length) == 0);
        CHECK(plaintext_length >= NONCE_SIZE * 2);
        CHECK(memcmp(plaintext + NONCE_SIZE, hello + AUTH_ID_LEN, NONCE_SIZE) ==
              0);

        unsigned char response[128] = {0};
        memcpy(response, plaintext, NONCE_SIZE);
        free(plaintext);
        if (fixture->response == WRONG_NONCE) response[NONCE_SIZE - 1] ^= 1;
        unsigned int offset = NONCE_SIZE;
        response[offset++] = 2;  // Length-prefixed crypto spec.
        response[offset++] = '{';
        response[offset++] = '}';
        write_in_n_bytes(1, 4, response + offset);
        offset += 4;
        // Binary IDs share a leading NUL; strcmp/strncmp cannot compare them.
        response[offset + SESSION_KEY_ID_SIZE - 1] =
            fixture->response == WRONG_KEY_ID ? 43 : 42;
        offset += SESSION_KEY_ID_SIZE;
        memset(response + offset, 0xff, ABS_VALIDITY_SIZE);
        offset += ABS_VALIDITY_SIZE;
        write_in_n_bytes(60000, REL_VALIDITY_SIZE, response + offset);
        offset += REL_VALIDITY_SIZE;
        response[offset++] = CIPHER_KEY_SIZE;
        memset(response + offset, 0x11, CIPHER_KEY_SIZE);
        offset += CIPHER_KEY_SIZE;
        response[offset++] = MAC_KEY_SIZE;
        memset(response + offset, 0x22, MAC_KEY_SIZE);
        offset += MAC_KEY_SIZE;

        unsigned char* encrypted = NULL;
        unsigned int encrypted_length;
        CHECK(symmetric_encrypt_authenticate(
                  response, offset, fixture->key.mac_key,
                  fixture->key.mac_key_size, fixture->key.cipher_key,
                  fixture->key.cipher_key_size, AES_128_CBC_IV_SIZE,
                  AES_128_CBC, USE_HMAC, &encrypted, &encrypted_length) == 0);
        send_frame(sock, SESSION_KEY_RESP, encrypted, encrypted_length);
        free(encrypted);
    }
    if (fixture->use_tcp) CHECK(close(sock) == 0);
    return NULL;
}

static void check_exchange(int use_tcp, enum response_kind response) {
    int before = next_descriptor();
    int listener = socket(AF_INET, use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0);
    socklen_t address_length = sizeof(address);
    CHECK(getsockname(listener, (struct sockaddr*)&address, &address_length) ==
          0);
    if (use_tcp) CHECK(listen(listener, 1) == 0);

    SST_ctx_t ctx = {0};
    strcpy(ctx.config.auth_ip_addr, "127.0.0.1");
    strcpy(ctx.config.network_protocol, use_tcp ? "TCP" : "UDP");
    strcpy(ctx.config.name, "net1.client");
    strcpy(ctx.purpose_for_requesting_key, "{\"keyId\":42}");
    ctx.config.auth_port_num = ntohs(address.sin_port);
    ctx.config.auth_id = 101;
    ctx.config.numkey = 1;
    ctx.config.session_key_enc_mode = AES_128_CBC;
    ctx.config.hmac_mode = USE_HMAC;
    ctx.dist_key.abs_validity = UINT64_MAX;
    ctx.dist_key.cipher_key_size = CIPHER_KEY_SIZE;
    ctx.dist_key.mac_key_size = MAC_KEY_SIZE;
    ctx.dist_key.enc_mode = AES_128_CBC;
    struct auth_fixture fixture = {listener, use_tcp, response, ctx.dist_key};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, serve_auth, &fixture) == 0);
    unsigned char id[SESSION_KEY_ID_SIZE] = {0};
    id[SESSION_KEY_ID_SIZE - 1] = 42;
    session_key_list_t* keys =
        send_session_key_request_check_protocol(&ctx, id);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(close(listener) == 0);
    if (response == VALID_KEYS) {
        CHECK(keys != NULL && keys->num_key == 1);
        CHECK(memcmp(keys->s_key[0].key_id, id, sizeof(id)) == 0);
        CHECK(keys->s_key[0].cipher_key_size == CIPHER_KEY_SIZE);
        CHECK(keys->s_key[0].mac_key_size == MAC_KEY_SIZE);
        free_session_key_list_t(keys);
    } else {
        CHECK(keys == NULL);
    }
    CHECK(next_descriptor() == before);
}

int main(void) {
    for (int use_tcp = 0; use_tcp <= 1; ++use_tcp) {
        for (int response = VALID_KEYS; response <= ALERT; ++response)
            check_exchange(use_tcp, (enum response_kind)response);
    }
    puts("TCP and UDP Auth transport regression tests passed.");
    return 0;
}
