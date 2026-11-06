#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
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

static EVP_PKEY* make_rsa_key(void) {
    EVP_PKEY_CTX* generator = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    CHECK(generator != NULL);
    CHECK(EVP_PKEY_keygen_init(generator) > 0);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(generator, RSA_KEY_SIZE * 8) > 0);
    EVP_PKEY* key = NULL;
    CHECK(EVP_PKEY_keygen(generator, &key) > 0);
    EVP_PKEY_CTX_free(generator);
    return key;
}

static void check_request(SST_ctx_t* ctx, int public_key, int key_request) {
    int sockets[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    unsigned char hello[AUTH_ID_LEN + NONCE_SIZE] = {0};
    write_in_n_bytes(ctx->config.auth_id, AUTH_ID_LEN, hello);
    memset(hello + AUTH_ID_LEN, 0xa5, NONCE_SIZE);
    unsigned char nonce[NONCE_SIZE];
    char purpose[] = "{\"group\":\"Servers\"}";
    int num_keys = key_request ? 1 : 0;
    ctx->dist_key.abs_validity = public_key ? 0 : UINT64_MAX;

    CHECK(handle_AUTH_HELLO(hello, ctx, nonce, sockets[0], num_keys, purpose,
                            key_request) == 0);
    unsigned char frame[MAX_AUTH_COMM_LENGTH];
    int length = sst_read_from_socket(sockets[1], frame, sizeof(frame));
    CHECK(length > 0);
    unsigned char msg_type;
    unsigned int body_length;
    unsigned char* body =
        parse_received_message(frame, length, &msg_type, &body_length);
    unsigned char* plaintext = NULL;
    size_t plaintext_length;
    if (public_key) {
        CHECK(msg_type == (key_request ? SESSION_KEY_REQ_IN_PUB_ENC
                                       : ADD_READER_REQ_IN_PUB_ENC));
        CHECK(body_length == RSA_KEY_SIZE * 2);
        CHECK(SHA256_verify(body, RSA_KEY_SIZE, body + RSA_KEY_SIZE,
                            RSA_KEY_SIZE, ctx->pub_key) == 0);
        plaintext = private_decrypt(body, RSA_KEY_SIZE, RSA_PKCS1_OAEP_PADDING,
                                    ctx->priv_key, &plaintext_length);
        CHECK(plaintext != NULL);
    } else {
        CHECK(msg_type == (key_request ? SESSION_KEY_REQ : ADD_READER_REQ));
        size_t name_length = strlen(ctx->config.name);
        CHECK(body_length > name_length + 1);
        CHECK(body[0] == name_length);
        CHECK(memcmp(body + 1, ctx->config.name, name_length) == 0);
        unsigned int decrypted_length;
        CHECK(symmetric_decrypt_authenticate(
                  body + 1 + name_length, body_length - 1 - name_length,
                  ctx->dist_key.mac_key, ctx->dist_key.mac_key_size,
                  ctx->dist_key.cipher_key, ctx->dist_key.cipher_key_size,
                  AES_128_CBC_IV_SIZE, ctx->dist_key.enc_mode, USE_HMAC,
                  &plaintext, &decrypted_length) == 0);
        plaintext_length = decrypted_length;
    }
    CHECK(plaintext_length >= NONCE_SIZE * 2);
    CHECK(memcmp(plaintext, nonce, NONCE_SIZE) == 0);
    CHECK(memcmp(plaintext + NONCE_SIZE, hello + AUTH_ID_LEN, NONCE_SIZE) == 0);
    OPENSSL_free(plaintext);
    CHECK(close(sockets[0]) == 0);
    CHECK(close(sockets[1]) == 0);

    // A failed write must release both the serialized and encrypted buffers.
    CHECK(handle_AUTH_HELLO(hello, ctx, nonce, -1, num_keys, purpose,
                            key_request) < 0);
}

int main(void) {
    EVP_PKEY* key = make_rsa_key();
    SST_ctx_t ctx = {0};
    ctx.pub_key = key;
    ctx.priv_key = key;
    ctx.config.auth_id = 101;
    memcpy(ctx.config.name, "net1.client", sizeof("net1.client"));
    ctx.dist_key.cipher_key_size = AES_128_KEY_SIZE_IN_BYTES;
    ctx.dist_key.mac_key_size = MAC_KEY_SIZE;
    ctx.dist_key.enc_mode = AES_128_CBC;
    for (int public_key = 0; public_key <= 1; ++public_key) {
        check_request(&ctx, public_key, 1);
        check_request(&ctx, public_key, 0);
    }
    EVP_PKEY_free(key);
    puts("Auth request ownership regression tests passed.");
    return 0;
}
