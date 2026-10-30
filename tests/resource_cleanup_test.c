#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/c_api.h"
#include "src/c_common.h"
#include "src/c_crypto.h"
#include "src/c_secure_comm.h"
#include "src/ipfs.h"
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

static void write_config(const char* path, const char* contents) {
    FILE* file = fopen(path, "w");
    CHECK(file != NULL);
    CHECK(fputs(contents, file) >= 0);
    CHECK(fclose(file) == 0);
}

static void test_config_cleanup(const char* path) {
    const char* invalid[] = {
        "unknown.setting=value\n",
        "entityInfo.name=\n",
        "entityInfo.name=abcdefghijklmnopqrstuvwxyz0123456789\n",
        "auth.port.number=-1\n",
        "entity.server.port.number=65536\n",
        "fileSystemManager.port.number=-1\n",
        "HmacMode=invalid\n",
        "PermanentDistKeyMode=invalid\n",
        "distKey.encryptionMode=invalid\n",
        "distKey.cipherkey.path=cipher.key\n",
    };
    int before = next_descriptor();
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        write_config(path, invalid[i]);
        config_t config = {0};
        CHECK(load_config(&config, path) < 0);
        CHECK(next_descriptor() == before);
    }
    write_config(path,
                 "entityInfo.name=net1.client\n"
                 "entityInfo.purpose=first\nentityInfo.purpose=second\n"
                 "entityInfo.number_key=3\nauthInfo.id=101\n"
                 "authInfo.pubkey.path=auth.pem\n"
                 "entityInfo.privkey.path=entity.pem\n"
                 "auth.ip.address=127.0.0.1\nauth.port.number=21900\n"
                 "entity.server.ip.address=127.0.0.1\n"
                 "entity.server.port.number=21100\nnetwork.protocol=TCP\n"
                 "fileSystemManager.ip.address=127.0.0.1\n"
                 "fileSystemManager.port.number=22100\n"
                 "HmacMode=off\nPermanentDistKeyMode=on\n"
                 "distKey.cipherkey.path=cipher.key\n"
                 "distkey.mackey.path=mac.key\n"
                 "sessionKey.encryptionMode=AES_128_GCM\n"
                 "distKey.encryptionMode=AES_128_CTR\n");
    config_t config = {0};
    CHECK(load_config(&config, path) == 0);
    CHECK(next_descriptor() == before);
    CHECK(strcmp(config.name, "net1.client") == 0);
    CHECK(config.purpose_index == 1 &&
          strcmp(config.purpose[1], "second") == 0);
    CHECK(config.numkey == 3 && config.auth_id == 101);
    CHECK(config.auth_port_num == 21900 &&
          config.entity_server_port_num == 21100);
    CHECK(config.file_system_manager_port_num == 22100);
    CHECK(config.hmac_mode == NO_HMAC);
    CHECK(config.perm_dist_key_mode == USE_PERMANENT_DIST_KEY);
    CHECK(config.session_key_enc_mode == AES_128_GCM);
    CHECK(config.dist_key_enc_mode == AES_128_CTR);
    CHECK(strcmp(config.dist_cipher_key_path, "cipher.key") == 0);
    CHECK(strcmp(config.dist_mac_key_path, "mac.key") == 0);
}

static void test_file_read_cleanup(const char* directory, const char* path) {
    session_key_t key = {0};
    key.enc_mode = AES_128_CBC;
    int before = next_descriptor();
    CHECK(file_decrypt_save(key, "missing-input-file") < 0);
    write_config(path, "");
    CHECK(file_decrypt_save(key, (char*)path) < 0);
    CHECK(next_descriptor() == before);

    const unsigned char plaintext[] = {'a', 0, 'b', 'c'};
    unsigned char iv[AES_128_CBC_IV_SIZE] = {0};
    unsigned char encrypted[32];
    unsigned int encrypted_length;
    CHECK(encrypt_AES(plaintext, sizeof(plaintext), key.cipher_key, iv,
                      key.enc_mode, encrypted, &encrypted_length) == 0);
    FILE* file = fopen(path, "wb");
    CHECK(file != NULL);
    CHECK(fputc(0, file) == 0);  // Empty owner name is a valid length field.
    CHECK(fputc(sizeof(iv), file) == sizeof(iv));
    CHECK(fwrite(iv, 1, sizeof(iv), file) == sizeof(iv));
    CHECK(fwrite(encrypted, 1, encrypted_length, file) == encrypted_length);
    CHECK(fclose(file) == 0);
    int cwd = open(".", O_RDONLY);
    CHECK(cwd >= 0);
    CHECK(chdir(directory) == 0);
    CHECK(file_decrypt_save(key, (char*)path) == 0);
    file = fopen("result.txt", "rb");
    CHECK(file != NULL);
    unsigned char result[sizeof(plaintext)];
    CHECK(fread(result, 1, sizeof(result), file) == sizeof(result));
    CHECK(memcmp(result, plaintext, sizeof(result)) == 0);
    CHECK(fgetc(file) == EOF);
    CHECK(fclose(file) == 0);
    CHECK(unlink("result.txt") == 0);
    CHECK(fchdir(cwd) == 0);
    CHECK(close(cwd) == 0);
    CHECK(next_descriptor() == before);
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

int main(int argc, char* argv[]) {
    test_integer_decoding();
    CHECK(argc == 2);
    // CTest supplies the build directory; mkdtemp creates a private
    // subdirectory.
    char directory[MAX_PATH_LEN];
    int length = snprintf(directory, sizeof(directory),
                          "%s/sst-resource-XXXXXX", argv[1]);
    CHECK(length > 0 && (size_t)length < sizeof(directory));
    CHECK(mkdtemp(directory) != NULL);
    char path[MAX_PATH_LEN];
    length = snprintf(path, sizeof(path), "%s/invalid", directory);
    CHECK(length > 0 && (size_t)length < sizeof(path));
    write_config(path, "unknown.setting=value\n");

    int before = next_descriptor();
    CHECK(load_auth_public_key(path) == NULL);
    CHECK(next_descriptor() == before);
    test_config_cleanup(path);
    test_file_read_cleanup(directory, path);
    CHECK(unlink(path) == 0);
    CHECK(rmdir(directory) == 0);
    test_handshake_cleanup();
    puts("Resource cleanup regression tests passed.");
    return 0;
}
