#include <stdio.h>
#include <string.h>

#include "../c_api.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);

    unsigned char iv_high[8], iv_low[8];
    memset(iv_high, 0, 8);
    memset(iv_low, 0, 8);

    uint64_t initial_iv_high = 0, initial_iv_low = 0;
    memcpy(&initial_iv_high, iv_high, sizeof(iv_high));
    memcpy(&initial_iv_low, iv_low, sizeof(iv_low));

    unsigned char data[100] =
        "0123456789abcdef0123456789abcdef0123456789abcdef";
    size_t data_size = strlen((const char *)data);

    unsigned char encrypted_data[100];
    unsigned char decrypted_data[100];
    unsigned int processed_size;

    printf("Original data: %s\n", data);

    // Encrypt the data
    if (CTR_encrypt_buf_with_session_key(
            &s_key_list->s_key[0], initial_iv_high, initial_iv_low, 0, data, 20,
            encrypted_data, sizeof(encrypted_data), &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    if (CTR_encrypt_buf_with_session_key(
            &s_key_list->s_key[0], initial_iv_high, initial_iv_low, 20,
            data + 20, 20, encrypted_data + 20, sizeof(encrypted_data) - 20,
            &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    if (CTR_encrypt_buf_with_session_key(
            &s_key_list->s_key[0], initial_iv_high, initial_iv_low, 40,
            data + 40, data_size - 40, encrypted_data + 40,
            sizeof(encrypted_data) - 40, &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    printf("Encrypted data: ");
    for (size_t i = 0; i < data_size; i++) {
        printf("%02x", encrypted_data[i]);
    }
    printf("\n");

    // Decrypt the data in chunks of 20 bytes
    if (CTR_decrypt_buf_with_session_key(&s_key_list->s_key[0], initial_iv_high,
                                         initial_iv_low, 0, encrypted_data, 20,
                                         decrypted_data, sizeof(decrypted_data),
                                         &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    if (CTR_decrypt_buf_with_session_key(
            &s_key_list->s_key[0], initial_iv_high, initial_iv_low, 20,
            encrypted_data + 20, 20, decrypted_data + 20,
            sizeof(decrypted_data) - 20, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    if (CTR_decrypt_buf_with_session_key(
            &s_key_list->s_key[0], initial_iv_high, initial_iv_low, 40,
            encrypted_data + 40, data_size - 40, decrypted_data + 40,
            sizeof(decrypted_data) - 40, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Decrypted data: %s\n", decrypted_data);

    return 0;
}
