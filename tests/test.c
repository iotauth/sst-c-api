#include <stdio.h>
#include <string.h>

#include "../c_api.h"

int main() {
    unsigned char key[16];
    memset(key, 0, sizeof(key));  // For demonstration purposes, a zeroed key

    unsigned char iv_high[8], iv_low[8];
    memset(iv_high, 0, 8);
    memset(iv_low, 0, 8);

    uint64_t initial_iv_high = 0, initial_iv_low = 0;
    memcpy(&initial_iv_high, iv_high, sizeof(iv_high));
    memcpy(&initial_iv_low, iv_low, sizeof(iv_low));

    unsigned char data[100] =
        "0123456789abcdef0123456789abcdef0123456789abcdef";
    size_t data_size = strlen((const char*)data);

    unsigned char encrypted_data[100];
    unsigned char decrypted_data[100];
    unsigned int processed_size;

    printf("Original data: %s\n", data);

    // Encrypt the data
    if (CTR_Encrypt(key, initial_iv_high, initial_iv_low, 0, data,
                    encrypted_data, 20, sizeof(encrypted_data),
                    &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    if (CTR_Encrypt(key, initial_iv_high, initial_iv_low, 20, data + 20,
                    encrypted_data + 20, 20, sizeof(encrypted_data) - 20,
                    &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    if (CTR_Encrypt(key, initial_iv_high, initial_iv_low, 40, data + 40,
                    encrypted_data + 40, data_size - 40,
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
    if (CTR_Decrypt(key, initial_iv_high, initial_iv_low, 0, encrypted_data,
                    decrypted_data, 20, sizeof(decrypted_data),
                    &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    if (CTR_Decrypt(key, initial_iv_high, initial_iv_low, 20,
                    encrypted_data + 20, decrypted_data + 20, 20,
                    sizeof(decrypted_data) - 20, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    if (CTR_Decrypt(key, initial_iv_high, initial_iv_low, 40,
                    encrypted_data + 40, decrypted_data + 40, data_size - 40,
                    sizeof(decrypted_data) - 40, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Decrypted data: %s\n", decrypted_data);

    return 0;
}
