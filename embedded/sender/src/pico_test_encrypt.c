#include <stdio.h>
#include <string.h>
#include "../../include/sst_crypto_embedded.h"

int main() {
    uint8_t key[SST_KEY_SIZE] = { 0x00 };
    uint8_t nonce[SST_NONCE_SIZE] = { 0x01 };
    const char *msg = "Hello, LiFi!";
    size_t len = strlen(msg);

    uint8_t ciphertext[128] = {0};
    uint8_t tag[SST_TAG_SIZE] = {0};

    int ret = sst_encrypt_gcm(
        key, nonce, (const uint8_t *)msg, len,
        ciphertext, tag
    );

    if (ret == 0) {
        printf("Encryption success:\n");
        printf("Ciphertext: ");
        for (size_t i = 0; i < len; i++) printf("%02X ", ciphertext[i]);
        printf("\nTag: ");
        for (int i = 0; i < SST_TAG_SIZE; i++) printf("%02X ", tag[i]);
        printf("\n");
    } else {
        printf("Encryption failed! ret = %d\n", ret);
    }

    return 0;
}
