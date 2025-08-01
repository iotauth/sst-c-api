#ifndef SST_CRYPTO_EMBEDDED_H
#define SST_CRYPTO_EMBEDDED_H

#include <stdint.h>
#include <stddef.h>

#define SST_KEY_SIZE   16
#define SST_NONCE_SIZE 12
#define SST_TAG_SIZE   16   

// Encrypt using AES-GCM with provided key & nonce
int sst_encrypt_gcm(
    const uint8_t key[SST_KEY_SIZE],
    const uint8_t nonce[SST_NONCE_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[SST_TAG_SIZE]
);

#endif // SST_CRYPTO_EMBEDDED_H
