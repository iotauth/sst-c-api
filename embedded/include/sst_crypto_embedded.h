#ifndef SST_CRYPTO_EMBEDDED_H
#define SST_CRYPTO_EMBEDDED_H

#include <stddef.h>
#include <stdint.h>

#define SST_KEY_SIZE 16
#define SST_NONCE_SIZE 12
#define SST_TAG_SIZE 16

// Encrypt using AES-GCM with provided key & nonce.
// @param key AES-128 key (16 bytes)
// @param nonce Nonce (12 bytes, must be unique per message)
// @param input Plaintext input buffer
// @param input_len Length of plaintext
// @param ciphertext Output buffer for encrypted data
// @param tag Output buffer for authentication tag (16 bytes)
// @return 0 on success, non-zero on failure
int sst_encrypt_gcm(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *input, size_t input_len, uint8_t *ciphertext,
                    uint8_t *tag);

// Decrypt using AES-GCM with provided key, nonce, and tag.
// @param key AES-128 key (16 bytes)
// @param nonce Nonce used during encryption
// @param ciphertext Input buffer with encrypted data
// @param ciphertext_len Length of ciphertext
// @param tag Authentication tag (16 bytes)
// @param output Output buffer for decrypted plaintext
// @return 0 on success, non-zero if authentication fails
int sst_decrypt_gcm(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *tag, uint8_t *output);

#endif  // SST_CRYPTO_EMBEDDED_H
