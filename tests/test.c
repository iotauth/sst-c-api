#include <assert.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to handle errors
void error_exit(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

// Function to convert uint64_t to big endian and store in buffer
void PutBigEndian64(uint64_t value, unsigned char *output) {
    for (int i = 0; i < 8; ++i) {
        output[7 - i] = value & 0xff;
        value >>= 8;
    }
}


int Cipher(const unsigned char *key, const uint64_t initial_iv_high,
           const uint64_t initial_iv_low, uint64_t file_offset,
           const unsigned char *data, unsigned char *out_data, size_t data_size, size_t out_data_size, int encrypt, size_t *processed_size) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        error_exit("Failed to create EVP_CIPHER_CTX");
    }

    const size_t kBlockSize = 16;  // AES block size
    if (out_data_size < data_size) {
        fprintf(stderr, "Output buffer is too small, required: %zu, provided: %zu\n", data_size, out_data_size);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    uint64_t block_index = file_offset / kBlockSize;
    uint64_t block_offset = file_offset % kBlockSize;

    uint64_t iv_high = initial_iv_high;
    uint64_t iv_low = initial_iv_low + block_index;
    if (ULLONG_MAX - block_index < initial_iv_low) {
        iv_high++;
    }

    unsigned char iv[kBlockSize];
    PutBigEndian64(iv_high, iv);
    PutBigEndian64(iv_low, iv + sizeof(uint64_t));

    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv, encrypt) != 1) {
        error_exit("Failed to initialize cipher");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char partial_block[kBlockSize];
    size_t data_offset = 0;
    size_t remaining_data_size = data_size;
    int output_size = 0;
    *processed_size = 0;

    if (block_offset > 0) {
        size_t partial_block_size = kBlockSize - block_offset < remaining_data_size
                                    ? kBlockSize - block_offset
                                    : remaining_data_size;
        memcpy(partial_block + block_offset, data, partial_block_size);
        if (EVP_CipherUpdate(ctx, partial_block, &output_size, partial_block, kBlockSize) != 1) {
            error_exit("Failed to update cipher");
        }
        if (output_size != kBlockSize) {
            fprintf(stderr, "Unexpected output size for first block, expected %zu vs actual %d\n",
                    kBlockSize, output_size);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        memcpy(out_data, partial_block + block_offset, partial_block_size);
        data_offset += partial_block_size;
        remaining_data_size -= partial_block_size;
        *processed_size += partial_block_size;
    }

    while (remaining_data_size >= kBlockSize) {
        const unsigned char *full_blocks = data + data_offset;
        unsigned char *full_blocks_out = out_data + data_offset;
        size_t actual_data_size = remaining_data_size - (remaining_data_size % kBlockSize);
        if (EVP_CipherUpdate(ctx, full_blocks_out, &output_size, full_blocks, actual_data_size) != 1) {
            error_exit("Failed to update cipher");
        }
        if (output_size != actual_data_size) {
            fprintf(stderr, "Unexpected output size, expected %zu vs actual %d\n",
                    actual_data_size, output_size);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        data_offset += actual_data_size;
        remaining_data_size -= actual_data_size;
        *processed_size += actual_data_size;
    }

    if (remaining_data_size > 0) {
        memcpy(partial_block, data + data_offset, remaining_data_size);
        if (EVP_CipherUpdate(ctx, partial_block, &output_size, partial_block, kBlockSize) != 1) {
            error_exit("Failed to update cipher");
        }
        if (output_size != kBlockSize) {
            fprintf(stderr, "Unexpected output size for last block, expected %zu vs actual %d\n",
                    kBlockSize, output_size);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        memcpy(out_data + data_offset, partial_block, remaining_data_size);
        *processed_size += remaining_data_size;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main() {
    unsigned char key[16];
    memset(key, 0, sizeof(key)); // For demonstration purposes, a zeroed key

    unsigned char iv_high[8], iv_low[8];
    memset(iv_high, 0, 8);
    memset(iv_low, 0, 8);

    uint64_t initial_iv_high = 0, initial_iv_low = 0;
    memcpy(&initial_iv_high, iv_high, sizeof(iv_high));
    memcpy(&initial_iv_low, iv_low, sizeof(iv_low));

    unsigned char data[100] = "0123456789abcdef0123456789abcdef0123456789abcdef";
    size_t data_size = strlen((const char*)data);

    unsigned char encrypted_data[100];
    unsigned char decrypted_data[100];
    size_t processed_size;

    printf("Original data: %s\n", data);

    // Encrypt the data
    if (Cipher(key, initial_iv_high, initial_iv_low, 0, data, encrypted_data, 20, sizeof(encrypted_data), 1, &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    if (Cipher(key, initial_iv_high, initial_iv_low, 20, data + 20, encrypted_data + 20, 20, sizeof(encrypted_data) - 20, 1, &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    if (Cipher(key, initial_iv_high, initial_iv_low, 40, data + 40, encrypted_data + 40, data_size - 40, sizeof(encrypted_data) - 40, 1, &processed_size) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    printf("Encrypted data: ");
    for (size_t i = 0; i < data_size; i++) {
        printf("%02x", encrypted_data[i]);
    }
    printf("\n");

    // Decrypt the data in chunks of 20 bytes
    if (Cipher(key, initial_iv_high, initial_iv_low, 0, encrypted_data, decrypted_data, 20, sizeof(decrypted_data), 0, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    if (Cipher(key, initial_iv_high, initial_iv_low, 20, encrypted_data + 20, decrypted_data + 20, 20, sizeof(decrypted_data) - 20, 0, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    if (Cipher(key, initial_iv_high, initial_iv_low, 40, encrypted_data + 40, decrypted_data + 40, data_size - 40, sizeof(decrypted_data) - 40, 0, &processed_size) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Decrypted data: %s\n", decrypted_data);

    return 0;
}
