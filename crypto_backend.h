#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include "c_api.h"

// Forward declarations for crypto backend types
#ifdef USE_OPENSSL
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

typedef EVP_PKEY crypto_pkey_t;
typedef EVP_MD_CTX crypto_md_ctx_t;
typedef EVP_CIPHER_CTX crypto_cipher_ctx_t;
typedef const EVP_CIPHER crypto_cipher_t;
typedef const EVP_MD crypto_md_t;

#elif defined(USE_MBEDTLS)
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

typedef mbedtls_pk_context crypto_pkey_t;
typedef mbedtls_md_context_t crypto_md_ctx_t;
typedef mbedtls_cipher_context_t crypto_cipher_ctx_t;
typedef mbedtls_cipher_type_t crypto_cipher_t;
typedef mbedtls_md_type_t crypto_md_t;

#endif

// Common crypto backend interface
typedef struct {
    crypto_pkey_t* (*load_public_key)(const char* path);
    crypto_pkey_t* (*load_private_key)(const char* path);
    void (*free_pkey)(crypto_pkey_t* pkey);
    // Backend-specific error printer
    void (*print_error)(const char* msg);

    unsigned char* (*public_encrypt)(const unsigned char* data, size_t data_len,
                                     crypto_pkey_t* pub_key, size_t* ret_len);
    unsigned char* (*private_decrypt)(const unsigned char* enc_data,
                                      size_t enc_data_len,
                                      crypto_pkey_t* priv_key, size_t* ret_len);

    unsigned char* (*sign_sha256)(const unsigned char* data,
                                  unsigned int data_length,
                                  crypto_pkey_t* priv_key, size_t* sig_length);
    int (*verify_sha256)(const unsigned char* data, unsigned int data_length,
                         unsigned char* sig, size_t sig_length,
                         crypto_pkey_t* pub_key);

    int (*digest_sha256)(const unsigned char* data, size_t data_len,
                         unsigned char* hash, unsigned int* hash_len);

    int (*encrypt_aes)(const unsigned char* plaintext,
                       unsigned int plaintext_length, const unsigned char* key,
                       const unsigned char* iv, AES_encryption_mode_t enc_mode,
                       unsigned char* ret, unsigned int* ret_length);
    int (*decrypt_aes)(const unsigned char* encrypted,
                       unsigned int encrypted_length, const unsigned char* key,
                       const unsigned char* iv, AES_encryption_mode_t enc_mode,
                       unsigned char* ret, unsigned int* ret_length);

    int (*generate_random)(unsigned char* buf, int length);
    void (*free_memory)(void* ptr);
    void* (*malloc_memory)(size_t size);

    // HMAC functions
    int (*hmac_sha256)(const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       unsigned char* output, unsigned int* output_len);
} crypto_backend_t;

// Get the appropriate crypto backend
const crypto_backend_t* get_crypto_backend(void);

// TODO: Clean up.
//  // Initialize crypto backend
//  int init_crypto_backend(void);

// // Cleanup crypto backend
// void cleanup_crypto_backend(void);

#endif  // CRYPTO_BACKEND_H
