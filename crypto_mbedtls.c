#ifdef USE_MBEDTLS

#include <stdlib.h>
#include <string.h>
#include <errno.h>  

#include "c_api.h"
#include "c_common.h"
#include "c_crypto.h"
#include "crypto_backend.h"

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static int g_rng_ready = 0;

// mbed TLS implementation of crypto backend

static void mbedtls_print_error(const char* msg) {
    SST_print_error("%s ERROR: mbed TLS crypto error", msg);
}

static void mbedtls_print_error_with_code(const char* msg, int error_code) {
    char error_buf[256];
    mbedtls_strerror(error_code, error_buf, sizeof(error_buf));
    SST_print_error("%s ERROR: %s (code: 0x%x)", msg, error_buf, error_code);
}

static crypto_pkey_t* mbedtls_load_public_key(const char* path) {
    mbedtls_pk_context* pk = malloc(sizeof(mbedtls_pk_context));
    if (!pk) {
        SST_print_error("malloc(mbedtls_pk_context) failed");
        return NULL;
    }
    mbedtls_pk_init(pk);

    // Parse as X.509 certificate instead of a plain public key
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_file(&crt, path);
    if (ret != 0) {
        mbedtls_print_error_with_code(
            "Failed to parse certificate (public key)", ret);
        mbedtls_x509_crt_free(&crt);
        free(pk);
        return NULL;
    }

    // Move the public key from certificate to our pk context
    *pk = crt.pk;
    memset(&crt.pk, 0, sizeof(crt.pk));  // Prevent double-free on crt
    mbedtls_x509_crt_free(&crt);

    return pk;
}

static crypto_pkey_t* mbedtls_load_private_key(const char* path) {
    mbedtls_pk_context* pk = malloc(sizeof(mbedtls_pk_context));
    if (!pk) {
        return NULL;
    }

    mbedtls_pk_init(pk);

    int ret = mbedtls_pk_parse_keyfile(pk, path, NULL, NULL, NULL);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to parse private key file", ret);
        mbedtls_pk_free(pk);
        free(pk);
        return NULL;
    }

    return pk;
}

static void mbedtls_free_pkey(crypto_pkey_t* pkey) {
    if (pkey) {
        mbedtls_pk_free(pkey);
        free(pkey);
    }
}

static int crypto_mbedtls_rng_init_once(void) {
    if (g_rng_ready) return 0;

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    const char* pers = "crypto_mbedtls_rng";
    int ret =
        mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                              (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to seed global CTR-DRBG", ret);
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
        return ret;
    }

    g_rng_ready = 1;
    return 0;
}

static unsigned char* mbedtls_public_encrypt(
    const unsigned char* data, size_t data_len,
    int padding,  // always RSA_PKCS1_OAEP_PADDING
    crypto_pkey_t* pub_key, size_t* ret_len) {
    if (!data || data_len == 0 || !pub_key || !ret_len) {
        errno = EINVAL;
        SST_print_error("mbedtls_public_encrypt invalid arguments");
        return NULL;
    }
    if (!mbedtls_pk_can_do(pub_key, MBEDTLS_PK_RSA)) {
        SST_print_error("mbedtls_public_encrypt expects an RSA public key");
        return NULL;
    }

    // 1) Initialize global RNG once (no per-call seeding)
    int ret = crypto_mbedtls_rng_init_once();
    if (ret != 0) {
        SST_print_error("Global RNG not ready");
        return NULL;
    }

    // 2) Force OAEP padding (OpenSSL compatibility)
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pub_key);
     // Set OAEP (PKCS#1 v2.1) with SHA-1 to mirror OpenSSL's RSA_PKCS1_OAEP_PADDING default
    ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to set RSA OAEP padding", ret);
        return NULL;
    }

    // 3) Allocate ciphertext buffer of modulus size
    const size_t key_size = (mbedtls_pk_get_bitlen(pub_key) + 7) / 8;
    unsigned char* out = (unsigned char*)malloc(key_size);
    if (!out) {
        SST_print_error("malloc(ciphertext) failed");
        return NULL;
    }

    // 4) Encrypt (OAEP uses RNG internally)
    size_t out_len = 0;
    ret = mbedtls_pk_encrypt(pub_key, data, data_len, out, &out_len, key_size,
                             mbedtls_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to encrypt with public key", ret);
        free(out);
        return NULL;
    }

    *ret_len = out_len;  // equals key_size for RSA
    return out;
}

static unsigned char* mbedtls_private_decrypt(
    const unsigned char* enc_data, size_t enc_data_len,
    int padding,  // always RSA_PKCS1_OAEP_PADDING
    crypto_pkey_t* priv_key, size_t* ret_len) {
    // Validate arguments
    if (!enc_data || enc_data_len == 0 || !priv_key || !ret_len) {
        errno = EINVAL;
        SST_print_error("mbedtls_private_decrypt invalid arguments");
        return NULL;
    }

    // Ensure RSA private key
    if (!mbedtls_pk_can_do(priv_key, MBEDTLS_PK_RSA)) {
        SST_print_error("mbedtls_private_decrypt expects an RSA private key");
        return NULL;
    }

    // Initialize global RNG once (used for RSA blinding in private ops)
    int ret = crypto_mbedtls_rng_init_once();
    if (ret != 0) {
        SST_print_error("Global RNG not ready");
        return NULL;
    }

    // Force OAEP padding (to mirror OpenSSL's RSA_PKCS1_OAEP_PADDING)
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*priv_key);
     // Set OAEP (PKCS#1 v2.1) with SHA-1 to mirror OpenSSL's RSA_PKCS1_OAEP_PADDING default
    ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to set RSA OAEP padding", ret);
        return NULL;
    }

    // Allocate output buffer: maximum possible plaintext size is key_size
    const size_t key_size = (mbedtls_pk_get_bitlen(priv_key) + 7) / 8;
    unsigned char* out = (unsigned char*)malloc(key_size);
    if (!out) {
        SST_print_error("malloc(plaintext) failed");
        return NULL;
    }

    // Decrypt (RSA private op may use RNG for blinding → pass DRBG)
    size_t out_len = 0;
    ret = mbedtls_pk_decrypt(priv_key, enc_data, enc_data_len, out, &out_len,
                             key_size, mbedtls_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to decrypt with private key",
                                      ret);
        free(out);
        return NULL;
    }

    // Optionally shrink to fit:
    // unsigned char* shrunk = realloc(out, out_len);
    // if (shrunk) out = shrunk;

    *ret_len = out_len;
    return out;
}

static unsigned char* mbedtls_sign_sha256(const unsigned char* data,
                                          unsigned int data_length,
                                          crypto_pkey_t* priv_key,
                                          size_t* sig_length) {
    unsigned char hash[32];
    size_t hash_len = 32;

    // Calculate SHA256 hash
    int ret = mbedtls_sha256(data, data_length, hash, 0);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to calculate SHA256 hash", ret);
        return NULL;
    }

    size_t key_size = (mbedtls_pk_get_bitlen(priv_key) + 7) / 8;
    unsigned char* sig = malloc(key_size);
    if (!sig) {
        return NULL;
    }

    ret = mbedtls_pk_sign(priv_key, MBEDTLS_MD_SHA256, hash, hash_len, sig,
                          key_size, sig_length, mbedtls_ctr_drbg_random, NULL);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to sign with private key", ret);
        free(sig);
        return NULL;
    }

    return sig;
}

static int mbedtls_verify_sha256(const unsigned char* data,
                                 unsigned int data_length, unsigned char* sig,
                                 size_t sig_length, crypto_pkey_t* pub_key) {
    unsigned char hash[32];

    // Calculate SHA256 hash
    int ret = mbedtls_sha256(data, data_length, hash, 0);
    if (ret != 0) {
        mbedtls_print_error_with_code(
            "Failed to calculate SHA256 hash for verification", ret);
        return -1;
    }

    ret = mbedtls_pk_verify(pub_key, MBEDTLS_MD_SHA256, hash, 32, sig,
                            sig_length);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to verify signature", ret);
    }
    return (ret == 0) ? 0 : -1;
}

static int mbedtls_digest_sha256(const unsigned char* data, size_t data_len,
                                 unsigned char* hash, unsigned int* hash_len) {
    int ret = mbedtls_sha256(data, data_len, hash, 0);
    if (ret == 0) {
        *hash_len = 32;
    }
    return ret;
}

static int mbedtls_encrypt_aes(const unsigned char* plaintext,
                               unsigned int plaintext_length,
                               const unsigned char* key,
                               const unsigned char* iv,
                               AES_encryption_mode_t enc_mode,
                               unsigned char* output,
                               unsigned int* ret_length) {
    switch (enc_mode) {
        case AES_128_CBC: {
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            // For CBC, we need to pad the input to a multiple of 16 bytes
            size_t padded_len = ((plaintext_length + 15) / 16) * 16;
            unsigned char* padded_input = malloc(padded_len);
            if (!padded_input) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            memcpy(padded_input, plaintext, plaintext_length);
            // PKCS7 padding
            unsigned char pad_value = padded_len - plaintext_length;
            for (size_t i = plaintext_length; i < padded_len; i++) {
                padded_input[i] = pad_value;
            }

            // Copy IV to a mutable buffer
            unsigned char iv_copy[16];
            memcpy(iv_copy, iv, 16);

            result =
                mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len,
                                      iv_copy, padded_input, output);
            if (result != 0) {
                mbedtls_print_error_with_code("Failed to encrypt with AES-CBC",
                                              result);
                free(padded_input);
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            *ret_length = padded_len;
            free(padded_input);
            mbedtls_aes_free(&aes_ctx);
            return 0;
        }

        case AES_128_CTR: {
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            // For CTR, we need to implement the counter mode manually
            unsigned char counter[16];
            memcpy(counter, iv, 16);

            size_t blocks = (plaintext_length + 15) / 16;
            for (size_t i = 0; i < blocks; i++) {
                unsigned char keystream[16];
                result = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                               counter, keystream);
                if (result != 0) {
                    mbedtls_aes_free(&aes_ctx);
                    return -1;
                }

                size_t block_len =
                    (i == blocks - 1) ? (plaintext_length - i * 16) : 16;
                for (size_t j = 0; j < block_len; j++) {
                    output[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
                }

                // Increment counter
                for (int j = 15; j >= 0; j--) {
                    if (++counter[j] != 0) break;
                }
            }

            *ret_length = plaintext_length;
            mbedtls_aes_free(&aes_ctx);
            return 0;
        }

        case AES_128_GCM: {
            mbedtls_gcm_context gcm_ctx;
            mbedtls_gcm_init(&gcm_ctx);

            int result =
                mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
            if (result != 0) {
                mbedtls_gcm_free(&gcm_ctx);
                return -1;
            }

            // Use only the first 12 bytes of the IV for GCM
            result = mbedtls_gcm_crypt_and_tag(
                &gcm_ctx, MBEDTLS_GCM_ENCRYPT, plaintext_length, iv, 12, NULL,
                0, plaintext, output, 12, output + plaintext_length);
            if (result != 0) {
                mbedtls_print_error_with_code("Failed to encrypt with AES-GCM",
                                              result);
                mbedtls_gcm_free(&gcm_ctx);
                return -1;
            }

            *ret_length = plaintext_length + 12;  // plaintext + tag
            mbedtls_gcm_free(&gcm_ctx);
            return 0;
        }

        default:
            SST_print_debug("Invalid encryption mode: %d", enc_mode);
            return -1;
    }
}

static int mbedtls_decrypt_aes(const unsigned char* encrypted,
                               unsigned int encrypted_length,
                               const unsigned char* key,
                               const unsigned char* iv,
                               AES_encryption_mode_t enc_mode,
                               unsigned char* output,
                               unsigned int* ret_length) {
    switch (enc_mode) {
        case AES_128_CBC: {
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_dec(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            // Copy IV to a mutable buffer
            unsigned char iv_copy[16];
            memcpy(iv_copy, iv, 16);

            result = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT,
                                           encrypted_length, iv_copy, encrypted,
                                           output);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            // Remove PKCS7 padding
            unsigned char pad_value = output[encrypted_length - 1];
            if (pad_value > 16 || pad_value == 0) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            *ret_length = encrypted_length - pad_value;
            mbedtls_aes_free(&aes_ctx);
            return 0;
        }

        case AES_128_CTR: {
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                return -1;
            }

            // For CTR, decryption is the same as encryption
            unsigned char counter[16];
            memcpy(counter, iv, 16);

            size_t blocks = (encrypted_length + 15) / 16;
            for (size_t i = 0; i < blocks; i++) {
                unsigned char keystream[16];
                result = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                               counter, keystream);
                if (result != 0) {
                    mbedtls_aes_free(&aes_ctx);
                    return -1;
                }

                size_t block_len =
                    (i == blocks - 1) ? (encrypted_length - i * 16) : 16;
                for (size_t j = 0; j < block_len; j++) {
                    output[i * 16 + j] = encrypted[i * 16 + j] ^ keystream[j];
                }

                // Increment counter
                for (int j = 15; j >= 0; j--) {
                    if (++counter[j] != 0) break;
                }
            }

            *ret_length = encrypted_length;
            mbedtls_aes_free(&aes_ctx);
            return 0;
        }

        case AES_128_GCM: {
            mbedtls_gcm_context gcm_ctx;
            mbedtls_gcm_init(&gcm_ctx);

            int result =
                mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
            if (result != 0) {
                mbedtls_gcm_free(&gcm_ctx);
                return -1;
            }

            // Extract tag from the end of encrypted data
            unsigned char* tag =
                (unsigned char*)encrypted + encrypted_length - 12;
            unsigned char* ciphertext = (unsigned char*)encrypted;
            size_t ciphertext_len = encrypted_length - 12;

            // Use only the first 12 bytes of the IV for GCM
            result =
                mbedtls_gcm_auth_decrypt(&gcm_ctx, ciphertext_len, iv, 12, NULL,
                                         0, tag, 12, ciphertext, output);
            if (result != 0) {
                mbedtls_gcm_free(&gcm_ctx);
                return -1;
            }

            *ret_length = ciphertext_len;
            mbedtls_gcm_free(&gcm_ctx);
            return 0;
        }

        default:
            SST_print_debug("Invalid encryption mode: %d", enc_mode);
            return -1;
    }
}

static int mbedtls_generate_random(unsigned char* buf, int length) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return -1;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, length);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret == 0) ? 0 : -1;
}

static void mbedtls_free_memory(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

static void* mbedtls_malloc_memory(size_t size) { return malloc(size); }

static int mbedtls_hmac_sha256(const unsigned char* key, size_t key_len,
                               const unsigned char* data, size_t data_len,
                               unsigned char* output,
                               unsigned int* output_len) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int ret =
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    ret = mbedtls_md_hmac_update(&ctx, data, data_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    ret = mbedtls_md_hmac_finish(&ctx, output);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return -1;
    }

    *output_len = 32;  // SHA256 output length
    mbedtls_md_free(&ctx);
    return 0;
}

// mbed TLS crypto backend implementation
static const crypto_backend_t mbedtls_backend = {
    .load_public_key = mbedtls_load_public_key,
    .load_private_key = mbedtls_load_private_key,
    .free_pkey = mbedtls_free_pkey,
    .print_error = mbedtls_print_error,
    .public_encrypt = mbedtls_public_encrypt,
    .private_decrypt = mbedtls_private_decrypt,
    .sign_sha256 = mbedtls_sign_sha256,
    .verify_sha256 = mbedtls_verify_sha256,
    .digest_sha256 = mbedtls_digest_sha256,
    .encrypt_aes = mbedtls_encrypt_aes,
    .decrypt_aes = mbedtls_decrypt_aes,
    .generate_random = mbedtls_generate_random,
    .free_memory = mbedtls_free_memory,
    .malloc_memory = mbedtls_malloc_memory,
    .hmac_sha256 = mbedtls_hmac_sha256};

const crypto_backend_t* get_crypto_backend(void) { return &mbedtls_backend; }

// int init_crypto_backend(void) {
//     // mbed TLS initialization is typically done automatically
//     return 0;
// }

// void cleanup_crypto_backend(void) {
//     // mbed TLS cleanup is typically done automatically
// }

#endif  // USE_MBEDTLS
