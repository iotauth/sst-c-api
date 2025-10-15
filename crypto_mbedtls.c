#ifdef USE_MBEDTLS

#include <errno.h>
#include <stdlib.h>
#include <string.h>

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
    // Set OAEP (PKCS#1 v2.1) with SHA-1 to mirror OpenSSL's
    // RSA_PKCS1_OAEP_PADDING default
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
    // Set OAEP (PKCS#1 v2.1) with SHA-1 to mirror OpenSSL's
    // RSA_PKCS1_OAEP_PADDING default
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
    // Validate inputs
    if (!data || data_length == 0 || !priv_key || !sig_length) {
        errno = EINVAL;
        SST_print_error("mbedtls_sign_sha256 invalid arguments");
        return NULL;
    }

    // Ensure RSA private key
    if (!mbedtls_pk_can_do(priv_key, MBEDTLS_PK_RSA)) {
        SST_print_error("mbedtls_sign_sha256 expects an RSA private key");
        return NULL;
    }

    // Ensure global RNG is ready (used for RSA blinding)
    if (crypto_mbedtls_rng_init_once() != 0) {
        SST_print_error("Global RNG not ready");
        return NULL;
    }

    // Compute SHA-256 digest of the message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int ret = mbedtls_sha256(data, data_length, hash, 0);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to calculate SHA256 hash", ret);
        return NULL;
    }

    // Force PKCS#1 v1.5 signing (RSA-SHA256), to mirror OpenSSL's
    // RSA_PKCS1_PADDING + EVP_sha256()
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*priv_key);
    ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to set RSA PKCS#1 v1.5 padding",
                                      ret);
        return NULL;
    }

    // Allocate signature buffer of modulus size
    size_t key_size = (mbedtls_pk_get_bitlen(priv_key) + 7) / 8;
    unsigned char* sig = (unsigned char*)malloc(key_size);
    if (!sig) {
        SST_print_error("malloc(signature) failed");
        return NULL;
    }

    // Sign precomputed hash with RSA PKCS#1 v1.5 + SHA-256
    size_t out_len = 0;
    ret = mbedtls_pk_sign(priv_key, MBEDTLS_MD_SHA256, hash,
                          0,  // hash length ignored for fixed-size hash
                          sig, key_size, &out_len, mbedtls_ctr_drbg_random,
                          &g_ctr_drbg);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to sign with private key", ret);
        free(sig);
        return NULL;
    }

    *sig_length = out_len;
    return sig;
}

static int mbedtls_verify_sha256(const unsigned char* data,
                                 unsigned int data_length, unsigned char* sig,
                                 size_t sig_length, crypto_pkey_t* pub_key) {
    // Validate inputs
    if (!data || data_length == 0 || !sig || sig_length == 0 || !pub_key) {
        errno = EINVAL;
        SST_print_error("mbedtls_verify_sha256 invalid arguments");
        return -1;
    }

    // Ensure RSA public key
    if (!mbedtls_pk_can_do(pub_key, MBEDTLS_PK_RSA)) {
        SST_print_error("mbedtls_verify_sha256 expects an RSA public key");
        return -1;
    }

    // Compute SHA-256 digest of the message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int ret = mbedtls_sha256(data, data_length, hash, 0);
    if (ret != 0) {
        mbedtls_print_error_with_code(
            "Failed to calculate SHA256 hash for verification", ret);
        return -1;
    }

    // Force PKCS#1 v1.5 verify to mirror OpenSSL's RSA_PKCS1_PADDING +
    // EVP_sha256()
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pub_key);
    ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    if (ret != 0) {
        mbedtls_print_error_with_code(
            "Failed to set RSA PKCS#1 v1.5 padding for verify", ret);
        return -1;
    }

    // Verify signature over SHA-256 hash
    // Note: when md_alg != MBEDTLS_MD_NONE, mbedTLS expects hash_len == 0
    ret =
        mbedtls_pk_verify(pub_key, MBEDTLS_MD_SHA256, hash, 0, sig, sig_length);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to verify signature", ret);
        return -1;
    }

    return 0;
}

static int mbedtls_digest_sha256(const unsigned char* data, size_t data_len,
                                 unsigned char* hash, unsigned int* hash_len) {
    // Validate required output arguments
    if (!hash || !hash_len) {
        errno = EINVAL;
        SST_print_error("mbedtls_digest_sha256 invalid arguments");
        return -1;
    }

    // Compute SHA-256 digest over the input buffer (data may be NULL when
    // data_len==0)
    int ret = mbedtls_sha256(data, data_len, hash, 0);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to compute SHA-256 digest", ret);
        return -1;
    }

    // Set output length to 32 bytes to match OpenSSL's SHA256_DIGEST_LENGTH
    *hash_len = SHA256_DIGEST_LENGTH;
    return 0;
}

static int mbedtls_encrypt_aes(const unsigned char* plaintext,
                               unsigned int plaintext_length,
                               const unsigned char* key,
                               const unsigned char* iv,
                               AES_encryption_mode_t enc_mode,
                               unsigned char* output,
                               unsigned int* ret_length) {
    // Validate basic arguments
    if (!key || !iv || !output || !ret_length) {
        errno = EINVAL;
        SST_print_error("mbedtls_encrypt_aes invalid arguments");
        return -1;
    }

    switch (enc_mode) {
        case AES_128_CBC: {
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CBC)",
                                              result);
                return -1;
            }

            // PKCS#7 padding to a multiple of 16 bytes
            size_t padded_len = ((plaintext_length + 15) / 16) * 16;
            unsigned char* padded_input = (unsigned char*)malloc(padded_len);
            if (!padded_input) {
                mbedtls_aes_free(&aes_ctx);
                SST_print_error("malloc(padded_input) failed");
                return -1;
            }

            memcpy(padded_input, plaintext, plaintext_length);
            unsigned char pad_value =
                (unsigned char)(padded_len - plaintext_length);
            for (size_t i = plaintext_length; i < padded_len; i++) {
                padded_input[i] = pad_value;
            }

            // CBC consumes and mutates IV; use a local copy
            unsigned char iv_copy[AES_128_CBC_IV_SIZE];
            memcpy(iv_copy, iv, AES_128_CBC_IV_SIZE);

            result =
                mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len,
                                      iv_copy, padded_input, output);
            free(padded_input);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to encrypt with AES-CBC",
                                              result);
                return -1;
            }

            *ret_length = (unsigned int)padded_len;
            mbedtls_aes_free(&aes_ctx);
            return 0;
        }

        case AES_128_CTR: {
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CTR)",
                                              result);
                return -1;
            }

            // Use the official CTR helper (avoids manual ECB-keystream loop)
            unsigned char nonce_counter[AES_128_CTR_IV_SIZE];
            unsigned char stream_block[AES_128_CTR_IV_SIZE];
            size_t nc_off = 0;
            memcpy(nonce_counter, iv, AES_128_CTR_IV_SIZE);

            result = mbedtls_aes_crypt_ctr(&aes_ctx, plaintext_length, &nc_off,
                                           nonce_counter, stream_block,
                                           plaintext, output);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to encrypt with AES-CTR",
                                              result);
                return -1;
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
                mbedtls_print_error_with_code("Failed to set AES-128 key (GCM)",
                                              result);
                return -1;
            }

            // Mirror OpenSSL path: IV length = AES_128_GCM_IV_SIZE, tag
            // appended of AES_GCM_TAG_SIZE
            result = mbedtls_gcm_crypt_and_tag(
                &gcm_ctx, MBEDTLS_GCM_ENCRYPT, plaintext_length, iv,
                AES_128_GCM_IV_SIZE,
                /*aad*/ NULL, 0, plaintext, output, AES_GCM_TAG_SIZE,
                output + plaintext_length);
            if (result != 0) {
                mbedtls_gcm_free(&gcm_ctx);
                mbedtls_print_error_with_code("Failed to encrypt with AES-GCM",
                                              result);
                return -1;
            }

            *ret_length = (unsigned int)(plaintext_length + AES_GCM_TAG_SIZE);
            mbedtls_gcm_free(&gcm_ctx);
            return 0;
        }

        default:
            SST_print_error("Invalid encryption mode: %d", enc_mode);
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
    // Validate basic arguments
    if (!key || !iv || !output || !ret_length) {
        errno = EINVAL;
        SST_print_error("mbedtls_decrypt_aes invalid arguments");
        return -1;
    }

    switch (enc_mode) {
        case AES_128_CBC: {
            // Ciphertext length must be a multiple of block size (16)
            if (encrypted_length == 0 ||
                (encrypted_length % AES_128_CBC_IV_SIZE) != 0) {
                SST_print_error(
                    "AES-CBC ciphertext length is not a multiple of 16");
                return -1;
            }

            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int result = mbedtls_aes_setkey_dec(&aes_ctx, key, 128);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CBC)",
                                              result);
                return -1;
            }

            // CBC consumes and mutates IV; use a local copy
            unsigned char iv_copy[AES_128_CBC_IV_SIZE];
            memcpy(iv_copy, iv, AES_128_CBC_IV_SIZE);

            result = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT,
                                           encrypted_length, iv_copy, encrypted,
                                           output);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to decrypt with AES-CBC",
                                              result);
                return -1;
            }

            // Validate and remove PKCS#7 padding
            unsigned char pad_value = output[encrypted_length - 1];
            if (pad_value == 0 || pad_value > AES_128_CBC_IV_SIZE) {
                mbedtls_aes_free(&aes_ctx);
                SST_print_error("Invalid PKCS#7 padding value");
                return -1;
            }
            for (size_t i = 0; i < pad_value; ++i) {
                if (output[encrypted_length - 1 - i] != pad_value) {
                    mbedtls_aes_free(&aes_ctx);
                    SST_print_error("PKCS#7 padding bytes mismatch");
                    return -1;
                }
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
                mbedtls_print_error_with_code("Failed to set AES-128 key (CTR)",
                                              result);
                return -1;
            }

            unsigned char nonce_counter[AES_128_CTR_IV_SIZE];
            unsigned char stream_block[AES_128_CTR_IV_SIZE];
            size_t nc_off = 0;
            memcpy(nonce_counter, iv, AES_128_CTR_IV_SIZE);

            result = mbedtls_aes_crypt_ctr(&aes_ctx, encrypted_length, &nc_off,
                                           nonce_counter, stream_block,
                                           encrypted, output);
            if (result != 0) {
                mbedtls_aes_free(&aes_ctx);
                mbedtls_print_error_with_code("Failed to decrypt with AES-CTR",
                                              result);
                return -1;
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
                mbedtls_print_error_with_code("Failed to set AES-128 key (GCM)",
                                              result);
                return -1;
            }

            if (encrypted_length < AES_GCM_TAG_SIZE) {
                mbedtls_gcm_free(&gcm_ctx);
                SST_print_error("AES-GCM ciphertext too short");
                return -1;
            }

            unsigned char* tag =
                (unsigned char*)encrypted + encrypted_length - AES_GCM_TAG_SIZE;
            unsigned char* ciphertext = (unsigned char*)encrypted;
            size_t ciphertext_len = encrypted_length - AES_GCM_TAG_SIZE;

            result = mbedtls_gcm_auth_decrypt(
                &gcm_ctx, ciphertext_len, iv, AES_128_GCM_IV_SIZE,
                /*aad*/ NULL, 0, tag, AES_GCM_TAG_SIZE, ciphertext, output);
            if (result != 0) {
                mbedtls_gcm_free(&gcm_ctx);
                mbedtls_print_error_with_code("Failed to decrypt with AES-GCM",
                                              result);
                return -1;
            }

            *ret_length = (unsigned int)ciphertext_len;
            mbedtls_gcm_free(&gcm_ctx);
            return 0;
        }

        default:
            SST_print_error("Invalid encryption mode: %d", enc_mode);
            return -1;
    }
}

static int mbedtls_generate_random(unsigned char* buf, int length) {
    // Validate arguments
    if (!buf || length <= 0) {
        errno = EINVAL;
        SST_print_error("mbedtls_generate_random invalid arguments");
        return -1;
    }

    // Ensure global DRBG is initialized once (reuse across calls)
    if (crypto_mbedtls_rng_init_once() != 0) {
        SST_print_error("Global RNG not ready");
        return -1;
    }

    // Generate cryptographically secure random bytes
    int ret = mbedtls_ctr_drbg_random(&g_ctr_drbg, buf, (size_t)length);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to generate random bytes", ret);
        return -1;
    }

    return 0;
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
    // Validate arguments
    if (!key || key_len == 0 || (!data && data_len != 0) || !output ||
        !output_len) {
        errno = EINVAL;
        SST_print_error("mbedtls_hmac_sha256 invalid arguments");
        return -1;
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t* md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        mbedtls_md_free(&ctx);
        SST_print_error("mbedtls_hmac_sha256 failed to get md info");
        return -1;
    }

    int ret = mbedtls_md_setup(&ctx, md_info, 1 /* HMAC enable */);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        mbedtls_print_error_with_code("mbedtls_md_setup failed", ret);
        return -1;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        mbedtls_print_error_with_code("mbedtls_md_hmac_starts failed", ret);
        return -1;
    }

    ret = mbedtls_md_hmac_update(&ctx, data, data_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        mbedtls_print_error_with_code("mbedtls_md_hmac_update failed", ret);
        return -1;
    }

    ret = mbedtls_md_hmac_finish(&ctx, output);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        mbedtls_print_error_with_code("mbedtls_md_hmac_finish failed", ret);
        return -1;
    }

    *output_len = SHA256_DIGEST_LENGTH;  // SHA-256 HMAC length in bytes
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
