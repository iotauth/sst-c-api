#include <stddef.h>
#include <stdio.h>

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

// Extract a PEM block between given BEGIN/END markers from an in-memory text
// blob. On success, returns 0 and sets *pem_start/*pem_len to point inside
// `text`.
static int find_pem_block(const char* text, const char* begin_marker,
                          const char* end_marker,
                          const unsigned char** pem_start, size_t* pem_len) {
    if (!text || !begin_marker || !end_marker || !pem_start || !pem_len)
        return -1;
    const char* begin = strstr(text, begin_marker);
    if (!begin) return -1;
    const char* end = strstr(begin, end_marker);
    if (!end) return -1;
    end += strlen(end_marker);  // include END line
    *pem_start = (const unsigned char*)begin;
    *pem_len = (size_t)(end - begin);

    SST_print_debug("[find_pem_block] begin offset: %ld", (long)(begin - text));
    SST_print_debug("[find_pem_block] end offset:   %ld", (long)(end - text));
    SST_print_debug("[find_pem_block] pem_len:      %zu", *pem_len);


    SST_print_debug("[find_pem_block] PEM full:\n%.*s", (int)*pem_len,
                    (const char*)*pem_start);

    return 0;
}

static crypto_pkey_t* mbedtls_load_public_key(const char* config_blob) {
    // Treat the input string as an in-memory configuration blob that contains a
    // PEM certificate
    const unsigned char* pem = NULL;
    size_t pem_len = 0;
    if (find_pem_block(config_blob, "-----BEGIN CERTIFICATE-----",
                       "-----END CERTIFICATE-----", &pem, &pem_len) != 0) {
        SST_print_error("Public cert PEM not found in provided config text");
        return NULL;
    }

    unsigned char* pem_buf = malloc(pem_len + 1);
    if (!pem_buf) {
        SST_print_error("malloc(pem_buf) failed");
        return NULL;
    }
    memcpy(pem_buf, pem, pem_len);
    pem_buf[pem_len] = '\0';

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    int ret = mbedtls_x509_crt_parse(&crt, pem_buf, pem_len + 1);
    free(pem_buf);

    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to parse in-memory certificate",
                                      ret);
        mbedtls_x509_crt_free(&crt);
        return NULL;
    }

    mbedtls_pk_context* pk = malloc(sizeof(mbedtls_pk_context));
    if (!pk) {
        mbedtls_x509_crt_free(&crt);
        SST_print_error("malloc(mbedtls_pk_context) failed");
        return NULL;
    }
    mbedtls_pk_init(pk);

    // Move (copy) the public key from the certificate into our own context
    *pk = crt.pk;                        // struct copy
    memset(&crt.pk, 0, sizeof(crt.pk));  // avoid double-free
    mbedtls_x509_crt_free(&crt);

    return pk;
}

static crypto_pkey_t* mbedtls_load_private_key(const char* config_blob) {
    // Treat the input string as an in-memory configuration blob that contains a
    // PEM private key
    const unsigned char* pem = NULL;
    size_t pem_len = 0;
    if (find_pem_block(config_blob, "-----BEGIN PRIVATE KEY-----",
                       "-----END PRIVATE KEY-----", &pem, &pem_len) != 0) {
        SST_print_error("Private key PEM not found in provided config text");
        return NULL;
    }

    unsigned char* pem_buf = malloc(pem_len + 1);
    if (!pem_buf) {
        SST_print_error("malloc(pem_buf) failed");
        return NULL;
    }
    memcpy(pem_buf, pem, pem_len);
    pem_buf[pem_len] = '\0';

    mbedtls_pk_context* pk = malloc(sizeof(mbedtls_pk_context));
    if (!pk) {
        SST_print_error("malloc(mbedtls_pk_context) failed");
        return NULL;
    }
    mbedtls_pk_init(pk);

    // If your key is password-protected, pass the password bytes and length
    // below instead of NULLs.
    int ret =
        mbedtls_pk_parse_key(pk, pem_buf, pem_len + 1, NULL, 0,  // no password
                             mbedtls_ctr_drbg_random, &g_ctr_drbg);
    free(pem_buf);
    if (ret != 0) {
        mbedtls_print_error_with_code("Failed to parse in-memory private key",
                                      ret);
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

static unsigned char* mbedtls_public_encrypt(const unsigned char* data,
                                             size_t data_len,
                                             crypto_pkey_t* pub_key,
                                             size_t* ret_len) {
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

static unsigned char* mbedtls_private_decrypt(const unsigned char* enc_data,
                                              size_t enc_data_len,
                                              crypto_pkey_t* priv_key,
                                              size_t* ret_len) {
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

    int ret = 0;

    switch (enc_mode) {
        case AES_128_CBC: {
            mbedtls_cipher_context_t c;
            mbedtls_cipher_init(&c);

            const mbedtls_cipher_info_t* info =
                mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
            if (!info) {
                mbedtls_cipher_free(&c);
                SST_print_error("Failed to get cipher info (AES-128-CBC)");
                return -1;
            }

            if ((ret = mbedtls_cipher_setup(&c, info)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_setup failed",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_setkey(&c, key, 128, MBEDTLS_ENCRYPT)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CBC)",
                                              ret);
                return -1;
            }

            // Match OpenSSL default: PKCS#7 padding
            if ((ret = mbedtls_cipher_set_padding_mode(
                     &c, MBEDTLS_PADDING_PKCS7)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set PKCS#7 padding",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_set_iv(&c, iv, AES_128_CBC_IV_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set IV (CBC)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_reset(&c)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_reset failed",
                                              ret);
                return -1;
            }

            size_t out_len = 0, finish_len = 0;
            if ((ret = mbedtls_cipher_update(&c, plaintext, plaintext_length,
                                             output, &out_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_update failed (CBC)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_finish(&c, output + out_len,
                                             &finish_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_finish failed (CBC)", ret);
                return -1;
            }

            *ret_length = (unsigned int)(out_len + finish_len);
            mbedtls_cipher_free(&c);
            return 0;
        }

        case AES_128_CTR: {
            mbedtls_cipher_context_t c;
            mbedtls_cipher_init(&c);

            const mbedtls_cipher_info_t* info =
                mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
            if (!info) {
                mbedtls_cipher_free(&c);
                SST_print_error("Failed to get cipher info (AES-128-CTR)");
                return -1;
            }

            if ((ret = mbedtls_cipher_setup(&c, info)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_setup failed",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_setkey(&c, key, 128, MBEDTLS_ENCRYPT)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CTR)",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_set_iv(&c, iv, AES_128_CTR_IV_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set IV (CTR)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_reset(&c)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_reset failed",
                                              ret);
                return -1;
            }

            size_t out_len = 0, finish_len = 0;
            if ((ret = mbedtls_cipher_update(&c, plaintext, plaintext_length,
                                             output, &out_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_update failed (CTR)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_finish(&c, output + out_len,
                                             &finish_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_finish failed (CTR)", ret);
                return -1;
            }

            *ret_length =
                (unsigned int)(out_len +
                               finish_len);  // finish_len is expected 0 for CTR
            mbedtls_cipher_free(&c);
            return 0;
        }

        case AES_128_GCM: {
            mbedtls_cipher_context_t c;
            mbedtls_cipher_init(&c);

            const mbedtls_cipher_info_t* info =
                mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
            if (!info) {
                mbedtls_cipher_free(&c);
                SST_print_error("Failed to get cipher info (AES-128-GCM)");
                return -1;
            }

            if ((ret = mbedtls_cipher_setup(&c, info)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_setup failed",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_setkey(&c, key, 128, MBEDTLS_ENCRYPT)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set AES-128 key (GCM)",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_set_iv(&c, iv, AES_128_GCM_IV_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set IV (GCM)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_reset(&c)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_reset failed",
                                              ret);
                return -1;
            }

            size_t out_len = 0, finish_len = 0;
            if ((ret = mbedtls_cipher_update(&c, plaintext, plaintext_length,
                                             output, &out_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_update failed (GCM)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_finish(&c, output + out_len,
                                             &finish_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_finish failed (GCM)", ret);
                return -1;
            }

            unsigned char tag[AES_GCM_TAG_SIZE];
            if ((ret = mbedtls_cipher_write_tag(&c, tag, AES_GCM_TAG_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_write_tag failed (GCM)", ret);
                return -1;
            }

            memcpy(output + out_len + finish_len, tag, AES_GCM_TAG_SIZE);
            *ret_length =
                (unsigned int)(out_len + finish_len + AES_GCM_TAG_SIZE);

            mbedtls_cipher_free(&c);
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

    int ret = 0;

    switch (enc_mode) {
        case AES_128_CBC: {
            if (encrypted_length == 0 ||
                (encrypted_length % AES_128_CBC_IV_SIZE) != 0) {
                SST_print_error(
                    "AES-CBC ciphertext length is not a multiple of 16");
                return -1;
            }

            mbedtls_cipher_context_t c;
            mbedtls_cipher_init(&c);

            const mbedtls_cipher_info_t* info =
                mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
            if (!info) {
                mbedtls_cipher_free(&c);
                SST_print_error("Failed to get cipher info (AES-128-CBC)");
                return -1;
            }

            if ((ret = mbedtls_cipher_setup(&c, info)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_setup failed",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_setkey(&c, key, 128, MBEDTLS_DECRYPT)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CBC)",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_set_padding_mode(
                     &c, MBEDTLS_PADDING_PKCS7)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set PKCS#7 padding",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_set_iv(&c, iv, AES_128_CBC_IV_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set IV (CBC)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_reset(&c)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_reset failed",
                                              ret);
                return -1;
            }

            size_t out_len = 0, finish_len = 0;
            if ((ret = mbedtls_cipher_update(&c, encrypted, encrypted_length,
                                             output, &out_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_update failed (CBC)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_finish(&c, output + out_len,
                                             &finish_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_finish failed (CBC)", ret);
                return -1;
            }

            *ret_length = (unsigned int)(out_len + finish_len);
            mbedtls_cipher_free(&c);
            return 0;
        }

        case AES_128_CTR: {
            mbedtls_cipher_context_t c;
            mbedtls_cipher_init(&c);

            const mbedtls_cipher_info_t* info =
                mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
            if (!info) {
                mbedtls_cipher_free(&c);
                SST_print_error("Failed to get cipher info (AES-128-CTR)");
                return -1;
            }

            if ((ret = mbedtls_cipher_setup(&c, info)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_setup failed",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_setkey(&c, key, 128, MBEDTLS_DECRYPT)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set AES-128 key (CTR)",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_set_iv(&c, iv, AES_128_CTR_IV_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set IV (CTR)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_reset(&c)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_reset failed",
                                              ret);
                return -1;
            }

            size_t out_len = 0, finish_len = 0;
            if ((ret = mbedtls_cipher_update(&c, encrypted, encrypted_length,
                                             output, &out_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_update failed (CTR)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_finish(&c, output + out_len,
                                             &finish_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_finish failed (CTR)", ret);
                return -1;
            }

            *ret_length =
                (unsigned int)(out_len + finish_len);  // finish_len expected 0
            mbedtls_cipher_free(&c);
            return 0;
        }

        case AES_128_GCM: {
            if (encrypted_length < AES_GCM_TAG_SIZE) {
                SST_print_error("AES-GCM ciphertext too short");
                return -1;
            }

            mbedtls_cipher_context_t c;
            mbedtls_cipher_init(&c);

            const mbedtls_cipher_info_t* info =
                mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
            if (!info) {
                mbedtls_cipher_free(&c);
                SST_print_error("Failed to get cipher info (AES-128-GCM)");
                return -1;
            }

            if ((ret = mbedtls_cipher_setup(&c, info)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_setup failed",
                                              ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_setkey(&c, key, 128, MBEDTLS_DECRYPT)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set AES-128 key (GCM)",
                                              ret);
                return -1;
            }

            const unsigned char* tag =
                encrypted + encrypted_length - AES_GCM_TAG_SIZE;
            const unsigned char* ciphertext = encrypted;
            size_t ciphertext_len = encrypted_length - AES_GCM_TAG_SIZE;

            if ((ret = mbedtls_cipher_set_iv(&c, iv, AES_128_GCM_IV_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("Failed to set IV (GCM)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_reset(&c)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code("mbedtls_cipher_reset failed",
                                              ret);
                return -1;
            }

            size_t out_len = 0, finish_len = 0;
            if ((ret = mbedtls_cipher_update(&c, ciphertext, ciphertext_len,
                                             output, &out_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_update failed (GCM)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_finish(&c, output + out_len,
                                             &finish_len)) != 0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_finish failed (GCM)", ret);
                return -1;
            }

            if ((ret = mbedtls_cipher_check_tag(&c, tag, AES_GCM_TAG_SIZE)) !=
                0) {
                mbedtls_cipher_free(&c);
                mbedtls_print_error_with_code(
                    "mbedtls_cipher_check_tag failed (GCM)", ret);
                return -1;
            }

            *ret_length = (unsigned int)(out_len + finish_len);
            mbedtls_cipher_free(&c);
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
    .hmac_sha256 = mbedtls_hmac_sha256};

const crypto_backend_t* get_crypto_backend(void) { return &mbedtls_backend; }

#endif  // USE_MBEDTLS
