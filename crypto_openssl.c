#ifdef USE_OPENSSL

#include "c_api.h"
#include "c_common.h"
#include "c_crypto.h"
#include "crypto_backend.h"

// OpenSSL implementation of crypto backend

static void openssl_print_error(const char* msg) {
    unsigned long error_code = ERR_get_error();
    if (error_code != 0) {
        char err[MAX_ERROR_MESSAGE_LENGTH];
        ERR_load_crypto_strings();
        ERR_error_string(error_code, err);
        SST_print_error("%s ERROR: %s (code: 0x%lx)", msg, err, error_code);
    } else {
        SST_print_error("%s ERROR: Unknown OpenSSL error", msg);
    }
}

static crypto_pkey_t* openssl_load_public_key(const char* path) {
    FILE* pemFile = fopen(path, "rb");
    if (pemFile == NULL) {
        SST_print_error("Failed to open public key file: %s (errno: %d)", path,
                        errno);
        return NULL;
    }
    X509* cert = PEM_read_X509(pemFile, NULL, NULL, NULL);
    EVP_PKEY* pub_key = X509_get_pubkey(cert);
    if (pub_key == NULL) {
        fclose(pemFile);
        X509_free(cert);
        return NULL;
    }
    int id = EVP_PKEY_id(pub_key);
    if (id != EVP_PKEY_RSA) {
        EVP_PKEY_free(pub_key);
        fclose(pemFile);
        X509_free(cert);
        return NULL;
    }
    fclose(pemFile);
    X509_free(cert);
    return pub_key;
}

static crypto_pkey_t* openssl_load_private_key(const char* path) {
    FILE* keyfile = fopen(path, "rb");
    if (keyfile == NULL) {
        SST_print_error("Failed to open private key file: %s (errno: %d)", path,
                        errno);
        return NULL;
    }
    EVP_PKEY* priv_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    return priv_key;
}

static void openssl_free_pkey(crypto_pkey_t* pkey) {
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
}

static unsigned char* openssl_public_encrypt(const unsigned char* data,
                                             size_t data_len, int padding,
                                             crypto_pkey_t* pub_key,
                                             size_t* ret_len) {
    EVP_PKEY_CTX* ctx;
    unsigned char* out = NULL;

    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        return NULL;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_encrypt(ctx, NULL, ret_len, data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    out = (unsigned char*)malloc(*ret_len);
    if (!out) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, out, ret_len, data, data_len) <= 0) {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

static unsigned char* openssl_private_decrypt(const unsigned char* enc_data,
                                              size_t enc_data_len, int padding,
                                              crypto_pkey_t* priv_key,
                                              size_t* ret_len) {
    EVP_PKEY_CTX* ctx;
    unsigned char* out = NULL;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        return NULL;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_decrypt(ctx, NULL, ret_len, enc_data, enc_data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    out = (unsigned char*)malloc(*ret_len);
    if (!out) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_decrypt(ctx, out, ret_len, enc_data, enc_data_len) <= 0) {
        free(out);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

static unsigned char* openssl_sign_sha256(const unsigned char* data,
                                          unsigned int data_length,
                                          crypto_pkey_t* priv_key,
                                          size_t* sig_length) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_length;
    if (digest_message_SHA_256(data, data_length, md, &md_length) < 0) {
        return NULL;
    }
    EVP_PKEY_CTX* ctx;
    unsigned char* sig = NULL;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        return NULL;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_sign(ctx, NULL, sig_length, md, md_length) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    sig = (unsigned char*)malloc(*sig_length);

    if (!sig) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_sign(ctx, sig, sig_length, md, md_length) <= 0) {
        free(sig);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return sig;
}

static int openssl_verify_sha256(const unsigned char* data,
                                 unsigned int data_length, unsigned char* sig,
                                 size_t sig_length, crypto_pkey_t* pub_key) {
    EVP_PKEY_CTX* ctx;
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len;
    if (digest_message_SHA_256(data, data_length, md, &md_len) < 0) {
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        return -1;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_verify(ctx, sig, sig_length, md, md_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int openssl_digest_sha256(const unsigned char* data, size_t data_len,
                                 unsigned char* hash, unsigned int* hash_len) {
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_create()) == NULL) {
        return -1;
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_destroy(mdctx);
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        EVP_MD_CTX_destroy(mdctx);
        return -1;
    }
    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        EVP_MD_CTX_destroy(mdctx);
        return -1;
    }
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}

static const EVP_CIPHER* get_EVP_CIPHER(AES_encryption_mode_t enc_mode) {
    if (enc_mode == AES_128_CBC) {
        return EVP_aes_128_cbc();
    } else if (enc_mode == AES_128_CTR) {
        return EVP_aes_128_ctr();
    } else if (enc_mode == AES_128_GCM) {
        return EVP_aes_128_gcm();
    } else {
        return NULL;
    }
}

static int openssl_encrypt_aes(const unsigned char* plaintext,
                               unsigned int plaintext_length,
                               const unsigned char* key,
                               const unsigned char* iv,
                               AES_encryption_mode_t enc_mode,
                               unsigned char* ret, unsigned int* ret_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, get_EVP_CIPHER(enc_mode), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (!EVP_EncryptUpdate(ctx, ret, (int*)ret_length, plaintext,
                           plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ret + *ret_length, (int*)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ret_length += temp_len;

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE,
                                 ret + *ret_length)) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        *ret_length += AES_GCM_TAG_SIZE;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int openssl_decrypt_aes(const unsigned char* encrypted,
                               unsigned int encrypted_length,
                               const unsigned char* key,
                               const unsigned char* iv,
                               AES_encryption_mode_t enc_mode,
                               unsigned char* ret, unsigned int* ret_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, get_EVP_CIPHER(enc_mode), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        unsigned char* tag =
            (unsigned char*)encrypted + encrypted_length - AES_GCM_TAG_SIZE;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                                 tag)) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        encrypted_length -= AES_GCM_TAG_SIZE;
    }

    if (!EVP_DecryptUpdate(ctx, ret, (int*)ret_length, encrypted,
                           encrypted_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned int temp_len;
    if (!EVP_DecryptFinal_ex(ctx, ret + *ret_length, (int*)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ret_length += temp_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int openssl_generate_random(unsigned char* buf, int length) {
    return RAND_bytes(buf, length) == 1 ? 0 : -1;
}

static void openssl_free_memory(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

static void* openssl_malloc_memory(size_t size) { return OPENSSL_malloc(size); }

static int openssl_hmac_sha256(const unsigned char* key, size_t key_len,
                               const unsigned char* data, size_t data_len,
                               unsigned char* output,
                               unsigned int* output_len) {
    unsigned int len = 0;
    unsigned char* result =
        HMAC(EVP_sha256(), key, key_len, data, data_len, output, &len);
    if (!result) {
        return -1;
    }
    *output_len = len;
    return 0;
}

// OpenSSL crypto backend implementation
static const crypto_backend_t openssl_backend = {
    .load_public_key = openssl_load_public_key,
    .load_private_key = openssl_load_private_key,
    .free_pkey = openssl_free_pkey,
    .print_error = openssl_print_error,
    .public_encrypt = openssl_public_encrypt,
    .private_decrypt = openssl_private_decrypt,
    .sign_sha256 = openssl_sign_sha256,
    .verify_sha256 = openssl_verify_sha256,
    .digest_sha256 = openssl_digest_sha256,
    .encrypt_aes = openssl_encrypt_aes,
    .decrypt_aes = openssl_decrypt_aes,
    .generate_random = openssl_generate_random,
    .free_memory = openssl_free_memory,
    .malloc_memory = openssl_malloc_memory,
    .hmac_sha256 = openssl_hmac_sha256};

const crypto_backend_t* get_crypto_backend(void) { return &openssl_backend; }

// TODO: Clean up.
//  int init_crypto_backend(void) {
//      // OpenSSL initialization is typically done automatically
//      return 0;
//  }

// void cleanup_crypto_backend(void) {
//     // OpenSSL cleanup is typically done automatically
// }

#endif  // USE_OPENSSL
