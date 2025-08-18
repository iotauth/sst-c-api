#include "c_crypto.h"

#include "c_common.h"

// Print OpenSSL crypto error message to stderr with message.
// @param msg Message to print with.
static void print_crypto_error(const char *msg) {
    char err[MAX_ERROR_MESSAGE_LENGTH];

    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
}

// Print OpenSSL crypto error message, and return NULL.
// @param msg Message to print with.
static void *print_crypto_error_return_NULL(const char *msg) {
    print_crypto_error(msg);
    return NULL;
}

EVP_PKEY *load_auth_public_key(const char *path) {
    FILE *pemFile = fopen(path, "rb");
    if (pemFile == NULL) {
        printf("Error %d \n", errno);
        return print_crypto_error_return_NULL(
            "Loading auth_pub_key_path failed");
    }
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL);
    EVP_PKEY *pub_key = X509_get_pubkey(cert);
    if (pub_key == NULL) {
        return print_crypto_error_return_NULL("public key getting fail");
    }
    int id = EVP_PKEY_id(pub_key);
    if (id != EVP_PKEY_RSA) {
        return print_crypto_error_return_NULL("is not RSA Encryption file");
    }
    fclose(pemFile);
    X509_free(cert);
    return pub_key;
}

EVP_PKEY *load_entity_private_key(const char *path) {
    FILE *keyfile = fopen(path, "rb");
    if (keyfile == NULL) {
        printf("Error %d \n", errno);
        return print_crypto_error_return_NULL(
            "Loading entity_priv_key_path failed");
    }
    EVP_PKEY *priv_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    return priv_key;
}

unsigned char *public_encrypt(const unsigned char *data, size_t data_len,
                              int padding, EVP_PKEY *pub_key, size_t *ret_len) {
    EVP_PKEY_CTX *ctx;
    unsigned char *out = NULL;

    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        return print_crypto_error_return_NULL("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_encrypt_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        return print_crypto_error_return_NULL(
            "EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_encrypt(ctx, NULL, ret_len, data, data_len) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_encrypt failed");
    }
    out = (unsigned char *)OPENSSL_malloc(*ret_len);
    if (!out) {
        return print_crypto_error_return_NULL("OPENSSL_malloc failed");
    }

    if (EVP_PKEY_encrypt(ctx, out, ret_len, data, data_len) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_encrypt failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

unsigned char *private_decrypt(const unsigned char *enc_data,
                               size_t enc_data_len, int padding,
                               EVP_PKEY *priv_key, size_t *ret_len) {
    EVP_PKEY_CTX *ctx;
    unsigned char *out = NULL;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        return print_crypto_error_return_NULL("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_decrypt_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        return print_crypto_error_return_NULL(
            "EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_decrypt(ctx, NULL, ret_len, enc_data, enc_data_len) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_decrypt failed");
    }
    out = (unsigned char *)OPENSSL_malloc(*ret_len);
    if (!out) {
        return print_crypto_error_return_NULL("OPENSSL_malloc failed");
    }
    if (EVP_PKEY_decrypt(ctx, out, ret_len, enc_data, enc_data_len) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_decrypt failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

unsigned char *SHA256_sign(const unsigned char *encrypted,
                           unsigned int encrypted_length, EVP_PKEY *priv_key,
                           size_t *sig_length) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_length;
    if (digest_message_SHA_256(encrypted, encrypted_length, md, &md_length) <
        0) {
        return print_crypto_error_return_NULL(
            "Failed digest_message_SHA_256().");
    }
    EVP_PKEY_CTX *ctx;
    unsigned char *sig = NULL;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        return print_crypto_error_return_NULL("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_sign_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        return print_crypto_error_return_NULL(
            "EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        return print_crypto_error_return_NULL(
            "EVP_PKEY_CTX_set_signature_md failed");
    }
    if (EVP_PKEY_sign(ctx, NULL, sig_length, md, md_length) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_sign failed");
    }
    sig = (unsigned char *)OPENSSL_malloc(*sig_length);

    if (!sig) {
        return print_crypto_error_return_NULL("OPENSSL_malloc failed");
    }
    if (EVP_PKEY_sign(ctx, sig, sig_length, md, md_length) <= 0) {
        return print_crypto_error_return_NULL("EVP_PKEY_sign failed");
    }
    EVP_PKEY_CTX_free(ctx);

    return sig;
}

int SHA256_verify(const unsigned char *data, unsigned int data_length,
                  unsigned char *sig, size_t sig_length, EVP_PKEY *pub_key) {
    EVP_PKEY_CTX *ctx;
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len;
    if (digest_message_SHA_256(data, data_length, md, &md_len) < 0) {
        print_crypto_error("Failed digest_message_SHA_256().");
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        print_crypto_error("EVP_PKEY_CTX_new failed");
        return -1;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        print_crypto_error("EVP_PKEY_verify_init failed");
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_rsa_padding failed");
        return -1;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_signature_md failed");
        return -1;
    }
    if (EVP_PKEY_verify(ctx, sig, sig_length, md, md_len) != 1) {
        print_crypto_error("EVP_PKEY_verify failed");
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int digest_message_SHA_256(const unsigned char *data, size_t data_len,
                           unsigned char *md5_hash, unsigned int *md_len) {
    EVP_MD_CTX *mdctx;

    if ((mdctx = EVP_MD_CTX_create()) == NULL) {
        print_crypto_error("EVP_MD_CTX_create() failed");
        return -1;
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        print_crypto_error("EVP_DigestInit_ex failed");
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        print_crypto_error("EVP_DigestUpdate failed");
        return -1;
    }
    if (EVP_DigestFinal_ex(mdctx, md5_hash, md_len) != 1) {
        print_crypto_error("failed");
        return -1;
    }
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}

// Get OpenSSL EVP_CIPHER structure corresponding to the given encryption mode.
// @param enc_mode AES encryption mode enum (e.g., AES_128_CBC)
// @return OpenSSL EVP_CIPHER*, or NULL if unsupported
static const EVP_CIPHER *get_EVP_CIPHER(AES_encryption_mode_t enc_mode) {
    if (enc_mode == AES_128_CBC) {
        return EVP_aes_128_cbc();
    } else if (enc_mode == AES_128_CTR) {
        return EVP_aes_128_ctr();
    } else if (enc_mode == AES_128_GCM) {
        return EVP_aes_128_gcm();
    } else {
        SST_print_error("Encryption type not supported.");
    }
    return NULL;
}

int encrypt_AES(const unsigned char *plaintext, unsigned int plaintext_length,
                const unsigned char *key, const unsigned char *iv,
                AES_encryption_mode_t enc_mode, unsigned char *ret,
                unsigned int *ret_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, get_EVP_CIPHER(enc_mode), NULL, key, iv)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_EncryptInit_ex failed");
        return -1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE,
                                 NULL)) {  // Set IV length to 12 bytes
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
            return -1;
        }
    }

    if (!EVP_EncryptUpdate(ctx, ret, (int *)ret_length, plaintext,
                           plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_EncryptUpdate failed");
        return -1;
    }

    unsigned int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ret + *ret_length, (int *)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_EncryptFinal_ex failed");
        return -1;
    }
    *ret_length += temp_len;

    if (enc_mode == AES_128_GCM) {
        // Append the GCM authentication tag to the end of the ciphertext
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE,
                                 ret + *ret_length)) {  // 16 bytes tag
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
            return -1;
        }
        *ret_length += AES_GCM_TAG_SIZE;  // Increase the length by the tag size
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt_AES(const unsigned char *encrypted, unsigned int encrypted_length,
                const unsigned char *key, const unsigned char *iv,
                AES_encryption_mode_t enc_mode, unsigned char *ret,
                unsigned int *ret_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, get_EVP_CIPHER(enc_mode), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_DecryptInit_ex failed");
        return -1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE,
                                 NULL)) {  // Set IV length to 12 bytes
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
            return -1;
        }

        // Set the expected tag value by extracting it from the end of the
        // ciphertext
        unsigned char *tag =
            (unsigned char *)encrypted + encrypted_length -
            AES_GCM_TAG_SIZE;  // Get the last 16 bytes as the tag
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                                 tag)) {
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
            return -1;
        }

        encrypted_length -=
            AES_GCM_TAG_SIZE;  // Adjust the encrypted length to exclude the tag
    }

    if (!EVP_DecryptUpdate(ctx, ret, (int *)ret_length, encrypted,
                           encrypted_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_DecryptUpdate failed");
        return -1;
    }

    unsigned int temp_len;
    if (!EVP_DecryptFinal_ex(ctx, ret + *ret_length, (int *)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_DecryptFinal_ex failed");
        return -1;
    }
    *ret_length += temp_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

unsigned int get_expected_encrypted_total_length(unsigned int buf_length,
                                                 unsigned int iv_size,
                                                 unsigned int mac_key_size,
                                                 AES_encryption_mode_t enc_mode,
                                                 hmac_mode_t hmac_mode) {
    unsigned int encrypted_total_length = 0;
    if (enc_mode == AES_128_CBC) {
        // This requires, paddings, making the encrypted length multiples of the
        // block size (key size)
        encrypted_total_length = ((buf_length / iv_size) + 1) * iv_size;
    } else if (enc_mode == AES_128_CTR) {
        // The encrypted length is same on CTR mode.
        encrypted_total_length = buf_length;
    } else if (enc_mode == AES_128_GCM) {
        encrypted_total_length =
            buf_length +
            AES_GCM_TAG_SIZE;  // GCM_TAG //TODO: Check. Tag size default is 12.
    }
    if (hmac_mode == USE_HMAC) {
        encrypted_total_length =
            iv_size + encrypted_total_length + mac_key_size;
    } else {
        encrypted_total_length = iv_size + encrypted_total_length;
    }
    return encrypted_total_length;
}

static int get_symmetric_encrypt_authenticate_buffer(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned int expected_encrypted_total_length, unsigned char *ret,
    unsigned int *ret_length) {
    // The return of encrypt_AES will look like this.
    // ret = IV (16) + encrypted(IV+buf) + (optional) HMAC(IV + encrypted) (32)
    // First attach IV.
    if (generate_nonce(iv_size, ret) < 0) {
        SST_print_error("Failed generate_nonce().");
        return -1;
    }
    unsigned int total_length = 0;
    // Attach encrypted buffer
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (encrypt_AES(buf, buf_length, cipher_key, ret, enc_mode,
                        ret + iv_size, &total_length) < 0) {
            SST_print_error("AES encryption failed!");
            return -1;
        }
        total_length += iv_size;
    }
    // Add other ciphers in future.
    else {
        SST_print_error("Cipher_key_size is not supported.");
        return -1;
    };
    if (hmac_mode == USE_HMAC) {
        // Attach HMAC tag
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            HMAC(EVP_sha256(), mac_key, mac_key_size, ret, total_length,
                 ret + total_length, &mac_key_size);
            total_length += mac_key_size;
        }
        // Add other MAC key sizes in future.
        else {
            SST_print_error("HMAC_key_size is not supported.");
            return -1;
        }
    }
    if (expected_encrypted_total_length != total_length) {
        SST_print_error("Encrypted length does not match with expected.");
        return -1;
    }
    *ret_length = total_length;
    return 0;
}

unsigned int get_expected_decrypted_maximum_length(
    unsigned int buf_length, unsigned int iv_size, unsigned int mac_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode) {
    unsigned int decrypted_maximum_length;
    // First remove the IV length attached on front.
    decrypted_maximum_length = buf_length - iv_size;
    if (hmac_mode == USE_HMAC) {
        decrypted_maximum_length -= mac_key_size;
    } else {
        // There is already no mac.
    }
    if (enc_mode == AES_128_CBC) {
        decrypted_maximum_length = decrypted_maximum_length / iv_size * iv_size;
    } else if (enc_mode == AES_128_CTR) {
        // Decrypted_length is same as plaintext on CTR mode.
    } else if (enc_mode == AES_128_GCM) {
        decrypted_maximum_length = decrypted_maximum_length - AES_GCM_TAG_SIZE;
    }
    return decrypted_maximum_length;
}

static int get_symmetric_decrypt_authenticate_buffer(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned int expected_decrypted_total_length, unsigned char *ret,
    unsigned int *ret_length) {
    // The encrypted buffer is composed like below.
    // encrypted = iv (16) + encrypted (plaintext) + HMAC (IV + encrypted)(32)
    unsigned int encrypted_length = buf_length - iv_size;
    if (hmac_mode == USE_HMAC) {
        unsigned char reproduced_tag[mac_key_size];
        encrypted_length -= mac_key_size;
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            HMAC(EVP_sha256(), mac_key, mac_key_size, buf,
                 iv_size + encrypted_length, reproduced_tag, &mac_key_size);
        } else {
            SST_print_error("HMAC_key_size is not supported.");
            return -1;
        }
        if (memcmp(reproduced_tag, buf + iv_size + encrypted_length,
                   mac_key_size) != 0) {
            SST_print_debug("Received tag: ");
            print_buf_debug(buf + encrypted_length, mac_key_size);
            SST_print_debug("Hmac tag: ");
            print_buf_debug(reproduced_tag, mac_key_size);
            return -1;
        } else {
            SST_print_debug("MAC verified!");
        }
    }
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (decrypt_AES(buf + iv_size, encrypted_length, cipher_key, buf,
                        enc_mode, ret, ret_length) < 0) {
            SST_print_error("AES_CBC_128_decrypt failed!");
            return -1;
        }
        if (expected_decrypted_total_length != *ret_length) {
            if (enc_mode == AES_128_CBC &&
                expected_decrypted_total_length > *ret_length) {
                // This is fine. Cannot get exact decrypted length before
                // decrypting on block ciphers like CBC mode.
            } else {
                SST_print_error(
                    "Decrypted length does not match with expected.");
                return -1;
            }
        }
    }
    // Add other ciphers in future.
    else {
        SST_print_error("Cipher_key_size is not supported.");
        return -1;
    }
    return 0;
}

int symmetric_encrypt_authenticate(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char **ret, unsigned int *ret_length) {
    // First, get the expected encrypted length, to assign a buffer size.
    unsigned int expected_encrypted_total_length =
        get_expected_encrypted_total_length(buf_length, iv_size, mac_key_size,
                                            enc_mode, hmac_mode);
    *ret = (unsigned char *)malloc(expected_encrypted_total_length);
    return get_symmetric_encrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_encrypted_total_length, *ret,
        ret_length);
}

int symmetric_decrypt_authenticate(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char **ret, unsigned int *ret_length) {
    unsigned int expected_decrypted_total_length =
        get_expected_decrypted_maximum_length(buf_length, iv_size, mac_key_size,
                                              enc_mode, hmac_mode);
    *ret = (unsigned char *)malloc(expected_decrypted_total_length);
    return get_symmetric_decrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_decrypted_total_length, *ret,
        ret_length);
}

int symmetric_encrypt_authenticate_without_malloc(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char *ret, unsigned int *ret_length) {
    unsigned int expected_encrypted_total_length =
        get_expected_encrypted_total_length(buf_length, iv_size, mac_key_size,
                                            enc_mode, hmac_mode);

    return get_symmetric_encrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_encrypted_total_length, ret,
        ret_length);
}

int symmetric_decrypt_authenticate_without_malloc(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char *ret, unsigned int *ret_length) {
    unsigned int expected_decrypted_total_length =
        get_expected_decrypted_maximum_length(buf_length, iv_size, mac_key_size,
                                              enc_mode, hmac_mode);
    return get_symmetric_decrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_decrypted_total_length, ret,
        ret_length);
}

int create_salted_password_to_32bytes(const char *password,
                                      unsigned int password_len,
                                      const char *salt, unsigned int salt_len,
                                      unsigned char *ret) {
    // TODO: Need to think about this. How should we pass the length? Is
    // strlen() better or sizeof() better? Should we handle it inside the
    // function or should it be a argument? Leaving it as argument to pass the
    // char * and the length using sizeof(). Then, when salting the password, it
    // should exclude the NULL terminator when salting the password.

    // Exclude NULL for both password and salt.
    unsigned int salted_password_length = password_len - 1 + salt_len - 1;
    unsigned char salted_password[salted_password_length];
    // Combine the password with the salt
    memcpy(salted_password, password, password_len - 1);
    memcpy(salted_password + password_len - 1, salt,
           salt_len - 1);  // Exclude NULL
    // Create SHA256 HMAC.
    unsigned int md_len;
    if (digest_message_SHA_256(salted_password, salted_password_length, ret,
                               &md_len) < 0) {
        print_crypto_error("Failed digest_message_SHA_256().");
        return -1;
    }
    return 0;
}
