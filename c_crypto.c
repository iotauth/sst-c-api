#include "c_crypto.h"

void print_last_error(char *msg) {
    char err[MAX_ERROR_MESSAGE_LENGTH];

    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    exit(1);
}

EVP_PKEY *load_auth_public_key(const char *path) {
    FILE *pemFile = fopen(path, "rb");
    if (pemFile == NULL) {
        printf("Error %d \n", errno);
        print_last_error("Loading auth_pub_key_path failed");
    }
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL);
    EVP_PKEY *pub_key = X509_get_pubkey(cert);
    if (pub_key == NULL) {
        print_last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pub_key);
    if (id != EVP_PKEY_RSA) {
        print_last_error("is not RSA Encryption file");
    }
    fclose(pemFile);
    X509_free(cert);
    return pub_key;
}

EVP_PKEY *load_entity_private_key(const char *path) {
    FILE *keyfile = fopen(path, "rb");
    if (keyfile == NULL) {
        printf("Error %d \n", errno);
        print_last_error("Loading entity_priv_key_path failed");
    }
    EVP_PKEY *priv_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    return priv_key;
}

unsigned char *public_encrypt(unsigned char *data, size_t data_len, int padding,
                              EVP_PKEY *pub_key, size_t *ret_len) {
    EVP_PKEY_CTX *ctx;
    unsigned char *out;

    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        print_last_error("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        print_last_error("EVP_PKEY_encrypt_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_encrypt(ctx, NULL, ret_len, data, data_len) <= 0) {
        print_last_error("EVP_PKEY_encrypt failed");
    }
    out = OPENSSL_malloc(*ret_len);
    if (!out) {
        print_last_error("OPENSSL_malloc failed");
    }

    if (EVP_PKEY_encrypt(ctx, out, ret_len, data, data_len) <= 0) {
        print_last_error("EVP_PKEY_encrypt failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

unsigned char *private_decrypt(unsigned char *enc_data, size_t enc_data_len,
                               int padding, EVP_PKEY *priv_key,
                               size_t *ret_len) {
    EVP_PKEY_CTX *ctx;
    unsigned char *out;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        print_last_error("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        print_last_error("EVP_PKEY_decrypt_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_decrypt(ctx, NULL, ret_len, enc_data, enc_data_len) <= 0) {
        print_last_error("EVP_PKEY_decrypt failed");
    }
    out = OPENSSL_malloc(*ret_len);
    if (!out) {
        print_last_error("OPENSSL_malloc failed");
    }
    if (EVP_PKEY_decrypt(ctx, out, ret_len, enc_data, enc_data_len) <= 0) {
        print_last_error("EVP_PKEY_decrypt failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return out;
}

unsigned char *SHA256_sign(unsigned char *encrypted,
                           unsigned int encrypted_length, EVP_PKEY *priv_key,
                           size_t *sig_length) {
    unsigned int md_length;
    unsigned char *md =
        digest_message_SHA_256(encrypted, encrypted_length, &md_length);
    EVP_PKEY_CTX *ctx;
    unsigned char *sig;
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        print_last_error("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        print_last_error("EVP_PKEY_sign_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        print_last_error("EVP_PKEY_CTX_set_signature_md failed");
    }
    if (EVP_PKEY_sign(ctx, NULL, sig_length, md, md_length) <= 0) {
        print_last_error("EVP_PKEY_sign failed");
    }
    sig = OPENSSL_malloc(*sig_length);

    if (!sig) {
        print_last_error("OPENSSL_malloc failed");
    }
    if (EVP_PKEY_sign(ctx, sig, sig_length, md, md_length) <= 0) {
        print_last_error("EVP_PKEY_sign failed");
    }
    EVP_PKEY_CTX_free(ctx);
    free(md);

    return sig;
}

void SHA256_verify(unsigned char *data, unsigned int data_length,
                   unsigned char *sig, size_t sig_length, EVP_PKEY *pub_key) {
    EVP_PKEY_CTX *ctx;
    unsigned int md_length;
    unsigned char *md = digest_message_SHA_256(data, data_length, &md_length);

    ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) {
        print_last_error("EVP_PKEY_CTX_new failed");
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        print_last_error("EVP_PKEY_verify_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        print_last_error("EVP_PKEY_CTX_set_rsa_padding failed");
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        print_last_error("EVP_PKEY_CTX_set_signature_md failed");
    }
    if (EVP_PKEY_verify(ctx, sig, sig_length, md, md_length) != 1) {
        print_last_error("EVP_PKEY_verify failed");
    }
    EVP_PKEY_CTX_free(ctx);
    free(md);
}

unsigned char *digest_message_SHA_256(unsigned char *message,
                                      int message_length,
                                      unsigned int *digest_len) {
    EVP_MD_CTX *mdctx;

    if ((mdctx = EVP_MD_CTX_create()) == NULL) {
        print_last_error("EVP_MD_CTX_create() failed");
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        print_last_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(mdctx, message, message_length) != 1) {
        print_last_error("EVP_DigestUpdate failed");
    }
    unsigned char *digest =
        (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if (EVP_DigestFinal_ex(mdctx, digest, digest_len) != 1) {
        print_last_error("failed");
    }
    EVP_MD_CTX_destroy(mdctx);
    return digest;
}

const EVP_CIPHER *get_EVP_CIPHER(char enc_mode) {
    if (enc_mode == AES_128_CBC) {
        return EVP_aes_128_cbc();
    } else if (enc_mode == AES_128_CTR) {
        return EVP_aes_128_ctr();
    } else if (enc_mode == AES_128_GCM) {
        return EVP_aes_128_gcm();
    } else {
        error_exit("Encryption type not supported.");
    }
    return NULL;
}

int encrypt_AES(unsigned char *plaintext, unsigned int plaintext_length,
                unsigned char *key, unsigned char *iv, char enc_mode,
                unsigned char *ret, unsigned int *ret_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, get_EVP_CIPHER(enc_mode), NULL, key, iv)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptInit_ex failed");
        return 1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE,
                                 NULL)) {  // Set IV length to 16 bytes
            EVP_CIPHER_CTX_free(ctx);
            print_last_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
            return 1;
        }
    }

    if (!EVP_EncryptUpdate(ctx, ret, (int *)ret_length, plaintext,
                           plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptUpdate failed");
        return 1;
    }

    unsigned int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ret + *ret_length, (int *)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptFinal_ex failed");
        return 1;
    }
    *ret_length += temp_len;

    if (enc_mode == AES_128_GCM) {
        // Append the GCM authentication tag to the end of the ciphertext
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE,
                                 ret + *ret_length)) {  // 16 bytes tag
            EVP_CIPHER_CTX_free(ctx);
            print_last_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
            return 1;
        }
        *ret_length += AES_GCM_TAG_SIZE;  // Increase the length by the tag size
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int decrypt_AES(unsigned char *encrypted, unsigned int encrypted_length,
                unsigned char *key, unsigned char *iv, char enc_mode,
                unsigned char *ret, unsigned int *ret_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, get_EVP_CIPHER(enc_mode), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_DecryptInit_ex failed");
        return 1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE,
                                 NULL)) {  // Set IV length to 16 bytes
            EVP_CIPHER_CTX_free(ctx);
            print_last_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
            return 1;
        }

        // Set the expected tag value by extracting it from the end of the
        // ciphertext
        unsigned char *tag =
            encrypted + encrypted_length -
            AES_GCM_TAG_SIZE;  // Get the last 16 bytes as the tag
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                                 tag)) {
            EVP_CIPHER_CTX_free(ctx);
            print_last_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
            return 1;
        }

        encrypted_length -=
            AES_GCM_TAG_SIZE;  // Adjust the encrypted length to exclude the tag
    }

    if (!EVP_DecryptUpdate(ctx, ret, (int *)ret_length, encrypted,
                           encrypted_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_DecryptUpdate failed");
        return 1;
    }

    unsigned int temp_len;
    if (!EVP_DecryptFinal_ex(ctx, ret + *ret_length, (int *)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_DecryptFinal_ex failed");
        return 1;
    }
    *ret_length += temp_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int symmetric_encrypt_authenticate(
    unsigned char *buf, unsigned int buf_length, unsigned char *mac_key,
    unsigned int mac_key_size, unsigned char *cipher_key,
    unsigned int cipher_key_size, unsigned int iv_size, char enc_mode,
    char no_hmac_mode, unsigned char **ret, unsigned int *ret_length) {
    unsigned int encrypted_length;
    if (enc_mode == AES_128_CBC) {
        // This requires, paddings, making the encrypted length multiples of the
        // block size (key size)
        encrypted_length = ((buf_length / iv_size) + 1) * iv_size;
    } else if (enc_mode == AES_128_CTR) {
        // The encrypted length is same on CTR mode.
        encrypted_length = buf_length;
    } else if (enc_mode == AES_128_GCM) {
        encrypted_length = buf_length + 16;
    }
    if (no_hmac_mode == 0) {
        *ret_length = iv_size + encrypted_length + mac_key_size;
    } else {
        *ret_length = iv_size + encrypted_length;
    }
    *ret = (unsigned char *)malloc(*ret_length);
    // ret = IV (16) + encrypted(IV+buf) + HMAC((IV + encrypted)32)
    // First attach IV.
    generate_nonce(iv_size, *ret);
    unsigned int count = iv_size;
    // Attach encrypted buffer
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (encrypt_AES(buf, buf_length, cipher_key, *ret, enc_mode,
                        *ret + count, &encrypted_length)) {
            printf("AES encryption failed!");
            return 1;
        }
    }
    // Add other ciphers in future.
    else {
        printf("Cipher_key_size is not supported.");
        return 1;
    }
    if (no_hmac_mode == 0) {
        count += encrypted_length;
        // Attach HMAC tag
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            HMAC(EVP_sha256(), mac_key, mac_key_size, *ret,
                 iv_size + encrypted_length, *ret + count, &mac_key_size);
        }
        // Add other MAC key sizes in future.
        else {
            printf("HMAC_key_size is not supported.");
            return 1;
        }
    }
    return 0;
}

int symmetric_decrypt_authenticate(
    unsigned char *buf, unsigned int buf_length, unsigned char *mac_key,
    unsigned int mac_key_size, unsigned char *cipher_key,
    unsigned int cipher_key_size, unsigned int iv_size, char enc_mode,
    char no_hmac_mode, unsigned char **ret, unsigned int *ret_length) {
    unsigned int encrypted_length;
    if (no_hmac_mode == 0) {
        encrypted_length = buf_length - mac_key_size;
    } else {
        encrypted_length = buf_length;
    }
    *ret_length = encrypted_length / iv_size * iv_size;
    *ret = (unsigned char *)malloc(*ret_length);
    if (no_hmac_mode == 0) {
        unsigned char reproduced_tag[mac_key_size];
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            HMAC(EVP_sha256(), mac_key, mac_key_size, buf, encrypted_length,
                 reproduced_tag, &mac_key_size);
        } else {
            printf("HMAC_key_size is not supported.");
            return 1;
        }
        if (memcmp(reproduced_tag, buf + encrypted_length, mac_key_size) != 0) {
            // printf("Received tag: ");
            // print_buf(buf + encrypted_length, mac_key_size);
            // printf("Hmac tag: ");
            // print_buf(reproduced_tag, mac_key_size);
            return 1;
        } else {
            // printf("MAC verified!\n");
        }
    }
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (decrypt_AES(buf + iv_size, encrypted_length - iv_size, cipher_key,
                        buf, enc_mode, *ret, ret_length)) {
            printf("AES_CBC_128_decrypt failed!");
            return 1;
        }
    }
    // Add other ciphers in future.
    else {
        printf("Cipher_key_size is not supported.");
        return 1;
    }
    return 0;
}

int symmetric_encrypt_authenticate_without_malloc(
    unsigned char *buf, unsigned int buf_length, unsigned char *mac_key,
    unsigned int mac_key_size, unsigned char *cipher_key,
    unsigned int cipher_key_size, unsigned int iv_size, char enc_mode,
    char no_hmac_mode, unsigned char *ret, unsigned int *ret_length) {
    unsigned int encrypted_length;
    if (enc_mode == AES_128_CBC) {
        // This requires, paddings, making the encrypted length multiples of the
        // block size (key size)
        encrypted_length = ((buf_length / iv_size) + 1) * iv_size;
    } else if (enc_mode == AES_128_CTR) {
        // The encrypted length is same on CTR mode.
        encrypted_length = buf_length;
    } else if (enc_mode == AES_128_GCM) {
        encrypted_length = buf_length + 16;
    }
    if (no_hmac_mode == 0) {
        *ret_length = iv_size + encrypted_length + mac_key_size;
    } else {
        *ret_length = iv_size + encrypted_length;
    }
    // ret = IV (16) + encrypted(IV+buf) + HMAC((IV + encrypted)32)
    // First attach IV.
    generate_nonce(iv_size, ret);
    unsigned int count = iv_size;
    // Attach encrypted buffer
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (encrypt_AES(buf, buf_length, cipher_key, ret, enc_mode,
                        ret + count, &encrypted_length)) {
            printf("AES encryption failed!");
            return 1;
        }
    }
    // Add other ciphers in future.
    else {
        printf("Cipher_key_size is not supported.");
        return 1;
    }
    if (no_hmac_mode == 0) {
        count += encrypted_length;
        // Attach HMAC tag
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            HMAC(EVP_sha256(), mac_key, mac_key_size, ret,
                 iv_size + encrypted_length, ret + count, &mac_key_size);
        }
        // Add other MAC key sizes in future.
        else {
            printf("HMAC_key_size is not supported.");
            return 1;
        }
    }
    return 0;
}

int symmetric_decrypt_authenticate_without_malloc(
    unsigned char *buf, unsigned int buf_length, unsigned char *mac_key,
    unsigned int mac_key_size, unsigned char *cipher_key,
    unsigned int cipher_key_size, unsigned int iv_size, char enc_mode,
    char no_hmac_mode, unsigned char *ret, unsigned int *ret_length) {
    unsigned int encrypted_length;
    if (no_hmac_mode == 0) {
        encrypted_length = buf_length - mac_key_size;
    } else {
        encrypted_length = buf_length;
    }
    *ret_length = encrypted_length / iv_size * iv_size;
    if (no_hmac_mode == 0) {
        unsigned char reproduced_tag[mac_key_size];
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            HMAC(EVP_sha256(), mac_key, mac_key_size, buf, encrypted_length,
                 reproduced_tag, &mac_key_size);
        } else {
            printf("HMAC_key_size is not supported.");
            return 1;
        }
        if (memcmp(reproduced_tag, buf + encrypted_length, mac_key_size) != 0) {
            // printf("Received tag: ");
            // print_buf(buf + encrypted_length, mac_key_size);
            // printf("Hmac tag: ");
            // print_buf(reproduced_tag, mac_key_size);
            return 1;
        } else {
            // printf("MAC verified!\n");
        }
    }
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (decrypt_AES(buf + iv_size, encrypted_length - iv_size, cipher_key,
                        buf, enc_mode, ret, ret_length)) {
            printf("AES_CBC_128_decrypt failed!");
            return 1;
        }
    }
    // Add other ciphers in future.
    else {
        printf("Cipher_key_size is not supported.");
        return 1;
    }
    return 0;
}

void generate_md5_hash(unsigned char *data, size_t data_len,
                       unsigned char *md5_hash) {
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    if ((mdctx = EVP_MD_CTX_create()) == NULL) {
        print_last_error("EVP_MD_CTX_create() failed");
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        print_last_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        print_last_error("EVP_DigestUpdate failed");
    }
    if (EVP_DigestFinal_ex(mdctx, md5_hash, &md_len) != 1) {
        print_last_error("failed");
    }
    EVP_MD_CTX_destroy(mdctx);
}

int CTR_Cipher(const unsigned char *key, const uint64_t initial_iv_high,
               const uint64_t initial_iv_low, uint64_t file_offset,
               const unsigned char *data, unsigned char *out_data,
               size_t data_size, size_t out_data_size, int encrypt,
               unsigned int *processed_size) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        error_exit("Failed to create EVP_CIPHER_CTX");
    }

    const size_t kBlockSize = 16;  // AES block size
    if (out_data_size < data_size) {
        fprintf(stderr,
                "Output buffer is too small, required: %zu, provided: %zu\n",
                data_size, out_data_size);
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

    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv, encrypt) !=
        1) {
        error_exit("Failed to initialize cipher");
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char partial_block[kBlockSize];
    size_t data_offset = 0;
    size_t remaining_data_size = data_size;
    int output_size = 0;
    *processed_size = 0;

    if (block_offset > 0) {
        size_t partial_block_size =
            kBlockSize - block_offset < remaining_data_size
                ? kBlockSize - block_offset
                : remaining_data_size;
        memcpy(partial_block + block_offset, data, partial_block_size);
        if (EVP_CipherUpdate(ctx, partial_block, &output_size, partial_block,
                             kBlockSize) != 1) {
            error_exit("Failed to update cipher");
        }
        if (output_size != (int)kBlockSize) {
            fprintf(stderr,
                    "Unexpected output size for first block, expected %zu vs "
                    "actual %d\n",
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
        size_t actual_data_size =
            remaining_data_size - (remaining_data_size % kBlockSize);
        if (EVP_CipherUpdate(ctx, full_blocks_out, &output_size, full_blocks,
                             actual_data_size) != 1) {
            error_exit("Failed to update cipher");
        }
        if (output_size != (int)actual_data_size) {
            fprintf(stderr,
                    "Unexpected output size, expected %zu vs actual %d\n",
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
        if (EVP_CipherUpdate(ctx, partial_block, &output_size, partial_block,
                             kBlockSize) != 1) {
            error_exit("Failed to update cipher");
        }
        if (output_size != (int)kBlockSize) {
            fprintf(stderr,
                    "Unexpected output size for last block, expected %zu vs "
                    "actual %d\n",
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