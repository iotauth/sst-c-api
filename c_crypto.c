#include "c_crypto.h"

#include <stdlib.h>
#include <string.h>

#include "c_common.h"
#include "crypto_backend.h"

// Print crypto error message to stderr with message.
// @param msg Message to print with.
static void print_crypto_error(const char* msg) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (backend && backend->print_error) {
        backend->print_error(msg);
        return;
    }
    SST_print_error("%s", msg);
}

// Print OpenSSL crypto error message, and return NULL.
// @param msg Message to print with.
static void* print_crypto_error_return_NULL(const char* msg) {
    print_crypto_error(msg);
    return NULL;
}

crypto_pkey_t* load_auth_public_key(const char* path) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        return print_crypto_error_return_NULL("Crypto backend not available");
    }

    crypto_pkey_t* pkey = backend->load_public_key(path);
    if (!pkey) {
        return print_crypto_error_return_NULL(
            "Loading auth_pub_key_path failed");
    }

    return (crypto_pkey_t*)pkey;
}

crypto_pkey_t* load_entity_private_key(const char* path) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        return print_crypto_error_return_NULL("Crypto backend not available");
    }

    crypto_pkey_t* pkey = backend->load_private_key(path);
    if (!pkey) {
        return print_crypto_error_return_NULL(
            "Loading entity_priv_key_path failed");
    }

    return (crypto_pkey_t*)pkey;
}

unsigned char* public_encrypt(const unsigned char* data, size_t data_len,
                              crypto_pkey_t* pub_key, size_t* ret_len) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        return print_crypto_error_return_NULL("Crypto backend not available");
    }

    unsigned char* result = backend->public_encrypt(
        data, data_len, (crypto_pkey_t*)pub_key, ret_len);
    if (!result) {
        return print_crypto_error_return_NULL("Public encryption failed");
    }

    return result;
}

unsigned char* private_decrypt(const unsigned char* enc_data,
                               size_t enc_data_len, crypto_pkey_t* priv_key,
                               size_t* ret_len) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        return print_crypto_error_return_NULL("Crypto backend not available");
    }

    unsigned char* result = backend->private_decrypt(
        enc_data, enc_data_len, (crypto_pkey_t*)priv_key, ret_len);
    if (!result) {
        return print_crypto_error_return_NULL("Private decryption failed");
    }

    return result;
}

unsigned char* SHA256_sign(const unsigned char* encrypted,
                           unsigned int encrypted_length,
                           crypto_pkey_t* priv_key, size_t* sig_length) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        return print_crypto_error_return_NULL("Crypto backend not available");
    }

    unsigned char* result = backend->sign_sha256(
        encrypted, encrypted_length, (crypto_pkey_t*)priv_key, sig_length);
    if (!result) {
        return print_crypto_error_return_NULL("SHA256 signing failed");
    }

    return result;
}

int SHA256_verify(const unsigned char* data, unsigned int data_length,
                  unsigned char* sig, size_t sig_length,
                  crypto_pkey_t* pub_key) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        print_crypto_error("Crypto backend not available");
        return -1;
    }

    int result = backend->verify_sha256(data, data_length, sig, sig_length,
                                        (crypto_pkey_t*)pub_key);
    if (result != 0) {
        print_crypto_error("SHA256 verification failed");
        return -1;
    }

    return 0;
}

int digest_message_SHA_256(const unsigned char* data, size_t data_len,
                           unsigned char* md5_hash, unsigned int* md_len) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        print_crypto_error("Crypto backend not available");
        return -1;
    }

    int result = backend->digest_sha256(data, data_len, md5_hash, md_len);
    if (result != 0) {
        print_crypto_error("SHA256 digest failed");
        return -1;
    }

    return 0;
}

int encrypt_AES(const unsigned char* plaintext, unsigned int plaintext_length,
                const unsigned char* key, const unsigned char* iv,
                AES_encryption_mode_t enc_mode, unsigned char* ret,
                unsigned int* ret_length) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        print_crypto_error("Crypto backend not available");
        return -1;
    }

    int result = backend->encrypt_aes(plaintext, plaintext_length, key, iv,
                                      enc_mode, ret, ret_length);
    if (result != 0) {
        print_crypto_error("AES encryption failed");
        return -1;
    }
    return 0;
}

int decrypt_AES(const unsigned char* encrypted, unsigned int encrypted_length,
                const unsigned char* key, const unsigned char* iv,
                AES_encryption_mode_t enc_mode, unsigned char* ret,
                unsigned int* ret_length) {
    const crypto_backend_t* backend = get_crypto_backend();
    if (!backend) {
        print_crypto_error("Crypto backend not available");
        return -1;
    }

    int result = backend->decrypt_aes(encrypted, encrypted_length, key, iv,
                                      enc_mode, ret, ret_length);
    if (result != 0) {
        print_crypto_error("AES decryption failed");
        return -1;
    }

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
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned int expected_encrypted_total_length, unsigned char* ret,
    unsigned int* ret_length) {
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
            const crypto_backend_t* backend = get_crypto_backend();
            if (!backend) {
                SST_print_error("Crypto backend not available.");
                return -1;
            }

            unsigned int hmac_len = 0;
            if (backend->hmac_sha256(mac_key, mac_key_size, ret, total_length,
                                     ret + total_length, &hmac_len) != 0) {
                SST_print_error("HMAC generation failed.");
                return -1;
            }
            total_length += hmac_len;
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
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned int expected_decrypted_total_length, unsigned char* ret,
    unsigned int* ret_length) {
    // The encrypted buffer is composed like below.
    // encrypted = iv (16) + encrypted (plaintext) + HMAC (IV + encrypted)(32)
    unsigned int encrypted_length = buf_length - iv_size;
    if (hmac_mode == USE_HMAC) {
        unsigned char reproduced_tag[mac_key_size];
        encrypted_length -= mac_key_size;
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            const crypto_backend_t* backend = get_crypto_backend();
            if (!backend) {
                SST_print_error("Crypto backend not available.");
                return -1;
            }

            unsigned int hmac_len = 0;
            if (backend->hmac_sha256(mac_key, mac_key_size, buf,
                                     iv_size + encrypted_length, reproduced_tag,
                                     &hmac_len) != 0) {
                SST_print_error("HMAC verification failed.");
                return -1;
            }
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
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char** ret, unsigned int* ret_length) {
    // First, get the expected encrypted length, to assign a buffer size.
    unsigned int expected_encrypted_total_length =
        get_expected_encrypted_total_length(buf_length, iv_size, mac_key_size,
                                            enc_mode, hmac_mode);
    *ret = (unsigned char*)malloc(expected_encrypted_total_length);
    return get_symmetric_encrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_encrypted_total_length, *ret,
        ret_length);
}

int symmetric_decrypt_authenticate(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char** ret, unsigned int* ret_length) {
    unsigned int expected_decrypted_total_length =
        get_expected_decrypted_maximum_length(buf_length, iv_size, mac_key_size,
                                              enc_mode, hmac_mode);
    *ret = (unsigned char*)malloc(expected_decrypted_total_length);
    return get_symmetric_decrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_decrypted_total_length, *ret,
        ret_length);
}

int symmetric_encrypt_authenticate_without_malloc(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char* ret, unsigned int* ret_length) {
    unsigned int expected_encrypted_total_length =
        get_expected_encrypted_total_length(buf_length, iv_size, mac_key_size,
                                            enc_mode, hmac_mode);

    return get_symmetric_encrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_encrypted_total_length, ret,
        ret_length);
}

int symmetric_decrypt_authenticate_without_malloc(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char* ret, unsigned int* ret_length) {
    unsigned int expected_decrypted_total_length =
        get_expected_decrypted_maximum_length(buf_length, iv_size, mac_key_size,
                                              enc_mode, hmac_mode);
    return get_symmetric_decrypt_authenticate_buffer(
        buf, buf_length, mac_key, mac_key_size, cipher_key, cipher_key_size,
        iv_size, enc_mode, hmac_mode, expected_decrypted_total_length, ret,
        ret_length);
}

int create_salted_password_to_32bytes(const char* password,
                                      unsigned int password_len,
                                      const char* salt, unsigned int salt_len,
                                      unsigned char* ret) {
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
