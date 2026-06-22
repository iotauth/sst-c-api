#include "crypto.hpp"

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

namespace sst {

// ---- Internal helpers (private) ----

void Crypto::print_crypto_error(const std::string& msg) {
    std::string err(MAX_ERROR_MESSAGE_LENGTH, '\0');
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err.data());
    std::fprintf(stderr, "%s ERROR: %s\n", msg.c_str(), err.c_str());
}

const EVP_CIPHER* Crypto::get_evp_cipher(AES_encryption_mode_t enc_mode) {
    if (enc_mode == AES_128_CBC) {
        return EVP_aes_128_cbc();
    } else if (enc_mode == AES_128_CTR) {
        return EVP_aes_128_ctr();
    } else if (enc_mode == AES_128_GCM) {
        return EVP_aes_128_gcm();
    } else {
        std::fprintf(stderr, "ERROR: Encryption type not supported.\n");
    }
    return nullptr;
}

// ---- Utility ----

int Crypto::generate_nonce(int length, unsigned char* buf) {
    if (RAND_bytes(buf, length) != 1) {
        print_crypto_error("Failed to create Random Nonce");
        return -1;
    }
    return 0;
}

// ---- Key loading ----

EVP_PKEY* Crypto::load_auth_public_key(const std::string& path) {
    FILE* pem_file = std::fopen(path.c_str(), "rb");
    if (pem_file == nullptr) {
        std::fprintf(stderr, "Error %d \n", errno);
        print_crypto_error("Loading auth_pub_key_path failed");
        return nullptr;
    }
    X509* cert = PEM_read_X509(pem_file, nullptr, nullptr, nullptr);
    std::fclose(pem_file);
    if (cert == nullptr) {
        print_crypto_error("Reading X509 certificate failed");
        return nullptr;
    }
    EVP_PKEY* pub_key = X509_get_pubkey(cert);
    X509_free(cert);
    if (pub_key == nullptr) {
        print_crypto_error("public key getting fail");
        return nullptr;
    }
    if (EVP_PKEY_id(pub_key) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pub_key);
        print_crypto_error("is not RSA Encryption file");
        return nullptr;
    }
    return pub_key;
}

EVP_PKEY* Crypto::load_entity_private_key(const std::string& path) {
    FILE* keyfile = std::fopen(path.c_str(), "rb");
    if (keyfile == nullptr) {
        std::fprintf(stderr, "Error %d \n", errno);
        print_crypto_error("Loading entity_priv_key_path failed");
        return nullptr;
    }
    EVP_PKEY* priv_key =
        PEM_read_PrivateKey(keyfile, nullptr, nullptr, nullptr);
    std::fclose(keyfile);
    return priv_key;
}

// ---- Public key encryption / decryption ----

int Crypto::public_encrypt(const unsigned char* data, size_t data_len,
                           int padding, EVP_PKEY* pub_key, unsigned char* ret,
                           size_t* ret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) {
        print_crypto_error("EVP_PKEY_CTX_new failed");
        return -1;
    }
    int result = -1;
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        print_crypto_error("EVP_PKEY_encrypt_init failed");
    } else if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_rsa_padding failed");
    } else if (EVP_PKEY_encrypt(ctx, ret, ret_len, data, data_len) <= 0) {
        print_crypto_error("EVP_PKEY_encrypt failed");
    } else {
        result = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return result;
}

int Crypto::private_decrypt(const unsigned char* enc_data, size_t enc_data_len,
                            int padding, EVP_PKEY* priv_key, unsigned char* ret,
                            size_t* ret_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) {
        print_crypto_error("EVP_PKEY_CTX_new failed");
        return -1;
    }
    int result = -1;
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        print_crypto_error("EVP_PKEY_decrypt_init failed");
    } else if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_rsa_padding failed");
    } else if (EVP_PKEY_decrypt(ctx, ret, ret_len, enc_data, enc_data_len) <=
               0) {
        print_crypto_error("EVP_PKEY_decrypt failed");
    } else {
        result = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// ---- Digital signature ----

int Crypto::sha256_sign(const unsigned char* encrypted,
                        unsigned int encrypted_length, EVP_PKEY* priv_key,
                        unsigned char* sig, size_t* sig_length) {
    unsigned char md[SHA256_DIGEST_SIZE];
    unsigned int md_length;
    if (digest_message_sha256(encrypted, encrypted_length, md, &md_length) <
        0) {
        print_crypto_error("Failed digest_message_sha256().");
        return -1;
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) {
        print_crypto_error("EVP_PKEY_CTX_new failed");
        return -1;
    }
    int result = -1;
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        print_crypto_error("EVP_PKEY_sign_init failed");
    } else if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_rsa_padding failed");
    } else if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_signature_md failed");
    } else if (EVP_PKEY_sign(ctx, sig, sig_length, md, md_length) <= 0) {
        print_crypto_error("EVP_PKEY_sign failed");
    } else {
        result = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return result;
}

int Crypto::sha256_verify(const unsigned char* data, unsigned int data_length,
                          const unsigned char* sig, size_t sig_length,
                          EVP_PKEY* pub_key) {
    unsigned char md[SHA256_DIGEST_SIZE];
    unsigned int md_len;
    if (digest_message_sha256(data, data_length, md, &md_len) < 0) {
        print_crypto_error("Failed digest_message_sha256().");
        return -1;
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) {
        print_crypto_error("EVP_PKEY_CTX_new failed");
        return -1;
    }
    int ret = -1;
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        print_crypto_error("EVP_PKEY_verify_init failed");
    } else if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_rsa_padding failed");
    } else if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        print_crypto_error("EVP_PKEY_CTX_set_signature_md failed");
    } else if (EVP_PKEY_verify(ctx, sig, sig_length, md, md_len) != 1) {
        print_crypto_error("EVP_PKEY_verify failed");
    } else {
        ret = 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

// ---- Hashing ----

int Crypto::digest_message_sha256(const unsigned char* data, size_t data_len,
                                  unsigned char* hash, unsigned int* md_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr) {
        print_crypto_error("EVP_MD_CTX_create() failed");
        return -1;
    }
    int ret = -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        print_crypto_error("EVP_DigestInit_ex failed");
    } else if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        print_crypto_error("EVP_DigestUpdate failed");
    } else if (EVP_DigestFinal_ex(mdctx, hash, md_len) != 1) {
        print_crypto_error("EVP_DigestFinal_ex failed");
    } else {
        ret = 0;
    }
    EVP_MD_CTX_destroy(mdctx);
    return ret;
}

// ---- Raw AES encryption / decryption ----

int Crypto::encrypt_aes(const unsigned char* plaintext,
                        unsigned int plaintext_length, const unsigned char* key,
                        const unsigned char* iv,
                        AES_encryption_mode_t enc_mode, unsigned char* ret,
                        unsigned int* ret_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_crypto_error("EVP_CIPHER_CTX_new failed");
        return -1;
    }
    if (!EVP_EncryptInit_ex(ctx, get_evp_cipher(enc_mode), nullptr, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_EncryptInit_ex failed");
        return -1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE, nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
            return -1;
        }
    }

    if (!EVP_EncryptUpdate(ctx, ret, reinterpret_cast<int*>(ret_length),
                           plaintext, plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_EncryptUpdate failed");
        return -1;
    }

    int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ret + *ret_length, &temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_EncryptFinal_ex failed");
        return -1;
    }
    *ret_length += temp_len;

    if (enc_mode == AES_128_GCM) {
        // Append the GCM authentication tag to the end of the ciphertext.
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE,
                                 ret + *ret_length)) {
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
            return -1;
        }
        *ret_length += AES_GCM_TAG_SIZE;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int Crypto::decrypt_aes(const unsigned char* encrypted,
                        unsigned int encrypted_length, const unsigned char* key,
                        const unsigned char* iv,
                        AES_encryption_mode_t enc_mode, unsigned char* ret,
                        unsigned int* ret_length) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_crypto_error("EVP_CIPHER_CTX_new failed");
        return -1;
    }
    if (!EVP_DecryptInit_ex(ctx, get_evp_cipher(enc_mode), nullptr, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_DecryptInit_ex failed");
        return -1;
    }

    if (enc_mode == AES_128_GCM) {
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 AES_128_GCM_IV_SIZE, nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
            return -1;
        }
        // The last AES_GCM_TAG_SIZE bytes of the ciphertext hold the tag.
        unsigned char* tag = const_cast<unsigned char*>(encrypted) +
                             encrypted_length - AES_GCM_TAG_SIZE;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                                 tag)) {
            EVP_CIPHER_CTX_free(ctx);
            print_crypto_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
            return -1;
        }
        encrypted_length -= AES_GCM_TAG_SIZE;
    }

    if (!EVP_DecryptUpdate(ctx, ret, reinterpret_cast<int*>(ret_length),
                           encrypted, encrypted_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_DecryptUpdate failed");
        return -1;
    }

    int temp_len;
    if (!EVP_DecryptFinal_ex(ctx, ret + *ret_length, &temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_crypto_error("EVP_DecryptFinal_ex failed");
        return -1;
    }
    *ret_length += temp_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// ---- Expected length helpers ----

unsigned int Crypto::get_expected_encrypted_total_length(
    unsigned int buf_length, unsigned int iv_size, unsigned int mac_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode) {
    unsigned int encrypted_total_length = 0;
    if (enc_mode == AES_128_CBC) {
        // CBC pads up to a multiple of the block size.
        encrypted_total_length = ((buf_length / iv_size) + 1) * iv_size;
    } else if (enc_mode == AES_128_CTR) {
        encrypted_total_length = buf_length;
    } else if (enc_mode == AES_128_GCM) {
        encrypted_total_length = buf_length + AES_GCM_TAG_SIZE;
    }
    if (hmac_mode == USE_HMAC) {
        encrypted_total_length = iv_size + encrypted_total_length + mac_key_size;
    } else {
        encrypted_total_length = iv_size + encrypted_total_length;
    }
    return encrypted_total_length;
}

unsigned int Crypto::get_expected_decrypted_maximum_length(
    unsigned int buf_length, unsigned int iv_size, unsigned int mac_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode) {
    // First remove the IV length attached at the front.
    unsigned int decrypted_maximum_length = buf_length - iv_size;
    if (hmac_mode == USE_HMAC) {
        decrypted_maximum_length -= mac_key_size;
    }
    if (enc_mode == AES_128_CBC) {
        decrypted_maximum_length = decrypted_maximum_length / iv_size * iv_size;
    } else if (enc_mode == AES_128_CTR) {
        // Same as plaintext on CTR mode.
    } else if (enc_mode == AES_128_GCM) {
        decrypted_maximum_length = decrypted_maximum_length - AES_GCM_TAG_SIZE;
    }
    return decrypted_maximum_length;
}

// ---- Symmetric encrypt-then-authenticate buffer helpers (private) ----

int Crypto::get_symmetric_encrypt_authenticate_buffer(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned int expected_encrypted_total_length, unsigned char* ret,
    unsigned int* ret_length) {
    // ret = IV (16) + encrypted(IV+buf) + (optional) HMAC(IV + encrypted) (32)
    if (generate_nonce(iv_size, ret) < 0) {
        std::fprintf(stderr, "ERROR: Failed generate_nonce().\n");
        return -1;
    }
    unsigned int total_length = 0;
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (encrypt_aes(buf, buf_length, cipher_key, ret, enc_mode,
                        ret + iv_size, &total_length) < 0) {
            std::fprintf(stderr, "ERROR: AES encryption failed!\n");
            return -1;
        }
        total_length += iv_size;
    } else {
        std::fprintf(stderr, "ERROR: Cipher_key_size is not supported.\n");
        return -1;
    }
    if (hmac_mode == USE_HMAC) {
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            unsigned int hmac_len = mac_key_size;
            HMAC(EVP_sha256(), mac_key, mac_key_size, ret, total_length,
                 ret + total_length, &hmac_len);
            total_length += hmac_len;
        } else {
            std::fprintf(stderr, "ERROR: HMAC_key_size is not supported.\n");
            return -1;
        }
    }
    if (expected_encrypted_total_length != total_length) {
        std::fprintf(stderr,
                     "ERROR: Encrypted length does not match with expected.\n");
        return -1;
    }
    *ret_length = total_length;
    return 0;
}

int Crypto::get_symmetric_decrypt_authenticate_buffer(
    const unsigned char* buf, unsigned int buf_length,
    const unsigned char* mac_key, unsigned int mac_key_size,
    const unsigned char* cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned int expected_decrypted_total_length, unsigned char* ret,
    unsigned int* ret_length) {
    // encrypted = iv (16) + encrypted (plaintext) + HMAC (IV + encrypted)(32)
    unsigned int encrypted_length = buf_length - iv_size;
    if (hmac_mode == USE_HMAC) {
        // Fixed-size stack buffer (no allocation); HMAC-SHA256 fits in 32 B.
        std::array<unsigned char, MAX_MAC_KEY_SIZE> reproduced_tag{};
        encrypted_length -= mac_key_size;
        if (mac_key_size == MAC_KEY_SHA256_SIZE) {
            unsigned int hmac_len = mac_key_size;
            HMAC(EVP_sha256(), mac_key, mac_key_size, buf,
                 iv_size + encrypted_length, reproduced_tag.data(), &hmac_len);
        } else {
            std::fprintf(stderr, "ERROR: HMAC_key_size is not supported.\n");
            return -1;
        }
        if (std::memcmp(reproduced_tag.data(),
                        buf + iv_size + encrypted_length, mac_key_size) != 0) {
            std::fprintf(stderr, "ERROR: HMAC tag does not match.\n");
            return -1;
        }
    }
    if (cipher_key_size == AES_128_KEY_SIZE_IN_BYTES) {
        if (decrypt_aes(buf + iv_size, encrypted_length, cipher_key, buf,
                        enc_mode, ret, ret_length) < 0) {
            std::fprintf(stderr, "ERROR: AES decrypt failed!\n");
            return -1;
        }
        if (expected_decrypted_total_length != *ret_length) {
            if (enc_mode == AES_128_CBC &&
                expected_decrypted_total_length > *ret_length) {
                // Fine: the exact decrypted length of a block cipher (CBC) is
                // only known after decryption; the estimate is an upper bound.
            } else {
                std::fprintf(
                    stderr,
                    "ERROR: Decrypted length does not match with expected.\n");
                return -1;
            }
        }
    } else {
        std::fprintf(stderr, "ERROR: Cipher_key_size is not supported.\n");
        return -1;
    }
    return 0;
}

// ---- Symmetric encrypt-then-authenticate (public, zero allocation) ----

int Crypto::symmetric_encrypt_authenticate(
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

int Crypto::symmetric_decrypt_authenticate(
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

// ---- Password salting ----

int Crypto::create_salted_password_to_32bytes(const std::string& password,
                                              const std::string& salt,
                                              unsigned char* ret) {
    // Digest password || salt incrementally so no concatenation buffer (and no
    // allocation) is needed. std::string::size() already excludes the trailing
    // NUL, so the whole string is digested.
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr) {
        print_crypto_error("EVP_MD_CTX_create() failed");
        return -1;
    }
    unsigned int md_len;
    int ret_code = -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        print_crypto_error("EVP_DigestInit_ex failed");
    } else if (EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        print_crypto_error("EVP_DigestUpdate (password) failed");
    } else if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1) {
        print_crypto_error("EVP_DigestUpdate (salt) failed");
    } else if (EVP_DigestFinal_ex(mdctx, ret, &md_len) != 1) {
        print_crypto_error("EVP_DigestFinal_ex failed");
    } else {
        ret_code = 0;
    }
    EVP_MD_CTX_destroy(mdctx);
    return ret_code;
}

}  // namespace sst
