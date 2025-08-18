#ifndef C_CRYPTO_H
#define C_CRYPTO_H

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

#include "c_api.h"

#define AES_128_KEY_SIZE_IN_BYTES 16
#define AES_128_IV_SIZE 16
#define AES_128_CBC_IV_SIZE 16
#define AES_128_CTR_IV_SIZE 16
#define AES_128_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 12
#define ABS_VALIDITY_SIZE 6
#define REL_VALIDITY_SIZE 6
#define MAX_MAC_KEY_SIZE 32
#define MAC_KEY_SHA256_SIZE 32
#define CIPHER_KEY_SIZE 16
#define RSA_KEY_SIZE 256
#define RSA_ENCRYPT_SIGN_SIZE RSA_KEY_SIZE * 2
#define SHA256_DIGEST_LENGTH 32

// Encryption Mode //
// #define AES_128_CBC 101
// #define AES_128_CTR 102
// #define AES_128_GCM 103

// Struct for digital signature
typedef struct {
    unsigned char data[RSA_KEY_SIZE];
    unsigned char sign[RSA_KEY_SIZE];
} signed_data_t;

// Loads auth's public key from path
// @param path path of auth's public key
EVP_PKEY *load_auth_public_key(const char *path);

// Loads entity's private key from path
// @param path path of entity's private key
EVP_PKEY *load_entity_private_key(const char *path);

// Encrypt the message with public key using public key encryption from OpenSSL.
// @param data message for public key encryption
// @param data_len length of message
// @param padding set of padding , 1 if padding is used, 0 if not used.
// padding prevents an attacker from knowing the exact length of the plaintext
// message.
// @param path protected key path
// @param ret_len length of encrypted message
// @return encrypted message from public key encryption
unsigned char *public_encrypt(const unsigned char *data, size_t data_len,
                              int padding, EVP_PKEY *pub_key, size_t *ret_len);

// Decrypt message with private key using private key decryption from OpenSSL.
// @param enc_data encrypted message for private key decryption
// @param enc_data_len length of encrypted message
// @param padding set of padding , 1 if padding is used, 0 if not used.
// padding prevents an attacker from knowing the exact length of the plaintext
// message.
// @param path private key path
// @param ret_len length of decrypted message
// @return decrypted message from private key decryption
unsigned char *private_decrypt(const unsigned char *enc_data,
                               size_t enc_data_len, int padding,
                               EVP_PKEY *priv_key, size_t *ret_len);

// After digest the encrypted message, sign digested message
// with private key using private key signature from OpenSSL.
// @param encrypted encrypted message to sign
// @param encrypted_length length of encrypted message
// @param path private key path for private key signature
// @param sig_length length of signed buffer
// @return sign sign of the encrypted message
unsigned char *SHA256_sign(const unsigned char *encrypted,
                           unsigned int encrypted_length, EVP_PKEY *priv_key,
                           size_t *sig_length);

// Verification of encrypted data and signature
// using the RSA verification from OpenSSL.
// @param data encrypted data
// @param data_length length of encrypted data
// @param sign signature buffer
// @param sign_length length of signiture
// @param path public key path
int SHA256_verify(const unsigned char *data, unsigned int data_length,
                  unsigned char *sig, size_t sig_length, EVP_PKEY *pub_key);

// Digest the message using the SHA256 digest function.
// @param data Data to digest
// @param data_len Length of the data to digest
// @param md5_hash The pointer of the digested
// message
// @param md_len The length of the message digest. This cannot be given in a
// integer.
int digest_message_SHA_256(const unsigned char *data, size_t data_len,
                           unsigned char *md5_hash, unsigned int *md_len);

// Encrypt the message with the cipher key of the session key obtained from Auth
// by using Cipher Block Chaining(CBC) encryption of OpenSSL.
// @param plaintext data to encrypt
// @param plaintext_length length of plaintext
// @param key cipher key of session key to be used in CBC encryption
// @param iv initialize vector to be used in first encryption of CBC encryption
// @param ret decrypted message received from CBC encryption
// @param ret_length length of ret
// @return 0 for success, -1 for error.
int encrypt_AES(const unsigned char *plaintext, unsigned int plaintext_length,
                const unsigned char *key, const unsigned char *iv,
                AES_encryption_mode_t enc_mode, unsigned char *ret,
                unsigned int *ret_length);

// Decrypt the message with the cipher key of the session key obtained from Auth
// by using Cipher Block Chaining(CBC) decryption of OpenSSL.
// @param encrypted encrypted data
// @param encrypted_length length of encrypted data
// @param key cipher key of session key to be used in CBC decryption
// @param iv initialize vector to be used in first decryption of CBC decryption
// @param ret decrypted message received from CBC decryption
// @param ret_length length of ret
// @return 0 for success, -1 for error.
int decrypt_AES(const unsigned char *encrypted, unsigned int encrypted_length,
                const unsigned char *key, const unsigned char *iv,
                AES_encryption_mode_t enc_mode, unsigned char *ret,
                unsigned int *ret_length);

// Get the expected encrypted length depnding on encryption modes and
// hmac_mode. Use it together with
// symmetric_encrypt_authenticate_without_malloc() function to not dynamically
// assign memory.
// @param buf_length length of buf
// @param iv_size size of iv(initialize vector)
// @param mac_key_size size of mac key
// @param enc_mode AES encryption mode.
// @param hmac_mode Boolean to use or not use HMAC
// @return expected_encrypted_total_length The expected encrypted length
unsigned int get_expected_encrypted_total_length(unsigned int buf_length,
                                                 unsigned int iv_size,
                                                 unsigned int mac_key_size,
                                                 AES_encryption_mode_t enc_mode,
                                                 hmac_mode_t hmac_mode);

// Get the expected encrypted length depnding on encryption modes and
// hmac_mode. However, for block ciphers such as CBC mode, it cannot get the
// exact decrypted length, only the maximum length. Use it together with
// symmetric_decrypt_authenticate_without_malloc() function to not dynamically
// assign memory.
// @param buf_length length of buf
// @param iv_size size of iv(initialize vector)
// @param mac_key_size size of mac key
// @param enc_mode AES encryption mode.
// @param hmac_mode Boolean to use or not use HMAC
// @return expected_decrypted_maximum_length The expected decrypted length's
// maximum length.
unsigned int get_expected_decrypted_maximum_length(
    unsigned int buf_length, unsigned int iv_size, unsigned int mac_key_size,
    AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode);

// Encrypt the plaintext message with cipher key and optionally make HMAC(Hashed
// Message Authenticate Code) with mac key from session key. This function
// malloc()s a buffer and returns the pointer. So, if the user does not allocate
// memory itself, and rely to the API function, the user must free the buffer
// after use. For not malloc()ing memory, and who want to just assign memory on
// stack, please use symmetric_encrypt_authenticate_without_malloc(). For more
// details, check that function.
// @param buf input message
// @param buf_length length of buf
// @param mac_key mac key of session key to be used in HMAC
// @param mac_key_size size of mac key
// @param cipher_key cipher key of session key to be used in encryption
// @param cipher_key_size size of cipher key
// @param iv_size size of iv(initialize vector)
// @param enc_mode AES encryption mode.
// @param hmac_mode Boolean to use or not use HMAC
// @param ret The double pointer of the result of the encrypted buffer
// @param ret_length length of return buffer
// @return 0 for success, -1 for error.
int symmetric_encrypt_authenticate(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char **ret, unsigned int *ret_length);

// Decrypt the ciphertext with cipher key and optionally make HMAC(Hashed
// Message Authenticate Code) with mac key from session key. This function
// malloc()s a buffer and returns the pointer. So, if the user does not allocate
// memory itself, and rely to the API function, the user must free the buffer
// after use. For not malloc()ing memory, and who want to just assign memory on
// stack, please use symmetric_decrypt_authenticate_without_malloc(). For more
// details, check that function.
// @param buf input message
// @param buf_length length of buf
// @param mac_key mac key of session key to be used in HMAC
// @param mac_key_size size of mac key
// @param cipher_key cipher key of session key to be used in decryption
// @param cipher_key_size size of cipher key
// @param iv_size size of iv(initialize vector)
// @param enc_mode AES encryption mode.
// @param hmac_mode Boolean to use or not use HMAC
// @param ret The double pointer of the result of the encrypted buffer
// @param ret_length length of return buffer
// @return 0 for success, -1 for error.
int symmetric_decrypt_authenticate(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char **ret, unsigned int *ret_length);

// This works similar with the symmetric_encrypt_authenticate() function,
// however does not dynamically assign memory. The ret pointer should have been
// assigned memory. To do this, use the get_expected_encrypted_total_length()
// function to first get the expected memory size, and assign memory.
// @param buf input message
// @param buf_length length of buf
// @param mac_key mac key of session key to be used in HMAC
// @param mac_key_size size of mac key
// @param cipher_key cipher key of session key to be used in encryption
// @param cipher_key_size size of cipher key
// @param iv_size size of iv(initialize vector)
// @param enc_mode AES encryption mode.
// @param hmac_mode Boolean to use or not use HMAC
// @param ret The pointer of the result of the encrypted buffer
// @param ret_length length of return buffer
// @return 0 for success, -1 for error.
int symmetric_encrypt_authenticate_without_malloc(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char *ret, unsigned int *ret_length);

// This works similar with the symmetric_decrypt_authenticate() function,
// however does not dynamically assign memory. The ret pointer should have been
// assigned memory. To do this, use the get_expected_decrypted_maximum_length()
// function to first get the expected memory size, and assign memory.
// @param buf input message
// @param buf_length length of buf
// @param mac_key mac key of session key to be used in HMAC
// @param mac_key_size size of mac key
// @param cipher_key cipher key of session key to be used in decryption
// @param cipher_key_size size of cipher key
// @param iv_size size of iv(initialize vector)
// @param enc_mode AES encryption mode.
// @param hmac_mode Boolean to use or not use HMAC
// @param ret The pointer of the result of the encrypted buffer
// @param ret_length length of return buffer
// @return 0 for success, -1 for error.
int symmetric_decrypt_authenticate_without_malloc(
    const unsigned char *buf, unsigned int buf_length,
    const unsigned char *mac_key, unsigned int mac_key_size,
    const unsigned char *cipher_key, unsigned int cipher_key_size,
    unsigned int iv_size, AES_encryption_mode_t enc_mode, hmac_mode_t hmac_mode,
    unsigned char *ret, unsigned int *ret_length);

// Create a 32 byte digested password using the salt.
// @param password password's pointer
// @param password_len Length of password.
// @param salt Salt string's pointer.
// @param salt_len Length of salt.
// @param ret The pointer assigned by the caller, filled with the digested
// password.
// @return 0 for success, -1 for error.
int create_salted_password_to_32bytes(const char *password,
                                      unsigned int password_len,
                                      const char *salt, unsigned int salt_len,
                                      unsigned char *ret);

#endif  // C_CRYPTO_H
