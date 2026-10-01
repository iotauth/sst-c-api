#ifndef SST_CPP_CRYPTO_HPP
#define SST_CPP_CRYPTO_HPP

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <array>
#include <cstddef>
#include <string>

// SST C++ cryptography API.
//
// `Crypto` groups the SST cryptographic primitives (RSA key loading,
// public-key encryption/decryption, SHA-256 digest, RSA sign/verify, AES
// encryption, and symmetric encrypt-then-authenticate). The public entry
// points are static methods; helpers used only internally are private static
// methods.
//
// Design note: NO DYNAMIC ALLOCATION.
// Every routine writes its result into a caller-provided buffer (typically a
// stack std::array at the call site), and all internal temporaries are
// fixed-size stack buffers. No new/malloc/std::vector is used anywhere in this
// module. (EVP_PKEY* key objects are still owned by OpenSSL, which manages its
// own memory internally; the caller frees them with EVP_PKEY_free.)
//
// The crypto routines are stateless, so the public methods are `static`: the
// class is used as a namespace/grouping rather than something to instantiate.
namespace sst {

// ---- Sizes ----
constexpr unsigned int AES_128_KEY_SIZE_IN_BYTES = 16;
constexpr unsigned int AES_128_IV_SIZE = 16;
constexpr unsigned int AES_128_CBC_IV_SIZE = 16;
constexpr unsigned int AES_128_CTR_IV_SIZE = 16;
constexpr unsigned int AES_128_GCM_IV_SIZE = 12;
constexpr unsigned int AES_GCM_TAG_SIZE = 12;
constexpr unsigned int MAX_MAC_KEY_SIZE = 32;
constexpr unsigned int MAC_KEY_SHA256_SIZE = 32;
constexpr unsigned int CIPHER_KEY_SIZE = 16;
constexpr unsigned int RSA_KEY_SIZE = 256;
constexpr unsigned int RSA_ENCRYPT_SIGN_SIZE = RSA_KEY_SIZE * 2;
constexpr unsigned int SHA256_DIGEST_SIZE = 32;
constexpr unsigned int MAX_ERROR_MESSAGE_LENGTH = 128;

// ---- Encryption / HMAC modes ----
// Selects the AES mode used by the encryption routines.
enum AES_encryption_mode_t {
    AES_128_CBC,
    AES_128_CTR,
    AES_128_GCM,
};

// Selects whether the symmetric routines append/verify an HMAC.
enum hmac_mode_t {
    USE_HMAC,
    NO_HMAC,
};

// Holds an RSA-sized data block together with its RSA signature. Both members
// are fixed-size std::array, so a SignedData lives entirely on the stack.
class SignedData {
   public:
    std::array<unsigned char, RSA_KEY_SIZE> data{};
    std::array<unsigned char, RSA_KEY_SIZE> sign{};
};

class Crypto {
   public:
    // ---- Key loading ----

    // Loads Auth's public key (an RSA public key) from an X.509 PEM file.
    // @param path path of Auth's public key.
    // @return owning EVP_PKEY* on success (caller frees with EVP_PKEY_free),
    //         or nullptr on failure.
    static EVP_PKEY* load_auth_public_key(const std::string& path);

    // Loads the entity's private key from a PEM file.
    // @param path path of the entity's private key.
    // @return owning EVP_PKEY* on success (caller frees with EVP_PKEY_free),
    //         or nullptr on failure.
    static EVP_PKEY* load_entity_private_key(const std::string& path);

    // ---- Public key encryption / decryption ----

    // Encrypts a message with an RSA public key, writing into a caller-provided
    // buffer (no allocation).
    // @param data message to encrypt.
    // @param data_len length of the message.
    // @param padding RSA padding mode (e.g. RSA_PKCS1_OAEP_PADDING).
    // @param pub_key public key used for encryption.
    // @param ret caller-provided output buffer (>= EVP_PKEY_size(pub_key),
    //        i.e. RSA_KEY_SIZE for a 2048-bit key).
    // @param ret_len in/out: on input the capacity of `ret`, on output the
    //        ciphertext length.
    // @return 0 on success, -1 on failure.
    static int public_encrypt(const unsigned char* data, size_t data_len,
                              int padding, EVP_PKEY* pub_key,
                              unsigned char* ret, size_t* ret_len);

    // Decrypts a message with an RSA private key, writing into a
    // caller-provided buffer (no allocation).
    // @param enc_data encrypted message.
    // @param enc_data_len length of the encrypted message.
    // @param padding RSA padding mode (must match the encryption padding).
    // @param priv_key private key used for decryption.
    // @param ret caller-provided output buffer (>= EVP_PKEY_size(priv_key)).
    // @param ret_len in/out: on input the capacity of `ret`, on output the
    //        plaintext length.
    // @return 0 on success, -1 on failure.
    static int private_decrypt(const unsigned char* enc_data,
                               size_t enc_data_len, int padding,
                               EVP_PKEY* priv_key, unsigned char* ret,
                               size_t* ret_len);

    // ---- Digital signature ----

    // Digests the message with SHA-256 and signs it with an RSA private key,
    // writing into a caller-provided buffer (no allocation).
    // @param encrypted message to sign.
    // @param encrypted_length length of the message.
    // @param priv_key private key used to sign.
    // @param sig caller-provided output buffer (>= EVP_PKEY_size(priv_key),
    //        i.e. RSA_KEY_SIZE for a 2048-bit key).
    // @param sig_length in/out: on input the capacity of `sig`, on output the
    //        signature length.
    // @return 0 on success, -1 on failure.
    static int sha256_sign(const unsigned char* encrypted,
                           unsigned int encrypted_length, EVP_PKEY* priv_key,
                           unsigned char* sig, size_t* sig_length);

    // Verifies an RSA signature over the SHA-256 digest of the data.
    // @param data signed data.
    // @param data_length length of the data.
    // @param sig signature buffer.
    // @param sig_length length of the signature.
    // @param pub_key public key used to verify.
    // @return 0 on success, -1 on failure.
    static int sha256_verify(const unsigned char* data,
                             unsigned int data_length, const unsigned char* sig,
                             size_t sig_length, EVP_PKEY* pub_key);

    // ---- Hashing ----

    // Computes the SHA-256 digest of the data.
    // @param data data to digest.
    // @param data_len length of the data.
    // @param hash output buffer (>= SHA256_DIGEST_SIZE bytes).
    // @param md_len output digest length.
    // @return 0 on success, -1 on failure.
    static int digest_message_sha256(const unsigned char* data, size_t data_len,
                                     unsigned char* hash, unsigned int* md_len);

    // ---- Raw AES encryption / decryption ----

    // Encrypts plaintext with AES (CBC/CTR/GCM). For GCM the authentication tag
    // is appended to the ciphertext.
    // @param plaintext data to encrypt.
    // @param plaintext_length length of plaintext.
    // @param key AES key.
    // @param iv initialization vector.
    // @param enc_mode AES encryption mode.
    // @param ret output ciphertext buffer (caller-provided).
    // @param ret_length output ciphertext length.
    // @return 0 on success, -1 on failure.
    static int encrypt_aes(const unsigned char* plaintext,
                           unsigned int plaintext_length,
                           const unsigned char* key, const unsigned char* iv,
                           AES_encryption_mode_t enc_mode, unsigned char* ret,
                           unsigned int* ret_length);

    // Decrypts AES ciphertext (CBC/CTR/GCM). For GCM the tag is expected to be
    // appended to the ciphertext.
    // @param encrypted ciphertext.
    // @param encrypted_length length of the ciphertext.
    // @param key AES key.
    // @param iv initialization vector.
    // @param enc_mode AES encryption mode.
    // @param ret output plaintext buffer (caller-provided).
    // @param ret_length output plaintext length.
    // @return 0 on success, -1 on failure.
    static int decrypt_aes(const unsigned char* encrypted,
                           unsigned int encrypted_length,
                           const unsigned char* key, const unsigned char* iv,
                           AES_encryption_mode_t enc_mode, unsigned char* ret,
                           unsigned int* ret_length);

    // ---- Expected length helpers ----
    // Use these to size the caller-provided buffers for the symmetric routines
    // below (e.g. to allocate a stack std::array of the right size).

    // Returns the expected total length of an encrypted buffer
    // (IV + ciphertext + optional HMAC) for the given mode.
    static unsigned int get_expected_encrypted_total_length(
        unsigned int buf_length, unsigned int iv_size,
        unsigned int mac_key_size, AES_encryption_mode_t enc_mode,
        hmac_mode_t hmac_mode);

    // Returns the expected maximum length of a decrypted buffer for the given
    // mode. For block ciphers (CBC) this is an upper bound, not exact.
    static unsigned int get_expected_decrypted_maximum_length(
        unsigned int buf_length, unsigned int iv_size,
        unsigned int mac_key_size, AES_encryption_mode_t enc_mode,
        hmac_mode_t hmac_mode);

    // ---- Symmetric encrypt-then-authenticate (zero allocation) ----
    // The caller provides `ret`, sized via the get_expected_* helpers above
    // (a stack std::array works well).

    // Encrypts then (optionally) HMACs the buffer into `ret`.
    // @return 0 on success, -1 on failure.
    static int symmetric_encrypt_authenticate(
        const unsigned char* buf, unsigned int buf_length,
        const unsigned char* mac_key, unsigned int mac_key_size,
        const unsigned char* cipher_key, unsigned int cipher_key_size,
        unsigned int iv_size, AES_encryption_mode_t enc_mode,
        hmac_mode_t hmac_mode, unsigned char* ret, unsigned int* ret_length);

    // Verifies the (optional) HMAC then decrypts the buffer into `ret`.
    // @return 0 on success, -1 on failure.
    static int symmetric_decrypt_authenticate(
        const unsigned char* buf, unsigned int buf_length,
        const unsigned char* mac_key, unsigned int mac_key_size,
        const unsigned char* cipher_key, unsigned int cipher_key_size,
        unsigned int iv_size, AES_encryption_mode_t enc_mode,
        hmac_mode_t hmac_mode, unsigned char* ret, unsigned int* ret_length);

    // ---- Password salting ----

    // Creates a 32-byte salted password digest (SHA-256 of password || salt).
    // The digest is computed incrementally, so no concatenation buffer is
    // needed.
    // @param password the password to digest.
    // @param salt the salt appended to the password.
    // @param ret caller-provided buffer of at least SHA256_DIGEST_SIZE bytes.
    // @return 0 on success, -1 on failure.
    static int create_salted_password_to_32bytes(const std::string& password,
                                                 const std::string& salt,
                                                 unsigned char* ret);

    // ---- Utility ----
    // Generates `length` cryptographically secure random bytes into `buf`.
    // @return 0 on success, -1 on failure.
    static int generate_nonce(int length, unsigned char* buf);

   private:
    // ---- Internal helpers ----

    // Prints the most recent OpenSSL error to stderr, prefixed with `msg`.
    static void print_crypto_error(const std::string& msg);

    // Maps an AES_encryption_mode_t to the matching OpenSSL EVP_CIPHER,
    // or nullptr if unsupported.
    static const EVP_CIPHER* get_evp_cipher(AES_encryption_mode_t enc_mode);

    // Core of the encrypt-then-authenticate routine, writing into a
    // caller-provided buffer.
    static int get_symmetric_encrypt_authenticate_buffer(
        const unsigned char* buf, unsigned int buf_length,
        const unsigned char* mac_key, unsigned int mac_key_size,
        const unsigned char* cipher_key, unsigned int cipher_key_size,
        unsigned int iv_size, AES_encryption_mode_t enc_mode,
        hmac_mode_t hmac_mode, unsigned int expected_encrypted_total_length,
        unsigned char* ret, unsigned int* ret_length);

    // Core of the verify-then-decrypt routine, writing into a caller-provided
    // buffer.
    static int get_symmetric_decrypt_authenticate_buffer(
        const unsigned char* buf, unsigned int buf_length,
        const unsigned char* mac_key, unsigned int mac_key_size,
        const unsigned char* cipher_key, unsigned int cipher_key_size,
        unsigned int iv_size, AES_encryption_mode_t enc_mode,
        hmac_mode_t hmac_mode, unsigned int expected_decrypted_total_length,
        unsigned char* ret, unsigned int* ret_length);
};

}  // namespace sst

#endif  // SST_CPP_CRYPTO_HPP
