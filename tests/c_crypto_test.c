/**
 * @file c_crypto_test.c
 * @author Dongha Kim
 * @brief Unit test for c_crypto.c
 *
 * This tests encryption and decryption functions from c_crypto.c.
 * 1. encrypt_AES() / decrypt_AES()
 *    Checks with CBC, CTR, GCM encryption modes.
 * 2. symmetric_encrypt_authenticate() / symmetric_decrypt_authenticate()
 *    Checks with CBC, CTR, GCM encryption modes, and with HMAC / no HMAC.
 */

#include "../c_crypto.h"

#include <assert.h>

#include "../c_api.h"
#include "../c_common.h"

#define _unused(x) ((void)(x))  // To avoid unused-but-set-variable error.

void AES_test_common(AES_encryption_mode_t mode) {
    unsigned char iv[AES_128_CBC_IV_SIZE];    // 16 bytes
    generate_nonce(AES_128_CBC_IV_SIZE, iv);  // 16 bytes random nonce.

    // Generate key
    unsigned char key[AES_128_KEY_SIZE_IN_BYTES];  // 16 bytes
    generate_nonce(AES_128_KEY_SIZE_IN_BYTES, key);

    // Generate buffer
    const char plaintext[] = "Hello World!";
    printf("Plaintext Length: %ld, Plaintext: %s\n", strlen(plaintext),
           plaintext);

    // Encrypt Cipher
    unsigned char cipher[100];
    unsigned int length;
    memset(cipher, 0, 100);  // Set to 0 for visibility.
    if (encrypt_AES((const unsigned char *)plaintext, strlen(plaintext), key,
                    iv, mode, cipher, &length) < 0) {
        SST_print_error_exit("Failed encrypt_AES().");
    }

    // Returns IV(16) + cipher + (HMAC(32))
    printf("Cipher Length: %d, Cipher Text: ", length);
    print_buf_log(cipher, length);

    unsigned char decrypted[100];
    memset(decrypted, 0, 100);  // Set to 0 for visibility.
    unsigned int decrypted_length;
    if (decrypt_AES(cipher, length, key, iv, mode, decrypted,
                    &decrypted_length) < 0) {
        SST_print_error_exit("Failed decrypt_AES().");
    }
    printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
           decrypted);
    assert(decrypted_length == strlen(plaintext));
    assert(strncmp((const char *)decrypted, (const char *)plaintext,
                   decrypted_length) == 0);
    printf("\n");
}

void AES_CBC_test(void) {
    printf("**** STARTING AES_CBC_TEST.\n");
    AES_test_common(AES_128_CBC);
}

void AES_CTR_test(void) {
    printf("**** STARTING AES_CTR_TEST.\n");
    AES_test_common(AES_128_CTR);
}

void AES_GCM_test(void) {
    printf("**** STARTING AES_GCM_TEST.\n");
    AES_test_common(AES_128_GCM);
}

void AES_test(void) {
    AES_CBC_test();
    AES_CTR_test();
    AES_GCM_test();
}

void symmetric_encrypt_decrypt_authenticate_common(char enc_mode,
                                                   hmac_mode_t hmac_mode,
                                                   char without_malloc) {
    // Generate cipher_key
    unsigned char cipher_key[AES_128_KEY_SIZE_IN_BYTES];  // 16 bytes
    generate_nonce(AES_128_KEY_SIZE_IN_BYTES, cipher_key);

    // Generate mac_key
    unsigned char mac_key[MAC_KEY_SHA256_SIZE];  // 16 bytes
    generate_nonce(MAC_KEY_SHA256_SIZE, mac_key);

    // Generate buffer
    const char plaintext[] = "Hello World!";
    printf("Plaintext Length: %ld, Plaintext: %s\n", strlen(plaintext),
           plaintext);
    int s;
    _unused(s);
    unsigned int encrypted_length;
    unsigned char *encrypted = NULL;
    unsigned int decrypted_length;
    unsigned char *decrypted = NULL;
    if (!without_malloc) {
        s = symmetric_encrypt_authenticate(
            (const unsigned char *)plaintext, strlen(plaintext), mac_key,
            MAC_KEY_SHA256_SIZE, cipher_key, AES_128_KEY_SIZE_IN_BYTES,
            AES_128_IV_SIZE, enc_mode, hmac_mode, &encrypted,
            &encrypted_length);
        printf("Cipher Length: %d, Cipher Text: ", encrypted_length);
        print_buf_log(encrypted, encrypted_length);
        assert(s == 0);
        s = symmetric_decrypt_authenticate(
            encrypted, encrypted_length, mac_key, MAC_KEY_SHA256_SIZE,
            cipher_key, AES_128_KEY_SIZE_IN_BYTES, AES_128_CBC_IV_SIZE,
            enc_mode, hmac_mode, &decrypted, &decrypted_length);
        printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
               decrypted);
        assert(s == 0);
        assert(decrypted_length == strlen(plaintext));
        assert(strncmp((const char *)decrypted, (const char *)plaintext,
                       decrypted_length) == 0);
        printf("\n");
        free(encrypted);
        free(decrypted);
    } else {
        unsigned int estimate_encrypted_length =
            get_expected_encrypted_total_length(
                strlen(plaintext), AES_128_IV_SIZE, MAC_KEY_SHA256_SIZE,
                enc_mode, hmac_mode);
        unsigned char encrypted_stack[estimate_encrypted_length];
        s = symmetric_encrypt_authenticate_without_malloc(
            (const unsigned char *)plaintext, strlen(plaintext), mac_key,
            MAC_KEY_SHA256_SIZE, cipher_key, AES_128_KEY_SIZE_IN_BYTES,
            AES_128_IV_SIZE, enc_mode, hmac_mode, &encrypted_stack[0],
            &encrypted_length);
        encrypted = &encrypted_stack[0];
        printf("Cipher Length: %d, Cipher Text: ", encrypted_length);
        print_buf_log(encrypted, encrypted_length);
        assert(s == 0);
        unsigned int estimate_decrypted_length =
            get_expected_decrypted_maximum_length(
                encrypted_length, AES_128_IV_SIZE, MAC_KEY_SHA256_SIZE,
                enc_mode, hmac_mode);
        unsigned char decrypted_stack[estimate_decrypted_length];
        s = symmetric_decrypt_authenticate_without_malloc(
            encrypted, encrypted_length, mac_key, MAC_KEY_SHA256_SIZE,
            cipher_key, AES_128_KEY_SIZE_IN_BYTES, AES_128_IV_SIZE, enc_mode,
            hmac_mode, &decrypted_stack[0], &decrypted_length);
        decrypted = &decrypted_stack[0];
        printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
               decrypted);
        assert(s == 0);
        assert(decrypted_length == strlen(plaintext));
        assert(strncmp((const char *)decrypted, (const char *)plaintext,
                       decrypted_length) == 0);
        printf("\n");
    }
}

// These test cases perform encryption, authentication, and decryption using
// different encryption modes (AES-CBC, AES-CTR, AES-GCM) with dynamic memory
// allocation (malloc).

void symmetric_encrypt_decrypt_authenticate_AES_128_CBC_test(void) {
    printf("**** STARTING symmetric_encrypt_authenticate_AES_128_CBC_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CBC, 0, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CTR_test(void) {
    printf("**** STARTING symmetric_encrypt_authenticate_AES_128_CTR_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CTR, 0, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_GCM_test(void) {
    printf("**** STARTING symmetric_encrypt_authenticate_AES_128_GCM_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_GCM, 0, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CBC_noHMAC_test(void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CBC_noHMAC_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CBC, 1, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CTR_noHMAC_test(void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CTR_noHMAC_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CTR, 1, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_GCM_noHMAC_test(void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_GCM_noHMAC_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_GCM, 1, 0);
}

// These test cases perform encryption, authentication, and decryption using
// different encryption modes (AES-CBC, AES-CTR, AES-GCM) without dynamic memory
// allocation.

void symmetric_encrypt_decrypt_authenticate_AES_128_CBC_without_malloc_test(
    void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CBC_without_malloc_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CBC, 0, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CTR_without_malloc_test(
    void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CTR_without_malloc_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CTR, 0, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_GCM_without_malloc_test(
    void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_GCM_without_malloc_test.\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_GCM, 0, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CBC_noHMAC_without_malloc_test(
    void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CBC_noHMAC_without_malloc_test."
        "\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CBC, 1, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CTR_noHMAC_without_malloc_test(
    void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CTR_noHMAC_without_malloc_test."
        "\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CTR, 1, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_GCM_noHMAC_without_malloc_test(
    void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_GCM_noHMAC_without_malloc_test."
        "\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_GCM, 1, 1);
}

// Executes all encryption, authentication, and decryption tests without using
// malloc for buffer allocation. Includes HMAC and no-HMAC cases for AES
// encryption modes: AES-CBC AES-CTR AES-GCM

void symmetric_encrypt_decrypt_authenticate_AES_128_with_malloc_test(void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_with_malloc_tests.\n");
    symmetric_encrypt_decrypt_authenticate_AES_128_CBC_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CTR_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_GCM_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CBC_noHMAC_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CTR_noHMAC_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_GCM_noHMAC_test();
}

void symmetric_encrypt_decrypt_authenticate_AES_128_without_malloc_test(void) {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_without_malloc_tests.\n");
    symmetric_encrypt_decrypt_authenticate_AES_128_CBC_without_malloc_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CTR_without_malloc_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_GCM_without_malloc_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CBC_noHMAC_without_malloc_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CTR_noHMAC_without_malloc_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_GCM_noHMAC_without_malloc_test();
}

void symmetric_encrypt_decrypt_authenticate_test(void) {
    symmetric_encrypt_decrypt_authenticate_AES_128_with_malloc_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_without_malloc_test();
}

int main(void) {
    AES_test();
    symmetric_encrypt_decrypt_authenticate_test();
}
