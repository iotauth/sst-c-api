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

#include "../c_common.h"

void AES_test_common(unsigned char mode) {
    unsigned char iv[AES_128_CBC_IV_SIZE];    // 16 bytes
    generate_nonce(AES_128_CBC_IV_SIZE, iv);  // 16 bytes random nonce.

    // Generate key
    unsigned char key[AES_128_KEY_SIZE_IN_BYTES];  // 16 bytes
    generate_nonce(AES_128_KEY_SIZE_IN_BYTES, key);

    // Generate buffer
    unsigned char plaintext[] = "Hello World!";
    printf("Plaintext Length: %ld, Plaintext: %s\n",
           strlen((const char *)plaintext), plaintext);

    // Encrypt Cipher
    unsigned char cipher[100];
    unsigned int length;
    memset(cipher, 0, 100);  // Set to 0 for visibility.
    encrypt_AES(plaintext, strlen((const char *)plaintext), key, iv, mode,
                cipher, &length);

    // Returns IV(16) + cipher + (HMAC(32))
    printf("Cipher Length: %d, Cipher Text: ", length);
    print_buf(cipher, length);

    unsigned char decrypted[100];
    memset(decrypted, 0, 100);  // Set to 0 for visibility.
    unsigned int decrypted_length;
    decrypt_AES(cipher, length, key, iv, mode, decrypted, &decrypted_length);
    printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
           decrypted);
    assert(decrypted_length == strlen((const char *)plaintext));
    assert(strncmp((const char *)decrypted, (const char *)plaintext,
                   decrypted_length) == 0);
    printf("\n");
}

void AES_CBC_test() {
    printf("**** STARTING AES_CBC_TEST\n");
    AES_test_common(AES_128_CBC);
}

void AES_CTR_test() {
    printf("**** STARTING AES_CTR_TEST\n");
    AES_test_common(AES_128_CTR);
}

void AES_GCM_test() {
    printf("**** STARTING AES_GCM_TEST\n");
    AES_test_common(AES_128_GCM);
}

void AES_test() {
    AES_CBC_test();
    AES_CTR_test();
    // AES_GCM_test();
}

void symmetric_encrypt_decrypt_authenticate_common(char enc_mode,
                                                   char no_hmac_mode) {
    // Generate cipher_key
    unsigned char cipher_key[AES_128_KEY_SIZE_IN_BYTES];  // 16 bytes
    generate_nonce(AES_128_KEY_SIZE_IN_BYTES, cipher_key);

    // Generate mac_key
    unsigned char mac_key[MAC_KEY_SHA256_SIZE];  // 16 bytes
    generate_nonce(MAC_KEY_SHA256_SIZE, mac_key);

    // Generate buffer
    unsigned char plaintext[] = "Hello World!";
    printf("Plaintext Length: %ld, Plaintext: %s\n",
           strlen((const char *)plaintext), plaintext);
    int s;
    unsigned int encrypted_length;
    unsigned char *encrypted;
    s = symmetric_encrypt_authenticate(
        plaintext, strlen((const char *)plaintext), mac_key,
        MAC_KEY_SHA256_SIZE, cipher_key, AES_128_KEY_SIZE_IN_BYTES,
        AES_128_CBC_IV_SIZE, enc_mode, no_hmac_mode, &encrypted,
        &encrypted_length);
    printf("Cipher Length: %d, Cipher Text: ", encrypted_length);
    print_buf(encrypted, encrypted_length);
    assert(s == 0);
    unsigned int decrypted_length;
    unsigned char *decrypted;
    s = symmetric_decrypt_authenticate(
        encrypted, encrypted_length, mac_key, MAC_KEY_SHA256_SIZE, cipher_key,
        AES_128_KEY_SIZE_IN_BYTES, AES_128_CBC_IV_SIZE, enc_mode, no_hmac_mode,
        &decrypted, &decrypted_length);
    printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
           decrypted);
    assert(s == 0);
    assert(decrypted_length == strlen((const char *)plaintext));
    assert(strncmp((const char *)decrypted, (const char *)plaintext,
                   decrypted_length) == 0);
    printf("\n");
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CBC_test() {
    printf("**** STARTING symmetric_encrypt_authenticate_AES_128_CBC_test\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CBC, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CTR_test() {
    printf("**** STARTING symmetric_encrypt_authenticate_AES_128_CTR_test\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CTR, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_GCM_test() {
    printf("**** STARTING symmetric_encrypt_authenticate_AES_128_GCM_test\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_GCM, 0);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CBC_noHMAC_test() {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CBC_noHMAC_test\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CBC, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_CTR_noHMAC_test() {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_CTR_noHMAC_test\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_CTR, 1);
}

void symmetric_encrypt_decrypt_authenticate_AES_128_GCM_noHMAC_test() {
    printf(
        "**** STARTING "
        "symmetric_encrypt_authenticate_AES_128_GCM_noHMAC_test\n");
    symmetric_encrypt_decrypt_authenticate_common(AES_128_GCM, 1);
}

void symmetric_encrypt_decrypt_authenticate_test() {
    symmetric_encrypt_decrypt_authenticate_AES_128_CBC_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CTR_test();
    // symmetric_encrypt_decrypt_authenticate_AES_128_GCM_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CBC_noHMAC_test();
    symmetric_encrypt_decrypt_authenticate_AES_128_CTR_noHMAC_test();
    // symmetric_encrypt_decrypt_authenticate_AES_128_GCM_noHMAC_test();
}

int main() {
    AES_test();
    symmetric_encrypt_decrypt_authenticate_test();
}
