#include "../c_crypto.h"

int main() {
    unsigned char iv[AES_128_CBC_IV_SIZE];    // 16 bytes
    generate_nonce(AES_128_CBC_IV_SIZE, iv);  // 16 bytes random nonce.

    // Generate key
    unsigned char key[AES_128_KEY_SIZE_IN_BYTES];  // 16 bytes
    generate_nonce(AES_128_KEY_SIZE_IN_BYTES, key);

    // Generate buffer
    unsigned char plaintext[] = "Hello World!";
     printf("Plaintext Length: %ld, Plaintext: %s\n", strlen(plaintext), plaintext);

    // CBC
    unsigned char CBC_cipher[100];
    unsigned int CBC_length;
    bzero(CBC_cipher, 100); // Set to 0 for visibility.
    encrypt_AES(plaintext, strlen(plaintext), key, iv, AES_128_CBC, CBC_cipher,
                &CBC_length);

    printf("CBC Cipher Length: %d, CBC Cipher Text: ", CBC_length);
    print_buf(CBC_cipher, CBC_length);

    // CTR
    unsigned char CTR_cipher[100];
    unsigned int CTR_length;
    bzero(CTR_cipher, 100); // Set to 0 for visibility.
    encrypt_AES(plaintext, strlen(plaintext), key, iv, AES_128_CTR, CTR_cipher,
                &CTR_length);
    printf("CTR Cipher Length: %d, CTR Cipher Text: ", CTR_length);
    print_buf(CTR_cipher, CTR_length);
}