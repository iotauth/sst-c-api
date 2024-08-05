#include <assert.h>

#include "../c_api.h"
#include "../c_crypto.h"
#include <string.h>
#include <stdio.h>


int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    // Request one session key.
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);

    char password[] = "examplepassword";
    char salt[] = "randomsalt";

    save_session_key_list_with_password(s_key_list, "./sessionkey", password, sizeof(password), salt, sizeof(salt));

    // Generate buffer
    unsigned char plaintext[] = "Hello World!";
    printf("Plaintext Length: %ld, Plaintext: %s\n", strlen(plaintext),
           plaintext);
    int s;
    unsigned int encrypted_length;
    unsigned char *encrypted;
    s = symmetric_encrypt_authenticate(
        plaintext, strlen(plaintext), s_key_list->s_key->mac_key, MAC_KEY_SHA256_SIZE, s_key_list->s_key->cipher_key,
        AES_128_KEY_SIZE_IN_BYTES, AES_128_CBC_IV_SIZE, AES_128_CTR, 1,
        &encrypted, &encrypted_length);
    assert(s == 0);
    printf("Cipher Length: %d, Cipher Text: ", encrypted_length);
    print_buf(encrypted, encrypted_length);


    session_key_list_t *new_s_key_list = init_empty_session_key_list();
    load_session_key_list_with_password(new_s_key_list, "./sessionkey", password, sizeof(password), salt, sizeof(salt));
    unsigned int decrypted_length;
    unsigned char *decrypted;
    s = symmetric_decrypt_authenticate(
        encrypted, encrypted_length, new_s_key_list->s_key->mac_key, MAC_KEY_SHA256_SIZE, new_s_key_list->s_key->cipher_key,
        AES_128_KEY_SIZE_IN_BYTES, AES_128_CBC_IV_SIZE, AES_128_CTR, 1,
        &decrypted, &decrypted_length);
    printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
           decrypted);
    assert(s == 0);
    assert(decrypted_length == strlen(plaintext));
    assert(strncmp(decrypted, plaintext, decrypted_length) == 0);
    printf("\n");
    
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}