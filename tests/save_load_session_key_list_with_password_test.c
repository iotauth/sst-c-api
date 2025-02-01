/**
 *  This test mainly tests save_session_key_list_with_password() and
 * load_session_key_list_with_password(). It gets a session key, saves it,
 * encrypts a string, load the saved key, and decrypts the string.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../c_api.h"
#include "../c_common.h"
#include "../c_crypto.h"

int main(int argc, char *argv[]) {
    // Just to pass compiler warnings.
    (void)argc;
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    // Request one session key.
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);

    const char password[] = "examplepassword";
    const char salt[] = "randomsalt";

    // Save the session key list with a password, and salt it.
    save_session_key_list_with_password(s_key_list, "./sessionkey", password,
                                        sizeof(password), salt, sizeof(salt));

    // Generate buffer
    unsigned char plaintext[] =
        "Testing save_session_key_list_with_password().";
    printf("Plaintext Length: %ld, Plaintext: %s\n",
           strlen((const char *)plaintext), plaintext);
    int ret;
    unsigned int encrypted_length;
    unsigned char *encrypted = NULL;
    ret = symmetric_encrypt_authenticate(
        plaintext, strlen((const char *)plaintext), s_key_list->s_key->mac_key,
        MAC_KEY_SHA256_SIZE, s_key_list->s_key->cipher_key,
        AES_128_KEY_SIZE_IN_BYTES, AES_128_CBC_IV_SIZE, AES_128_CTR, 1,
        &encrypted, &encrypted_length);
    assert(ret == 0);
    printf("Cipher Length: %d, Cipher Text: ", encrypted_length);
    print_buf(encrypted, encrypted_length);

    session_key_list_t *new_s_key_list = init_empty_session_key_list();

    // Test to load the saved session key using the password.
    load_session_key_list_with_password(new_s_key_list, "./sessionkey",
                                        password, sizeof(password), salt,
                                        sizeof(salt));
    unsigned int decrypted_length;
    unsigned char *decrypted = NULL;
    ret = symmetric_decrypt_authenticate(
        encrypted, encrypted_length, new_s_key_list->s_key->mac_key,
        MAC_KEY_SHA256_SIZE, new_s_key_list->s_key->cipher_key,
        AES_128_KEY_SIZE_IN_BYTES, AES_128_CBC_IV_SIZE, AES_128_CTR, 1,
        &decrypted, &decrypted_length);
    printf("Decrypted Length: %d, Decrypted: %s\n", decrypted_length,
           decrypted);
    assert(ret == 0);
    assert(decrypted_length == strlen((const char *)plaintext));
    assert(strncmp((const char *)decrypted, (const char *)plaintext,
                   decrypted_length) == 0);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);
}
