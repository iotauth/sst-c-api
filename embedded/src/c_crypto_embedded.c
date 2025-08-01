#define MBEDTLS_MS_TIME_ALT
#include "sst_crypto_embedded.h"
#include "mbedtls/gcm.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "pico/time.h"
#include "pico/stdlib.h"
#include "mbedtls/platform_time.h"

mbedtls_ms_time_t mbedtls_ms_time(void) {
    // Milliseconds since boot (safe on Pico)
    return to_ms_since_boot(get_absolute_time());
}

int sst_encrypt_gcm(
    const uint8_t key[SST_KEY_SIZE],
    const uint8_t nonce[SST_NONCE_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[SST_TAG_SIZE]
) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, SST_KEY_SIZE * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(
        &ctx,
        MBEDTLS_GCM_ENCRYPT,
        plaintext_len,
        nonce, SST_NONCE_SIZE,
        NULL, 0, // No additional authenticated data (AAD)
        plaintext,
        ciphertext,
        SST_TAG_SIZE,
        tag
    );

    mbedtls_gcm_free(&ctx);
    return ret;
}
