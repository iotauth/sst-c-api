#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* === Core crypto modules you use === */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C

/* === Disable unused cipher backends to avoid link errors === */
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_NIST_KW_C
#undef MBEDTLS_CCM_C
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_POLY1305_C
#undef MBEDTLS_CHACHAPOLY_C

/* === Remove modules not needed === */
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_ERROR_C
#undef MBEDTLS_FS_IO

/* === Platform configuration for embedded (Pico) === */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* === Timing override for Pico ===
   MS_TIME_ALT requires MBEDTLS_HAVE_TIME in Mbed TLS 3.x */
#define MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_MS_TIME_ALT


#endif /* MBEDTLS_CONFIG_H */
