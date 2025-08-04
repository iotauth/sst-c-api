#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// === Core crypto modules ===
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C

// === Platform configuration for embedded (Pico) ===
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_NO_PLATFORM_ENTROPY

// === Platform zeroization === use default
#undef MBEDTLS_PLATFORM_ZEROIZE_ALT

// === Timing and time-related features === not used yet
#undef MBEDTLS_TIMING_C
//for my own timing override
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_PLATFORM_TIME_ALT

// === Unused or unnecessary features ===
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_ERROR_C
#undef MBEDTLS_FS_IO

// === Check config consistency ===
#include "mbedtls/check_config.h"

#endif // MBEDTLS_CONFIG_H
