#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Core modules
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C

// Platform specifics for Pico
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_NO_PLATFORM_ENTROPY

// Provide a custom time function to resolve build errors
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_PLATFORM_MS_TIME_ALT

// Disable unnecessary features
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_ERROR_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_TIMING_C


#include "mbedtls/check_config.h"

#endif // MBEDTLS_CONFIG_H