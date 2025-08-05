#ifndef MBEDTLS_TIME_ALT_H
#define MBEDTLS_TIME_ALT_H

#include "mbedtls/platform_time.h"  // Important: must match mbedtls_ms_time_t

#ifdef __cplusplus
extern "C" {
#endif

mbedtls_ms_time_t mbedtls_ms_time(void);  // Correct signature

#ifdef __cplusplus
}
#endif

#endif  // MBEDTLS_TIME_ALT_H
