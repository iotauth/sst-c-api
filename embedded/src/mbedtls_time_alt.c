#if defined(MBEDTLS_PLATFORM_MS_TIME_ALT)

#include "pico/time.h"
#include "pico/stdlib.h"

unsigned long mbedtls_ms_time(void) {
    return to_ms_since_boot(get_absolute_time());
}

#endif
