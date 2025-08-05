#include "mbedtls_time_alt.h"

#include "pico/time.h"

mbedtls_ms_time_t mbedtls_ms_time(void) {
    return to_ms_since_boot(get_absolute_time());
}
