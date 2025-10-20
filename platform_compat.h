#ifndef SST_PLATFORM_COMPAT_H
#define SST_PLATFORM_COMPAT_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef SST_PLATFORM_PICO
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "pico/time.h"

static inline void sst_platform_sleep_us(uint32_t micros) { sleep_us(micros); }

static inline int sst_inet_pton(int af, const char* src, void* dst) {
    if (af == AF_INET) {
        ip_addr_t addr;
        if (!ipaddr_aton(src, &addr)) {
            return 0;
        }
        *(uint32_t*)dst = ip4_addr_get_u32(ip_2_ip4(&addr));
        return 1;
    }
    return 0;
}

static inline uint64_t sst_platform_now_ms(void) {
    return to_ms_since_boot(get_absolute_time());
}

#else /* !SST_PLATFORM_PICO */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

static inline void sst_platform_sleep_us(uint32_t micros) {
    usleep((useconds_t)micros);
}

static inline int sst_inet_pton(int af, const char* src, void* dst) {
    return inet_pton(af, src, dst);
}

static inline uint64_t sst_platform_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

#endif /* SST_PLATFORM_PICO */

#endif /* SST_PLATFORM_COMPAT_H */
