#ifndef LOCATION_CONTEXT_H
#define LOCATION_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    ZONE_UNKNOWN = 0,
    ZONE_A,
    ZONE_B,
    ZONE_RESTRICTED
} Zone;

typedef struct {
    bool valid;
    Zone zone;
    float x;
    float y;
    uint64_t timestamp;
} LocationContext;


#endif