#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>

typedef enum {
    ACTION_MOVE = 0,
    ACTION_STOP
} Action;

typedef enum {
    ZONE_UNKNOWN = 0,
    ZONE_A,
    ZONE_B,
    ZONE_RESTRICTED
} Zone;

/*
 * Message sent from the prover/robot to the resource.
 */
typedef struct {
    Action action;
    Zone required_zone;
} ActionRequest;

/*
 * Response sent from the resource back to the prover.
 */
typedef struct {
    bool allowed;
} ActionResponse;

#endif