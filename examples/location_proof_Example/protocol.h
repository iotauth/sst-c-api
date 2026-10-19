#ifndef PROTOCOL_H
#define PROTOCOL_H
/**
 * Defines message used by the location verification protocol. 
 * Contains the action request and response structures that the Robot and the Resource exchange during location verification.
 */
#include <stdbool.h>

typedef enum { ACTION_MOVE = 0, ACTION_STOP } Action;

typedef enum { ZONE_UNKNOWN = 0, ZONE_A, ZONE_B, ZONE_RESTRICTED } Zone;

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

typedef struct {
    bool requested;
} LocationRequest;

typedef struct {
    double x;
    double y;
} LocationResponse;

#endif
