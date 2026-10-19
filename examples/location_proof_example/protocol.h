/**
 * @file protocol.h
 * @brief Defines messages used by the location verification protocol.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <stddef.h>
#include <stdint.h>

#include "../../src/c_api.h"

typedef enum {
    MSG_ACTION_REQUEST = 1,
    MSG_LOCATION_REQUEST = 2,
    MSG_LOCATION_RESPONSE = 3,
    MSG_ACTION_RESPONSE = 4
} MessageType;

typedef enum { ACTION_MOVE = 1 } Action;

typedef struct {
    uint8_t msg_type;
    uint8_t action;
} ActionRequest;

typedef struct {
    uint8_t msg_type;
} LocationRequest;

typedef struct {
    uint8_t msg_type;
    double x;
    double y;
} LocationResponse;

typedef struct {
    uint8_t msg_type;
    uint8_t allowed;
} ActionResponse;

int read_exact_message(SST_session_ctx_t* session_ctx, void* out, size_t len,
                       const char* message_name);

#endif
