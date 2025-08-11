// include/key_exchange.h
#pragma once
typedef enum {
  STATE_IDLE,
  STATE_WAITING_FOR_YES,
  STATE_WAITING_FOR_ACK
} receiver_state_t;

static inline int is_ack_token(const char* s) {
  return s && (!strcmp(s, "ACK") || !strcmp(s, "KEY_OK") || !strcmp(s, "I have the key"));
}
