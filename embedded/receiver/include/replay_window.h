// include/replay_window.h
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
  uint8_t buf[/*NONCE_HISTORY_SIZE*/ 64][/*NONCE_SIZE*/ 12];
  int idx;
  size_t nonce_size;
  size_t cap;
} replay_window_t;

static inline void replay_window_init(replay_window_t* w, size_t nonce_size, size_t cap) {
  w->idx = 0; w->nonce_size = nonce_size; w->cap = cap;
  for (size_t i = 0; i < cap; ++i)
    for (size_t j = 0; j < nonce_size; ++j) w->buf[i][j] = 0;
}
bool replay_window_seen(const replay_window_t* w, const uint8_t* nonce);
void replay_window_add(replay_window_t* w, const uint8_t* nonce);
