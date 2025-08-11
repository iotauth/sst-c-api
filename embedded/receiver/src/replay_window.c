// src/replay_window.c
#include <string.h>
#include "replay_window.h"

bool replay_window_seen(const replay_window_t* w, const uint8_t* n) {
  for (size_t i = 0; i < w->cap; ++i)
    if (memcmp(w->buf[i], n, w->nonce_size) == 0) return true;
  return false;
}
void replay_window_add(replay_window_t* w, const uint8_t* n) {
  memcpy(w->buf[w->idx], n, w->nonce_size);
  w->idx = (w->idx + 1) % w->cap;
}
