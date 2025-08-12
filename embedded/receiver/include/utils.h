// include/utils.h
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef HAVE_EXPLICIT_BZERO
static inline void secure_zero(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t*)p;
  while (n--) *v++ = 0;
}
#define explicit_bzero secure_zero
#endif

void print_hex(const char* label, const uint8_t* data, size_t len);
ssize_t read_exact(int fd, uint8_t* buf, size_t len);
int rand_bytes(uint8_t* buf, size_t len);
