#pragma once

/* -------- Protocol identity -------- */
#define PROTO_VERSION            1

/* -------- Framing -------- */
#define PREAMBLE_BYTE_1          0xAB
#define PREAMBLE_BYTE_2          0xCD
#define MSG_TYPE_ENCRYPTED       0x02

/* -------- Sizes -------- */
#define SESSION_KEY_SIZE         16
#define NONCE_SIZE               12
#define TAG_SIZE                 16
#define NONCE_HISTORY_SIZE       64
#define MAX_MSG_LEN              1024

/* -------- Tokens (shared strings) -------- */
#define KE_TOKEN_ACK_1           "ACK"
#define KE_TOKEN_ACK_2           "KEY_OK"
#define KE_TOKEN_ACK_3           "I have the key"
#define KE_TOKEN_YES             "yes"

/* -------- Serial settings -------- */
#define UART_DEVICE              "/dev/serial0"

#ifdef PICO_ON_DEVICE
  /* Pico SDK wants a numeric baud for uart_init() */
  #define UART_BAUDRATE_NUM      1000000
#else
  /* Host/Linux uses termios constants */
  #include <termios.h>
  #define UART_BAUDRATE_TERMIOS  B1000000
#endif

/* -------- Sanity checks -------- */
#if SESSION_KEY_SIZE != 16
  #error "This project assumes a 16-byte session key."
#endif
#if NONCE_SIZE != 12
  #error "This project assumes a 12-byte GCM nonce."
#endif
