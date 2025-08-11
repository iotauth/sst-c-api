// include/protocol.h
#pragma once
#include <termios.h> // for B1000000

#define UART_DEVICE "/dev/serial0"
#define UART_BAUDRATE B1000000

#define SESSION_KEY_SIZE 16
#define NONCE_SIZE       12
#define TAG_SIZE         16

#define PREAMBLE_BYTE_1  0xAB
#define PREAMBLE_BYTE_2  0xCD
#define MSG_TYPE_ENCRYPTED 0x02

#define NONCE_HISTORY_SIZE    64
#define KEY_UPDATE_COOLDOWN_S 15

// Optional sanity checks:
#if SESSION_KEY_SIZE != 16
#error "This receiver assumes a 16-byte session key."
#endif
