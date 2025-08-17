#pragma once

/* -------- Protocol identity -------- */
#define PROTO_VERSION 1

/* -------- Framing -------- */
#define PREAMBLE_BYTE_1 0xAB
#define PREAMBLE_BYTE_2 0xCD
#define MSG_TYPE_ENCRYPTED 0x02

/* Cooldown to avoid thrashing key updates */
#define KEY_UPDATE_COOLDOWN_S 15

/* -------- Sizes -------- */
#define SESSION_KEY_SIZE 32  // AES-256-GCM (keep in sync with Pico)
#define NONCE_SIZE 12        // 96-bit GCM IV
#define TAG_SIZE 16
#define NONCE_HISTORY_SIZE 64
#define MAX_MSG_LEN 1024

/* -------- Shared tokens -------- */
#define KE_TOKEN_ACK_1 "ACK"
#define KE_TOKEN_ACK_2 "KEY_OK"
#define KE_TOKEN_ACK_3 "I have the key"
#define KE_TOKEN_YES "yes"

/* -------- Serial settings (Linux host only) -------- */
#ifdef __linux__
#define UART_DEVICE "/dev/serial0"
#include <termios.h>
#ifndef UART_BAUDRATE_TERMIOS
#define UART_BAUDRATE_TERMIOS B1000000
#endif
#endif

/* -------- Sanity checks -------- */
#if SESSION_KEY_SIZE != 32
#error "This project assumes a 32-byte session key for AES-256-GCM."
#endif
#if NONCE_SIZE != 12
#error "This project assumes a 12-byte GCM nonce."
#endif
