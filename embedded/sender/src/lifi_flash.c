#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/gpio.h"
#include "hardware/uart.h"
#include "hardware/flash.h"
#include "hardware/watchdog.h"
#include "hardware/sync.h"
#include "pico/time.h"
#include "pico/bootrom.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "pico/stdio_usb.h"

#include "../../include/sst_crypto_embedded.h"
#include "../../include/pico_handler.h"
#include "../../include/cmd_handler.h"

#define UART_ID_DEBUG uart0
#define UART_RX_PIN_DEBUG 1
#define UART_TX_PIN_DEBUG 0

#define UART_ID uart1
#define UART_RX_PIN 5
#define UART_TX_PIN 4

#define BAUD_RATE 1000000
#define PREAMBLE_BYTE_1 0xAB
#define PREAMBLE_BYTE_2 0xCD
#define MSG_TYPE_ENCRYPTED 0x02

int main() {
    stdio_init_all();
    sleep_ms(3000); // Wait for USB serial

    // Enable watchdog with a 5-second timeout. It will be paused on debug.
    watchdog_enable(5000, 1);

    int current_slot = 0;  // 0 = A, 1 = B

    if (watchdog_caused_reboot() && !stdio_usb_connected()) {
        printf("Rebooted via watchdog.\n");
    } else {
        printf("Fresh power-on boot or reboot via flash.\n");
    }
    //boot with last saved slot
    int saved_slot = load_last_used_slot();
    if (saved_slot == 0 || saved_slot == 1) {
        current_slot = saved_slot;
    } else {
        current_slot = 0; // Default to A if not found
    }

    printf("PICO STARTED\n");

    gpio_init(25);
    gpio_set_dir(25, GPIO_OUT);

    uart_init(UART_ID_DEBUG, BAUD_RATE);
    gpio_set_function(UART_TX_PIN_DEBUG, GPIO_FUNC_UART);
    gpio_set_function(UART_RX_PIN_DEBUG, GPIO_FUNC_UART);

    uart_init(UART_ID, BAUD_RATE);
    gpio_set_function(UART_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(UART_RX_PIN, GPIO_FUNC_UART);

    while (uart_is_readable(UART_ID)) { volatile uint8_t _ = uart_getc(UART_ID); }

    uint8_t session_key[SST_KEY_SIZE] = {0};

    if (!load_session_key(session_key)) {
        printf("No valid session key found. Waiting for one...\n");
        if (receive_new_key_with_timeout(session_key, 10000)) {
            print_hex("Received session key: ", session_key, SST_KEY_SIZE);
            store_session_key(session_key);
            printf("Key saved to flash slot.\n");
        } else {
            printf("Timeout. No session key received. Aborting.\n");
            return 1;
        }
    } else {
        print_hex("Using session key: ", session_key, SST_KEY_SIZE);
    }

    char message_buffer[256];

    while (true) {
        printf("Enter a message to send over LiFi:\n");

        size_t msg_len = 0;
        int ch;
        uint8_t ciphertext[256] = {0};
        uint8_t tag[SST_TAG_SIZE] = {0};

        while (1) {
            ch = getchar_timeout_us(500000); // 0.5 second timeout
            if (ch == PICO_ERROR_TIMEOUT) {
                watchdog_update();
                continue;
            }

            if (ch == '\r' || ch == '\n') {
                message_buffer[msg_len] = '\0';
                putchar('\n');
                break;
            }
            if ((ch == 127 || ch == 8) && msg_len > 0) {
                msg_len--;
                printf("\b \b");
                continue;
            }
            if (msg_len < sizeof(message_buffer) - 1 && ch >= 32 && ch < 127) {
                message_buffer[msg_len++] = ch;
                putchar(ch);
            }
        }

        if (msg_len > sizeof(ciphertext)) {
            printf("Message too long!\n");
            continue;
        }

        if (is_key_zeroed(session_key)) {
            printf("No valid key in the current slot. Cannot send message.\n");
            printf("Use 'CMD: new key' or switch to a valid slot.\n");
            continue;
        }

        uint8_t nonce[SST_NONCE_SIZE];
        get_random_bytes(nonce, SST_NONCE_SIZE);

        int ret = sst_encrypt_gcm(session_key, nonce, (const uint8_t *)message_buffer,
                                  msg_len, ciphertext, tag);
        if (ret != 0) {
            printf("Encryption failed! ret=%d\n", ret);
            continue;
        }

        uart_putc_raw(UART_ID, PREAMBLE_BYTE_1);
        uart_putc_raw(UART_ID, PREAMBLE_BYTE_2);
        uart_putc_raw(UART_ID, MSG_TYPE_ENCRYPTED);
        uart_write_blocking(UART_ID, nonce, SST_NONCE_SIZE);
        uint8_t len_bytes[2] = {(msg_len >> 8) & 0xFF, msg_len & 0xFF};
        uart_write_blocking(UART_ID, len_bytes, 2);
        uart_write_blocking(UART_ID, ciphertext, msg_len);
        uart_write_blocking(UART_ID, tag, SST_TAG_SIZE);

        gpio_put(25, 1);
        sleep_ms(100);
        gpio_put(25, 0);

        // Clear sensitive data from memory
        explicit_bzero(ciphertext, sizeof(ciphertext));
        explicit_bzero(tag, sizeof(tag));
        explicit_bzero(nonce, sizeof(nonce));

        //if trigger command handling
         if (strncmp(message_buffer, "CMD:", 4) == 0) {
            const char *cmd = message_buffer + 4;
            handle_commands(cmd, session_key, &current_slot);
        }
    }

    return 0;
}
