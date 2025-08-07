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

#include "../../include/sst_crypto_embedded.h"

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

#define FLASH_KEY_OFFSET (PICO_FLASH_SIZE_BYTES - 4096)
#define FLASH_KEY_MAGIC  0x53455353  // 'SESS'

bool load_session_key_from_flash(uint8_t *key_out) {
    const uint8_t *flash_ptr = (const uint8_t *)(XIP_BASE + FLASH_KEY_OFFSET);

    bool all_ff = true;
    for (int i = 0; i < SST_KEY_SIZE; ++i) {
        if (flash_ptr[i] != 0xFF) {
            all_ff = false;
            break;
        }
    }

    if (all_ff || *(uint32_t *)&flash_ptr[16] != FLASH_KEY_MAGIC) {
        return false;
    }

    memcpy(key_out, flash_ptr, SST_KEY_SIZE);
    return true;
}

bool store_session_key_to_flash(const uint8_t *key) {
    uint8_t flash_buf[256] = {0};
    memcpy(&flash_buf[0], key, SST_KEY_SIZE);
    *(uint32_t *)&flash_buf[16] = FLASH_KEY_MAGIC;

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_KEY_OFFSET, 4096);
    flash_range_program(FLASH_KEY_OFFSET, flash_buf, 256);
    restore_interrupts(ints);
    return true;
}

bool erase_session_key_from_flash() {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_KEY_OFFSET, 4096);
    restore_interrupts(ints);
    return true;
}

void zero_key(uint8_t *key) {
    for (int i = 0; i < SST_KEY_SIZE; i++) key[i] = 0;
}

void get_random_bytes(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(get_rand_32() & 0xFF);
    }
}

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

bool receive_new_key_with_timeout(uint8_t *key_out, uint timeout_ms) {
    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    while (absolute_time_diff_us(get_absolute_time(), deadline) > 0) {
        if (uart_is_readable(UART_ID) && uart_getc(UART_ID) == PREAMBLE_BYTE_1) {
            while (!uart_is_readable(UART_ID));
            if (uart_getc(UART_ID) == PREAMBLE_BYTE_2) {
                printf("Receiving new session key...\n");
                size_t received = 0;
                while (received < SST_KEY_SIZE &&
                       absolute_time_diff_us(get_absolute_time(), deadline) > 0) {
                    if (uart_is_readable(UART_ID)) {
                        key_out[received++] = uart_getc(UART_ID);
                    }
                }
                return (received == SST_KEY_SIZE);
            }
        }
    }
    return false;
}

int main() {
    stdio_init_all();
    sleep_ms(3000); // Allow USB serial to connect

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
    bool has_key = load_session_key_from_flash(session_key);

    if (!has_key) {
        printf("No session key found in flash. Waiting to receive one...\n");

        if (receive_new_key_with_timeout(session_key, 10000)) {
            print_hex("Received session key: ", session_key, SST_KEY_SIZE);

            if (store_session_key_to_flash(session_key)) {
                printf("Session key stored to flash.\n");
            } else {
                printf("ERROR: Failed to write session key to flash.\n");
                return 1;
            }
        } else {
            printf("ERROR: Timed out waiting for session key. Cannot continue.\n");
            return 1;
        }
    } else {
        if (watchdog_caused_reboot()) {
            printf("Watchdog reboot. Retaining existing session key.\n");
        } else {
            printf("Fresh boot detected. Loading key from flash.\n");
        }
        print_hex("Using session key: ", session_key, SST_KEY_SIZE);
    }


    char message_buffer[256];

    while (true) {
        printf("Enter a message to send over LiFi:\n");

        size_t msg_len = 0;
        int ch;
        while (1) {
            ch = getchar();
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

        uint8_t nonce[SST_NONCE_SIZE];
        get_random_bytes(nonce, SST_NONCE_SIZE);

        uint8_t ciphertext[256] = {0};
        uint8_t tag[SST_TAG_SIZE] = {0};

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

                if (strncmp(message_buffer, "CMD:", 4) == 0) {
            const char *cmd = message_buffer + 4;

            if (strcmp(cmd, " print key") == 0) {
                print_hex("Current session key: ", session_key, SST_KEY_SIZE);

            } else if (strcmp(cmd, " clear key") == 0) {

                printf("Clearing session key...\n");
                zero_key(session_key);
                if (erase_session_key_from_flash()) {
                    printf("Key cleared from flash and RAM.\n");
                } else {
                    printf("ERROR: Flash is locked. Cannot clear key.\n");
                }

            } else if (strcmp(cmd, " rotate key") == 0) {
                printf("Waiting 3 seconds for new session key...\n");
                uint8_t new_key[SST_KEY_SIZE] = {0};
                if (receive_new_key_with_timeout(new_key, 3000)) {
                    print_hex("Received new key: ", new_key, SST_KEY_SIZE);
                    if (store_session_key_to_flash(new_key)) {
                        memcpy(session_key, new_key, SST_KEY_SIZE);
                        zero_key(new_key);
                        printf("New key stored.\n");
                    } else {
                        printf("ERROR: Failed to write new key to flash.\n");
                    }
                } else {
                    printf("Timeout waiting for new key. Keeping old key.\n");
                    zero_key(new_key);
                }

            } else if (strcmp(cmd, " reboot") == 0) {
                printf("Rebooting...\n");
                sleep_ms(500);
                watchdog_reboot(0, 0, 0);
            } else {
                printf("Unknown command.\n");
            }
        }
    }

    return 0;
}
