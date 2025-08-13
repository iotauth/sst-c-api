#include <stdio.h>
#include <string.h>

#include "../../include/sst_crypto_embedded.h"
#include "hardware/gpio.h"
#include "hardware/uart.h"
#include "pico/rand.h"
#include "pico/stdlib.h"

#define UART_ID_DEBUG uart0
#define UART_RX_PIN_DEBUG 1
#define UART_TX_PIN_DEBUG 0

#define UART_ID uart1
#define UART_RX_PIN 5
#define UART_TX_PIN 4

#define BAUD_RATE 1000000
#define PREAMBLE_BYTE_1 0xAA
#define PREAMBLE_BYTE_2 0x55
#define MSG_TYPE_ENCRYPTED 0x02

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

int main() {
    stdio_init_all();
    stdio_usb_init();
    sleep_ms(3000);
    printf("PICO STARTED\n");

    gpio_init(25);
    gpio_set_dir(25, GPIO_OUT);

    uart_init(UART_ID_DEBUG, BAUD_RATE);
    gpio_set_function(UART_TX_PIN_DEBUG, GPIO_FUNC_UART);
    gpio_set_function(UART_RX_PIN_DEBUG, GPIO_FUNC_UART);

    uart_init(UART_ID, BAUD_RATE);
    gpio_set_function(UART_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(UART_RX_PIN, GPIO_FUNC_UART);

    while (uart_is_readable(UART_ID)) {
        volatile uint8_t junk = uart_getc(UART_ID);
    }

    printf("Waiting for preamble...\n");
    while (true) {
        if (uart_is_readable(UART_ID) && uart_getc(UART_ID) == 0xAB) {
            while (!uart_is_readable(UART_ID))
                ;
            if (uart_getc(UART_ID) == 0xCD) {
                printf("Preamble received. Receiving session key...\n");
                break;
            }
        }
    }

    uint8_t session_key[SST_KEY_SIZE];
    size_t received = 0;
    while (received < SST_KEY_SIZE) {
        if (uart_is_readable(UART_ID)) {
            session_key[received++] = uart_getc(UART_ID);
        }
    }
    print_hex("🔑 Received Session Key: ", session_key, SST_KEY_SIZE);

    char message_buffer[256];

    while (true) {
        printf("✏️  Enter a message to send over LiFi:\n");

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

        int ret =
            sst_encrypt_gcm(session_key, nonce, (const uint8_t*)message_buffer,
                            msg_len, ciphertext, tag);

        if (ret != 0) {
            printf("Encryption failed! ret=%d\n", ret);
            continue;
        }

        printf("📤 Sending encrypted frame:\n");
        printf("   Message length: %d\n", msg_len);
        print_hex("   Nonce: ", nonce, SST_NONCE_SIZE);
        print_hex("   Ciphertext: ", ciphertext, msg_len);
        print_hex("   Tag: ", tag, SST_TAG_SIZE);

        uart_putc_raw(UART_ID, PREAMBLE_BYTE_1);
        uart_putc_raw(UART_ID, PREAMBLE_BYTE_2);
        uart_putc_raw(UART_ID, MSG_TYPE_ENCRYPTED);

        uart_write_blocking(UART_ID, nonce, SST_NONCE_SIZE);
        uint8_t len_bytes[2] = {(msg_len >> 8) & 0xFF, msg_len & 0xFF};
        uart_write_blocking(UART_ID, len_bytes, 2);
        uart_write_blocking(UART_ID, ciphertext, msg_len);
        uart_write_blocking(UART_ID, tag, SST_TAG_SIZE);

        printf("Sent!\n\n");

        gpio_put(25, 1);
        sleep_ms(100);
        gpio_put(25, 0);
    }

    return 0;
}
