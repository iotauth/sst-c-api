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

#define FLASH_SLOT_SIZE     256
#define FLASH_SLOT_A_OFFSET (PICO_FLASH_SIZE_BYTES - 4096)
#define FLASH_SLOT_B_OFFSET (PICO_FLASH_SIZE_BYTES - 4096 + FLASH_SLOT_SIZE)
#define FLASH_KEY_MAGIC     0x53455353  // 'SESS'

#define FLASH_SLOT_INDEX_OFFSET (PICO_FLASH_SIZE_BYTES - 4096 + 2 * FLASH_SLOT_SIZE)
#define SLOT_INDEX_MAGIC 0xA5

typedef struct {
    uint8_t key[SST_KEY_SIZE];
    uint8_t hash[32];   // SHA-256 hash
    uint32_t magic;
} key_flash_block_t;

void compute_key_hash(const uint8_t *data, size_t len, uint8_t *out_hash) {
    mbedtls_sha256(data, len, out_hash, 0); // 0 = SHA-256, not SHA-224
}

bool validate_flash_block(const key_flash_block_t *block) {
    if (block->magic != FLASH_KEY_MAGIC) return false;

    uint8_t expected_hash[32];
    compute_key_hash(block->key, SST_KEY_SIZE, expected_hash);
    return memcmp(block->hash, expected_hash, 32) == 0;
}

bool read_key_from_slot(uint32_t offset, uint8_t *out) {
    const key_flash_block_t *slot = (const key_flash_block_t *)(XIP_BASE + offset);
    if (validate_flash_block(slot)) {
        memcpy(out, slot->key, SST_KEY_SIZE);
        return true;
    }
    return false;
}

bool write_key_to_slot(uint32_t offset, const uint8_t *key) {
    key_flash_block_t block = {0};
    memcpy(block.key, key, SST_KEY_SIZE);
    compute_key_hash(block.key, SST_KEY_SIZE, block.hash);
    block.magic = FLASH_KEY_MAGIC;

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(offset, FLASH_SLOT_SIZE);
    flash_range_program(offset, (const uint8_t *)&block, sizeof(block));
    restore_interrupts(ints);
    return true;
}

bool load_session_key(uint8_t *out) {
    if (read_key_from_slot(FLASH_SLOT_B_OFFSET, out)) return true;
    if (read_key_from_slot(FLASH_SLOT_A_OFFSET, out)) return true;
    return false;
}

bool store_session_key(const uint8_t *key) {
    // Write to the slot not currently valid
    uint8_t temp[SST_KEY_SIZE];
    if (read_key_from_slot(FLASH_SLOT_A_OFFSET, temp)) {
        return write_key_to_slot(FLASH_SLOT_B_OFFSET, key);
    } else {
        return write_key_to_slot(FLASH_SLOT_A_OFFSET, key);
    }
}

bool erase_all_key_slots() {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_SLOT_A_OFFSET, FLASH_SLOT_SIZE);
    flash_range_erase(FLASH_SLOT_B_OFFSET, FLASH_SLOT_SIZE);
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
// functions to load last used slot index from flash and store it
int load_last_used_slot() {
    const uint8_t *flash_ptr = (const uint8_t *)(XIP_BASE + FLASH_SLOT_INDEX_OFFSET);
    if (flash_ptr[1] == SLOT_INDEX_MAGIC) {
        return flash_ptr[0]; // 0 = A, 1 = B
    }
    return -1; // Invalid
}

void store_last_used_slot(uint8_t slot) {
    uint8_t data[2] = { slot, SLOT_INDEX_MAGIC };
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_SLOT_INDEX_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_SLOT_INDEX_OFFSET, data, sizeof(data));
    restore_interrupts(ints);
}


int main() {
    stdio_init_all();
    sleep_ms(3000); // Wait for USB serial
    int current_slot = 0;  // 0 = A, 1 = B

    if (watchdog_caused_reboot()) {
        printf("Rebooted via watchdog.\n");
    } else {
        printf("Fresh power-on boot.\n");
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

        if (msg_len > sizeof(ciphertext)) {
            printf("Message too long!\n");
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

        if (strncmp(message_buffer, "CMD:", 4) == 0) {
            const char *cmd = message_buffer + 4;
            // In the command handler:
            if (strcmp(cmd, " print key") == 0 || strcmp(cmd, " print key sender") == 0) {
                print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
            } else if (strcmp(cmd, " print key receiver") == 0) {
                printf("Check receiver printed key.\n");
            } else if (strcmp(cmd, " print key *") == 0) {
                print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
                printf("Check receiver printed key.\n");
            } else if (strcmp(cmd, " slot status") == 0) {
                printf("Slot Status:\n");

                // Print current active slot
                if (current_slot == 0) {
                    printf("  Current slot: A\n");
                } else {
                    printf("  Current slot: B\n");
                }

                // Validate Slot A
                uint8_t tmp[SST_KEY_SIZE];
                if (read_key_from_slot(FLASH_SLOT_A_OFFSET, tmp)) {
                    printf("  Slot A: Valid\n");
                } else {
                    printf("  Slot A: Invalid\n");
                }

                // Validate Slot B
                if (read_key_from_slot(FLASH_SLOT_B_OFFSET, tmp)) {
                    printf("  Slot B: Valid\n");
                } else {
                    printf("  Slot B: Invalid\n");
                }
            } else if (strcmp(cmd, " clear slot A") == 0) {
                flash_range_erase(FLASH_SLOT_A_OFFSET, FLASH_SLOT_SIZE);
                printf("Slot A cleared.\n");
            } else if (strcmp(cmd, " clear slot B") == 0) {
                flash_range_erase(FLASH_SLOT_B_OFFSET, FLASH_SLOT_SIZE);
                printf("Slot B cleared.\n");
            } else if (strcmp(cmd, " use slot A") == 0) {
                current_slot = 0;
                store_last_used_slot(current_slot);
                if (read_key_from_slot(FLASH_SLOT_A_OFFSET, session_key)) {
                    print_hex("Using session key from Slot A: ", session_key, SST_KEY_SIZE);
                } else {
                    printf("Slot A is empty or invalid. Ready to receive new key.\n");
                }
            } else if (strcmp(cmd, " use slot B") == 0) {
                current_slot = 1;
                store_last_used_slot(current_slot);
                if (read_key_from_slot(FLASH_SLOT_B_OFFSET, session_key)) {
                    print_hex("Using session key from Slot B: ", session_key, SST_KEY_SIZE);
                } else {
                    printf("Slot B is empty or invalid. Ready to receive new key.\n");
                }
            } else if (strcmp(cmd, " entropy test") == 0) {
                uint8_t entropy_sample[16];
                get_random_bytes(entropy_sample, sizeof(entropy_sample));
                print_hex("Entropy Sample: ", entropy_sample, sizeof(entropy_sample));

            } else if (strcmp(cmd, " new key -f") == 0) {
                printf("Waiting 3 seconds for new key (forced)...\n");
                uint8_t new_key[SST_KEY_SIZE] = {0};
                if (receive_new_key_with_timeout(new_key, 3000)) {
                    print_hex("Received new key: ", new_key, SST_KEY_SIZE);
                    uint32_t offset = current_slot == 0 ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
                    write_key_to_slot(offset, new_key);
                    memcpy(session_key, new_key, SST_KEY_SIZE);
                    printf("New session key forcibly stored in Slot %c.\n", current_slot == 0 ? 'A' : 'B');
                } else {
                    printf("No key received. Aborting.\n");
                }
            } else if (strcmp(cmd, " new key") == 0) {
                uint32_t offset = current_slot == 0 ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
                uint8_t tmp[SST_KEY_SIZE];
                if (read_key_from_slot(offset, tmp)) {
                    printf("Slot %c is already occupied. Use 'new key -f' to overwrite.\n", current_slot == 0 ? 'A' : 'B');
                } else {
                    printf("Waiting 3 seconds for new key...\n");
                    uint8_t new_key[SST_KEY_SIZE] = {0};
                    if (receive_new_key_with_timeout(new_key, 3000)) {
                        print_hex("Received new key: ", new_key, SST_KEY_SIZE);
                        write_key_to_slot(offset, new_key);
                        memcpy(session_key, new_key, SST_KEY_SIZE);
                        printf("New session key stored in Slot %c.\n", current_slot == 0 ? 'A' : 'B');
                    } else {
                        printf("No key received. Aborting.\n");
                    }
                }
            } else if (strcmp(cmd, " print slot A key") == 0) {
                uint8_t tmp[SST_KEY_SIZE];
                if (read_key_from_slot(FLASH_SLOT_A_OFFSET, tmp)) {
                    print_hex("Slot A key: ", tmp, SST_KEY_SIZE);
                } else {
                    printf("Slot A is invalid.\n");
                }
            } else if (strcmp(cmd, " print slot B key") == 0) {
                uint8_t tmp[SST_KEY_SIZE];
                if (read_key_from_slot(FLASH_SLOT_B_OFFSET, tmp)) {
                    print_hex("Slot B key: ", tmp, SST_KEY_SIZE);
                } else {
                    printf("Slot B is invalid.\n");
                }
            } else if (strcmp(cmd, " print slot * key") == 0) {
                uint8_t tmp[SST_KEY_SIZE];
                if (read_key_from_slot(FLASH_SLOT_A_OFFSET, tmp)) {
                    print_hex("Slot A key: ", tmp, SST_KEY_SIZE);
                } else {
                    printf("Slot A is invalid.\n");
                }
                if (read_key_from_slot(FLASH_SLOT_B_OFFSET, tmp)) {
                    print_hex("Slot B key: ", tmp, SST_KEY_SIZE);
                } else {
                    printf("Slot B is invalid.\n");
                }
            } else if (strcmp(cmd, " reboot") == 0) {
                printf("Rebooting...\n");
                sleep_ms(500);
                watchdog_reboot(0, 0, 0);
            } else if (strcmp(cmd, " help") == 0) {
                printf("Available Commands:\n");
                printf("  CMD: print key\n");
                printf("  CMD: print key sender\n");
                printf("  CMD: print key receiver\n");
                printf("  CMD: print key *\n");
                printf("  CMD: print slot key A\n");
                printf("  CMD: print slot key B\n");
                printf("  CMD: print slot key *\n");
                printf("  CMD: clear slot A\n");
                printf("  CMD: clear slot B\n");
                printf("  CMD: clear slot *\n");
                printf("  CMD: use slot A\n");
                printf("  CMD: use slot B\n");
                printf("  CMD: new key         (request new key only if current slot is empty)\n");
                printf("  CMD: new key -f      (force overwrite current slot)\n");
                printf("  CMD: slot status     (show slot validity and active slot)\n");
                printf("  CMD: entropy test    (view entropy sample)\n");
                printf("  CMD: reboot\n");
                printf("  CMD: help\n");
            } else {
                printf("Unknown command. Type CMD: help\n");
            }

        }
    }

    return 0;
}
