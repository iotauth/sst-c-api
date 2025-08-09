#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/gpio.h"
#include "hardware/uart.h"
#include "hardware/watchdog.h"
#include "pico/time.h"
#include "pico/stdio_usb.h"
#include "sst_crypto_embedded.h"

#define FLASH_SLOT_A_OFFSET (PICO_FLASH_SIZE_BYTES - 4096)
#define FLASH_SLOT_B_OFFSET (PICO_FLASH_SIZE_BYTES - 4096 + FLASH_SLOT_SIZE)

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
    memset(key, 0, SST_KEY_SIZE);
}

bool is_key_zeroed(const uint8_t *key) {
    for (int i = 0; i < SST_KEY_SIZE; i++) {
        if (key[i] != 0) return false;
    }
    return true;
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