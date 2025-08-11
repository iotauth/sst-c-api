#include "hardware/sync.h"
#include "hardware/flash.h"
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/gpio.h"
#include "hardware/uart.h"
#include "hardware/watchdog.h"
#include "pico/time.h"
#include "pico/bootrom.h"
#include "pico/stdio_usb.h"
#include <stdio.h>
#include "mbedtls/sha256.h"
#include "sst_crypto_embedded.h"
#include "ram_handler.h"
#include "config_handler.h"
#include "pico_handler.h"

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

//add fix without breaking old logic
#define SLOT_A_SECTOR_OFFSET (PICO_FLASH_SIZE_BYTES - 2*FLASH_SECTOR_SIZE) // 4KB aligned
#define SLOT_B_SECTOR_OFFSET (PICO_FLASH_SIZE_BYTES - 1*FLASH_SECTOR_SIZE) // 4KB aligned

static uint8_t g_session_key[SST_KEY_SIZE];
static bool g_key_valid = false;

static inline uint32_t slot_to_sector_offset(int slot) {
    return (slot == 0) ? SLOT_A_SECTOR_OFFSET : SLOT_B_SECTOR_OFFSET;
}
//CORRECTLY LINKING
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
    flash_range_erase(offset, FLASH_SECTOR_SIZE);
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

bool receive_new_key_with_timeout(uint8_t *key_out, uint32_t timeout_ms) {
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


void pico_reboot(void) {
    watchdog_reboot(0, 0, 0);
}

void pico_print_slot_status(int current_slot) {
    printf("Slot Status:\n");
    printf("  Current slot: %c\n", current_slot == 0 ? 'A' : 'B');
    uint8_t tmp[SST_KEY_SIZE];
    if (read_key_from_slot(FLASH_SLOT_A_OFFSET, tmp)) {
        printf("  Slot A: Valid\n");
    } else {
        printf("  Slot A: Invalid\n");
    }
    if (read_key_from_slot(FLASH_SLOT_B_OFFSET, tmp)) {
        printf("  Slot B: Valid\n");
    } else {
        printf("  Slot B: Invalid\n");
    }
}

void pico_clear_slot(int slot) {
    uint32_t offset = (slot == 0) ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(offset, FLASH_SLOT_SIZE);
    restore_interrupts(ints);
}

bool pico_clear_slot_verify(int slot) {
    if (slot != 0 && slot != 1) return false; //slot A or B
    const uint32_t sector_off = slot_to_sector_offset(slot);
 
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(sector_off, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);

    // Verify erased (XIP readback)
    const uint8_t *p = (const uint8_t *)(XIP_BASE + sector_off);
    for (size_t i = 0; i < FLASH_SECTOR_SIZE; i++) {
        if (p[i] != 0xFF) return false;
    }
    return true;
}

bool pico_read_key_from_slot(int slot, uint8_t *out) {
    uint32_t offset = (slot == 0) ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
    return read_key_from_slot(offset, out);
}

bool pico_write_key_to_slot(int slot, const uint8_t *key) {
    uint32_t offset = (slot == 0) ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
    return write_key_to_slot(offset, key);
}

void pico_print_key_from_slot(int slot) {
    uint8_t tmp[SST_KEY_SIZE];
    if (pico_read_key_from_slot(slot, tmp)) {
        char label[20];
        sprintf(label, "Slot %c key: ", slot == 0 ? 'A' : 'B');
        print_hex(label, tmp, SST_KEY_SIZE);
    } else {
        printf("Slot %c is invalid.\n", slot == 0 ? 'A' : 'B');
    }
}

bool keyram_valid(void) {
    return g_key_valid;
}

void keyram_set(const uint8_t *k) {
    memcpy(g_session_key, k, SST_KEY_SIZE);
    g_key_valid = true;
}

const uint8_t* keyram_get(void) {
    return g_key_valid ? g_session_key : NULL;
}

void keyram_clear(void) {
    volatile uint8_t *p = g_session_key;
    for (size_t i = 0; i < SST_KEY_SIZE; i++) p[i] = 0;
    g_key_valid = false;
}