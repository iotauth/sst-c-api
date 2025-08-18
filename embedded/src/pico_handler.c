#include "pico_handler.h"

#include <stdio.h>
#include <string.h>

#include "config_handler.h"
#include "hardware/flash.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/uart.h"
#include "hardware/watchdog.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "pico/bootrom.h"
#include "pico/rand.h"
#include "pico/stdio_usb.h"
#include "pico/stdlib.h"
#include "pico/time.h"
#include "sst_crypto_embedded.h"

#define UART_ID_DEBUG uart0
#define UART_RX_PIN_DEBUG 1
#define UART_TX_PIN_DEBUG 0

#define UART_ID uart1
#define UART_RX_PIN 5
#define UART_TX_PIN 4

#define PREAMBLE_BYTE_1 0xAB
#define PREAMBLE_BYTE_2 0xCD

// --- Nonce parameters (12-byte GCM IV) ---
#define GCM_IV_LEN 12
#define NONCE_SALT_LEN 8
#define NONCE_COUNTER_LEN 4
_Static_assert(GCM_IV_LEN == NONCE_SALT_LEN + NONCE_COUNTER_LEN, "IV layout");

// Nonce state
static uint8_t g_boot_salt[NONCE_SALT_LEN];
static uint32_t g_msg_counter = 0;

#define FLASH_SLOT_SIZE 256
#define FLASH_KEY_MAGIC 0x53455353  // 'SESS'
#define SLOT_INDEX_MAGIC 0xA5

// 4KB-aligned sector bases
#define SLOT_A_SECTOR_OFFSET (PICO_FLASH_SIZE_BYTES - 3 * FLASH_SECTOR_SIZE)
#define SLOT_B_SECTOR_OFFSET (PICO_FLASH_SIZE_BYTES - 2 * FLASH_SECTOR_SIZE)
#define INDEX_SECTOR_OFFSET (PICO_FLASH_SIZE_BYTES - 1 * FLASH_SECTOR_SIZE)

// Store the 256B block at the start of each sector
#define FLASH_SLOT_A_OFFSET (SLOT_A_SECTOR_OFFSET)
#define FLASH_SLOT_B_OFFSET (SLOT_B_SECTOR_OFFSET)

// Put your 2-byte slot index (or other metadata) at the start of the index
// sector
#define FLASH_SLOT_INDEX_OFFSET (INDEX_SECTOR_OFFSET)

// Helpers
#define SLOT_SECTOR_OFFSET(slot) \
    ((slot) == 0 ? SLOT_A_SECTOR_OFFSET : SLOT_B_SECTOR_OFFSET)
#define SLOT_DATA_OFFSET(slot) SLOT_SECTOR_OFFSET(slot)

static uint8_t g_session_key[SST_KEY_SIZE];
static bool g_key_valid = false;

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static bool prng_initialized = false;

void pico_nonce_init(void) {  // call once after pico_prng_init()
    // Must be called after pico_prng_init() so DRBG is ready
    get_random_bytes(
        (uint8_t *)&g_boot_salt,
        sizeof(g_boot_salt));  // The boot_salt changes on each
                               // pico_nonce_init(), so nonces won't repeat
    g_msg_counter = 0;
}

void pico_nonce_generate(uint8_t out12[GCM_IV_LEN]) {
    // Critical section: ensure counter increment is atomic
    uint32_t ints = save_and_disable_interrupts();
    uint32_t ctr = g_msg_counter++;
    bool wrapped = (g_msg_counter == 0);  // detect 32-bit wrap
    restore_interrupts(ints);

    // Nonce reuse under the same key is catastrophic for GCM.
    // On wrap, force a reboot (caller must rotate key/salt on restart).
    if (wrapped) {
        printf("ERROR: nonce counter exhausted; rotate key/salt.\n");
        pico_reboot();
    }

    // Construct the 96-bit IV: salt + counter
    memcpy(out12, g_boot_salt, NONCE_SALT_LEN);
    store_be32(out12 + NONCE_SALT_LEN, ctr);
}

void pico_nonce_on_key_change(void) {  // call whenever session key changes
    // Safe to reset counter when key changes (new (key,nonce) space)
    pico_nonce_init();
}

static inline uint32_t slot_to_sector_offset(int slot) {
    return (slot == 0) ? SLOT_A_SECTOR_OFFSET : SLOT_B_SECTOR_OFFSET;
}
// CORRECTLY LINKING
typedef struct {
    uint8_t key[SST_KEY_SIZE];
    uint8_t hash[32];  // SHA-256 hash
    uint32_t magic;
} key_flash_block_t;

_Static_assert(sizeof(key_flash_block_t) <= 256,
               "key_flash_block_t must fit in one 256B page");

typedef struct {
    uint8_t slot;           // 0=A, 1=B
    uint8_t magic;          // SLOT_INDEX_MAGIC
    uint8_t reserved[254];  // pad to 256B page
} slot_index_page_t;

_Static_assert(sizeof(slot_index_page_t) == 256,
               "Index page must be exactly 256 bytes");

void compute_key_hash(const uint8_t *data, size_t len, uint8_t *out_hash) {
    mbedtls_sha256(data, len, out_hash, 0);  // 0 = SHA-256, not SHA-224
}

// Validates a flash key block by checking its magic value and hash.
// @param block Pointer to validate
// @return true if the block is valid, false otherwise
// TODO: Check if static.
bool validate_flash_block(const key_flash_block_t *block) {
    // Check if the block has the correct magic identifier.
    if (block->magic != FLASH_KEY_MAGIC) return false;

    uint8_t expected_hash[32];
    compute_key_hash(block->key, SST_KEY_SIZE, expected_hash);

    // Compare the stored hash with the computed hash.
    return memcmp(block->hash, expected_hash, 32) == 0;
}

// Reads a key from the specified flash memory slot and validates it.
// @param offset Offset from XIP_BASE where the key block is stored
// @param out Output buffer to copy the valid key into (must be SST_KEY_SIZE
// bytes)
// @return true if a valid key was found and copied, false otherwise
// Set to static.
static bool read_key_from_slot(uint32_t offset, uint8_t *out) {
    const key_flash_block_t *slot =
        (const key_flash_block_t *)(XIP_BASE + offset);
    if (validate_flash_block(slot)) {
        memcpy(out, slot->key, SST_KEY_SIZE);
        return true;
    }
    return false;
}

bool write_key_to_slot(uint32_t offset, const uint8_t *key) {
    key_flash_block_t block = (key_flash_block_t){0};
    memcpy(block.key, key, SST_KEY_SIZE);
    compute_key_hash(block.key, SST_KEY_SIZE, block.hash);
    block.magic = FLASH_KEY_MAGIC;

    // Stage into a 256-byte page
    uint8_t page[FLASH_PAGE_SIZE] = {0};  // FLASH_PAGE_SIZE is 256 on RP2040
    memcpy(page, &block, sizeof(block));

    const uint32_t sector = (offset == FLASH_SLOT_A_OFFSET)
                                ? SLOT_A_SECTOR_OFFSET
                                : SLOT_B_SECTOR_OFFSET;

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(sector, FLASH_SECTOR_SIZE);
    // program exactly one page (256B) at the slot offset
    flash_range_program(offset, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);

    secure_zero(&block, sizeof(block));
    secure_zero(page, sizeof(page));
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
    bool a_valid = read_key_from_slot(FLASH_SLOT_A_OFFSET, temp);
    bool ok = a_valid ? write_key_to_slot(FLASH_SLOT_B_OFFSET, key)
                      : write_key_to_slot(FLASH_SLOT_A_OFFSET, key);
    secure_zero(temp, sizeof(temp));
    return ok;
}

bool erase_all_key_slots() {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SLOT_A_SECTOR_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_erase(SLOT_B_SECTOR_OFFSET, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
    return true;
}

void zero_key(uint8_t *key) { secure_zero(key, SST_KEY_SIZE); }

bool is_key_zeroed(const uint8_t *key) {
    for (int i = 0; i < SST_KEY_SIZE; i++) {
        if (key[i] != 0) return false;
    }
    return true;
}

int pico_hardware_entropy_poll(void *data, unsigned char *output, size_t len,
                               size_t *olen) {
    (void)data;
    uint32_t r;
    size_t i = 0;
    while (i < len) {
        r = get_rand_32();
        // Copy 4 bytes of randomness
        for (int j = 0; j < 4 && i < len; j++) {
            output[i++] = (uint8_t)(r >> (j * 8));
        }
    }
    *olen = len;
    return 0;
}

void pico_prng_init(void) {
    if (prng_initialized) {
        return;
    }
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    int ret =
        mbedtls_entropy_add_source(&entropy, pico_hardware_entropy_poll, NULL,
                                   32,  // Minimum entropy length
                                   MBEDTLS_ENTROPY_SOURCE_STRONG);
    if (ret != 0) {
        printf("Failed to add entropy source: %d\n", ret);
        pico_reboot();
    }

    const char *pers = "sst-pico-prng";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed PRNG: %d\n", ret);
        pico_reboot();
    }
    prng_initialized = true;
}

void get_random_bytes(uint8_t *buffer, size_t len) {
    if (!prng_initialized) {
        printf("FATAL: PRNG not initialized. Rebooting.\n");
        pico_reboot();
    }
    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, buffer, len);
    if (ret != 0) {
        printf("Failed to get random bytes: %d. Rebooting.\n", ret);
        pico_reboot();
    }
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

bool receive_new_key_with_timeout(uint8_t *key_out, uint32_t timeout_ms) {
    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    while (absolute_time_diff_us(get_absolute_time(), deadline) > 0) {
        if (uart_is_readable(UART_ID) &&
            uart_getc(UART_ID) == PREAMBLE_BYTE_1) {
            while (!uart_is_readable(UART_ID)) {
            }  // spin until byte available

            if (uart_getc(UART_ID) == PREAMBLE_BYTE_2) {
                printf("Receiving new session key...\n");
                size_t received = 0;
                while (received < SST_KEY_SIZE &&
                       absolute_time_diff_us(get_absolute_time(), deadline) >
                           0) {
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
    const slot_index_page_t *idx =
        (const slot_index_page_t *)(XIP_BASE + FLASH_SLOT_INDEX_OFFSET);

    if (idx->magic == SLOT_INDEX_MAGIC && (idx->slot == 0 || idx->slot == 1)) {
        return idx->slot;
    }
    return -1;
}

void store_last_used_slot(uint8_t slot) {
    slot_index_page_t page = {0};
    page.slot = slot;
    page.magic = SLOT_INDEX_MAGIC;

    uint32_t ints = save_and_disable_interrupts();
    // erase entire index sector, then write one 256B page
    flash_range_erase(INDEX_SECTOR_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_SLOT_INDEX_OFFSET, (const uint8_t *)&page,
                        sizeof(page));
    restore_interrupts(ints);
}

void pico_reboot(void) { watchdog_reboot(0, 0, 0); }

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
    secure_zero(tmp, sizeof(tmp));
}

void pico_clear_slot(int slot) {
    const uint32_t sector = slot_to_sector_offset(slot);
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(sector, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
}

bool pico_clear_slot_verify(int slot) {
    if (slot != 0 && slot != 1) return false;  // slot A or B
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
    secure_zero(tmp, sizeof(tmp));
}

bool keyram_valid(void) { return g_key_valid; }

void keyram_set(const uint8_t *k) {
    memcpy(g_session_key, k, SST_KEY_SIZE);
    g_key_valid = true;
}

const uint8_t *keyram_get(void) { return g_key_valid ? g_session_key : NULL; }

void keyram_clear(void) {
    volatile uint8_t *p = g_session_key;
    for (size_t i = 0; i < SST_KEY_SIZE; i++) p[i] = 0;
    g_key_valid = false;
}
