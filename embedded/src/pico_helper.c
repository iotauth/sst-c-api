#include <stdio.h>
#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "mbedtls/sha256.h"
#include "pico/rand.h"
#include "pico/stdlib.h"
#include "ram_handler.h"
#include "sst_crypto_embedded.h"  // for SST_KEY_SIZE, etc.

/* --- Flash layout (end of flash, 2 sectors, 4KB each) --- */
#define SLOT_A_SECTOR_OFFSET \
    (PICO_FLASH_SIZE_BYTES - 2 * FLASH_SECTOR_SIZE)  // 4KB aligned
#define SLOT_B_SECTOR_OFFSET \
    (PICO_FLASH_SIZE_BYTES - 1 * FLASH_SECTOR_SIZE)  // 4KB aligned

#define FLASH_KEY_MAGIC 0x53455353u /* 'SESS' */

static uint8_t g_session_key[SST_KEY_SIZE];
static bool g_valid = false;

bool keyram_valid(void) { return g_valid; }

void keyram_set(const uint8_t *k) {
    memcpy(g_session_key, k, SST_KEY_SIZE);
    g_valid = true;
}

const uint8_t *keyram_get(void) { return g_valid ? g_session_key : NULL; }

void keyram_clear(void) {
    volatile uint8_t *p = g_session_key;
    for (size_t i = 0; i < SST_KEY_SIZE; i++) p[i] = 0;
    g_valid = false;
}

/* One 256-byte page per slot */
typedef struct {
    uint32_t magic;            /* 'SESS' */
    uint32_t version;          /* 1 */
    uint32_t counter;          /* increment each write */
    uint8_t key[SST_KEY_SIZE]; /* 16 bytes typical */
    uint8_t hash[32];          /* sha256(key) or sha256(header||key) */
    uint8_t reserved[FLASH_PAGE_SIZE - 4 - 4 - 4 - SST_KEY_SIZE - 32];
} key_flash_block_t; /* exactly 256 bytes */

static void compute_key_hash(const uint8_t *data, size_t len,
                             uint8_t *out_hash) {
    mbedtls_sha256(data, len, out_hash, 0); /* 0 = SHA-256 */
}

static bool validate_flash_block(const key_flash_block_t *blk) {
    if (blk->magic != FLASH_KEY_MAGIC) return false;
    if (blk->version != 1) return false;
    uint8_t expected[32];
    compute_key_hash(blk->key, SST_KEY_SIZE, expected);
    return memcmp(blk->hash, expected, 32) == 0;
}

static const key_flash_block_t *map_slot(uint32_t sector_offset) {
    return (const key_flash_block_t *)(XIP_BASE + sector_offset);
}

static bool read_key_from_sector(uint32_t sector_offset, uint8_t *out_key,
                                 uint32_t *out_counter) {
    const key_flash_block_t *blk = map_slot(sector_offset);
    if (!validate_flash_block(blk)) return false;
    memcpy(out_key, blk->key, SST_KEY_SIZE);
    if (out_counter) *out_counter = blk->counter;
    return true;
}

static bool program_sector_page0(uint32_t sector_offset,
                                 const key_flash_block_t *blk) {
    /* Erase full 4KB sector, then program exactly 256B page 0 */
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(sector_offset, FLASH_SECTOR_SIZE);

    /* Program must be multiple of 256 and 256-aligned; sector_offset is aligned
     */
    flash_range_program(sector_offset, (const uint8_t *)blk, FLASH_PAGE_SIZE);
    restore_interrupts(ints);

    /* Verify by reading back via XIP */
    const key_flash_block_t *rd = map_slot(sector_offset);
    return validate_flash_block(rd) &&
           memcmp(rd->key, blk->key, SST_KEY_SIZE) == 0 &&
           rd->counter == blk->counter && rd->version == blk->version &&
           rd->magic == blk->magic;
}

/* Public API */

bool load_session_key(uint8_t *out) {
    uint8_t a_key[SST_KEY_SIZE], b_key[SST_KEY_SIZE];
    uint32_t a_cnt = 0, b_cnt = 0;
    bool a_ok = read_key_from_sector(SLOT_A_SECTOR_OFFSET, a_key, &a_cnt);
    bool b_ok = read_key_from_sector(SLOT_B_SECTOR_OFFSET, b_key, &b_cnt);

    if (a_ok && b_ok) {
        if (b_cnt >= a_cnt) {
            memcpy(out, b_key, SST_KEY_SIZE);
            return true;
        } else {
            memcpy(out, a_key, SST_KEY_SIZE);
            return true;
        }
    } else if (a_ok) {
        memcpy(out, a_key, SST_KEY_SIZE);
        return true;
    } else if (b_ok) {
        memcpy(out, b_key, SST_KEY_SIZE);
        return true;
    }
    return false;
}

bool store_session_key(const uint8_t *key) {
    /* Read both slots to decide next counter/slot */
    uint8_t tmp[SST_KEY_SIZE];
    uint32_t a_cnt = 0, b_cnt = 0;
    bool a_ok = read_key_from_sector(SLOT_A_SECTOR_OFFSET, tmp, &a_cnt);
    bool b_ok = read_key_from_sector(SLOT_B_SECTOR_OFFSET, tmp, &b_cnt);

    uint32_t next_counter = 1;
    if (a_ok || b_ok) next_counter = (a_cnt > b_cnt ? a_cnt : b_cnt) + 1;

    key_flash_block_t blk = {0};
    blk.magic = FLASH_KEY_MAGIC;
    blk.version = 1;
    blk.counter = next_counter;
    memcpy(blk.key, key, SST_KEY_SIZE);
    compute_key_hash(blk.key, SST_KEY_SIZE, blk.hash);

    /* Write to the older/invalid slot to keep last-good copy */
    if (!a_ok || (a_cnt <= b_cnt)) {
        return program_sector_page0(SLOT_A_SECTOR_OFFSET, &blk);
    } else {
        return program_sector_page0(SLOT_B_SECTOR_OFFSET, &blk);
    }
}

bool erase_all_key_slots(void) {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(SLOT_A_SECTOR_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_erase(SLOT_B_SECTOR_OFFSET, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
    return true;
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

void zero_key(uint8_t *key) {
    volatile uint8_t *p = key;
    for (size_t i = 0; i < SST_KEY_SIZE; i++) p[i] = 0;
}

bool is_key_zeroed(const uint8_t *key) {
    for (size_t i = 0; i < SST_KEY_SIZE; i++)
        if (key[i] != 0) return false;
    return true;
}

void get_random_bytes(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++)
        buffer[i] = (uint8_t)(get_rand_32() & 0xFF);
}
