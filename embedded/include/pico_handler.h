#ifndef PICO_HANDLER_H
#define PICO_HANDLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Initializes the mbedTLS-based PRNG. Must be called once during startup.
void pico_prng_init(void);

// Prints byte data as a hex string.
// @param label Label to prefix the output
// @param data Byte array to print
// @param len Length of the data
void print_hex(const char *label, const uint8_t *data, size_t len);

// Generates random bytes using seeded mbedTLS PRNG.
// @param buffer Destination buffer
// @param len Number of bytes to generate
void get_random_bytes(uint8_t *buffer, size_t len);

// Waits for a new key to be received over UART with a specified timeout.
// @param key_out Buffer to store the key
// @param timeout_ms Timeout in milliseconds
// @return true if key received, false otherwise
bool receive_new_key_with_timeout(uint8_t *key_out, uint32_t timeout_ms);

// Fills a key buffer with zeros.
// @param key Key buffer to clear
void zero_key(uint8_t *key);

// Stores the index of the last used key slot (0 for A, 1 for B) to flash.
// @param slot 0 for slot A, 1 for slot B
void store_last_used_slot(uint8_t slot);

// Loads the index of the last used key slot from flash.
// @return Slot index (0 or 1), -1 if invalid
int load_last_used_slot(void);

// Reboots the Pico device.
void pico_reboot(void);

// Prints the status (valid/invalid) of both key slots.
// @param current_slot Currently active slot
void pico_print_slot_status(int current_slot);

// Erases a specific key slot in flash.
// @param slot Slot index to clear
void pico_clear_slot(int slot);

// Erase specific key slot in flash and confirms with 0xFF
// @param slot Slot index to clear
// @return true if verification succeeds
bool pico_clear_slot_verify(int slot);

// Reads a key from a specific slot in flash.
// @param slot Slot index to read
// @param out Output buffer for key
// @return true if successful
bool pico_read_key_from_slot(int slot, uint8_t *out);

// Writes a key to a specific slot in flash.
// @param slot Slot index to write
// @param key Key to store
// @return true if successful
bool pico_write_key_to_slot(int slot, const uint8_t *key);
// Prints the key stored in a specific slot.
// @param slot Slot index to print
void pico_print_key_from_slot(int slot);

// Loads a session key from the first valid flash slot found.
// @param out Output buffer to store the session key
// @return true if a valid key was loaded, false otherwise
bool load_session_key(uint8_t *out);

// Stores a session key into the next available flash slot.
// @param key Session key to store
// @return true if the key was successfully stored
bool store_session_key(const uint8_t *key);

// Checks if a key buffer is all zeros.
// @param key Pointer to key buffer
// @return true if all bytes are 0x00
bool is_key_zeroed(const uint8_t *key);

// Securely wipe sensitive data from memory.
static inline void secure_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

// Checks if keyram is valid.
// @return true if valid session key is present in RAM
bool keyram_valid(void);

// Copies SST_KEY_SIZE bytes of the given key into volatile RAM.
// @param k Key buffer to copy
void keyram_set(const uint8_t *k);

// Returns pointer to key in RAM, or NULL if not set.
// @return Key pointer or NULL
const uint8_t *keyram_get(void);

// Clears key data from RAM.
void keyram_clear(void);

// Resets the 32-bit message counter to 0.
void pico_nonce_init(void);

// Generates a unique 12-byte nonce for a message.
// @param out12 Output buffer (12 bytes)
void pico_nonce_next(uint8_t out12[12]);

// Resets the nonce state when a new session key is installed.
// Must be called whenever the session key changes to ensure nonce uniqueness.
void pico_nonce_on_key_change(void);

#endif  // PICO_HANDLER_H
