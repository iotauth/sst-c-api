#ifndef PICO_HANDLER_H
#define PICO_HANDLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Prints byte data as a hex string.
void print_hex(const char *label, const uint8_t *data, size_t len);
// Fills a buffer with random bytes from the Pico's hardware RNG.
void get_random_bytes(uint8_t *buffer, size_t len);
// Waits for a new key to be received over UART with a specified timeout.
bool receive_new_key_with_timeout(uint8_t *key_out, uint32_t timeout_ms);
// Fills a key buffer with zeros.
void zero_key(uint8_t *key);
// Stores the index of the last used key slot (0 for A, 1 for B) to flash.
void store_last_used_slot(uint8_t slot);
// Loads the index of the last used key slot from flash.
int load_last_used_slot();
// Reboots the Pico device.
void pico_reboot(void);
// Prints the status (valid/invalid) of both key slots.
void pico_print_slot_status(int current_slot);
// Erases a specific key slot in flash.
void pico_clear_slot(int slot);
// Reads a key from a specific slot in flash.
bool pico_read_key_from_slot(int slot, uint8_t *out);
// Writes a key to a specific slot in flash.
bool pico_write_key_to_slot(int slot, const uint8_t *key);
// Prints the key stored in a specific slot.
void pico_print_key_from_slot(int slot);
// Loads a session key from the first valid flash slot found.
bool load_session_key(uint8_t *out);
// Stores a session key into the next available flash slot.
bool store_session_key(const uint8_t *key);
// Checks if a key buffer is all zeros.
bool is_key_zeroed(const uint8_t *key);

#endif // PICO_HANDLER_H
