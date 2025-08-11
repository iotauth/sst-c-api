#ifndef RAM_HANDLER_H
#define RAM_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include "sst_crypto_embedded.h"


// Function declarations for the common interface
bool store_session_key(const uint8_t* key);
bool erase_all_key_slots(void);
bool write_key_to_slot(uint32_t offset, const uint8_t* key);
bool read_key_from_slot(uint32_t offset, uint8_t* out);

bool keyram_valid(void);
void keyram_set(const uint8_t *k);        // copies SST_KEY_SIZE bytes
const uint8_t* keyram_get(void);          // NULL if not set
void keyram_clear(void);

#endif // RAM_HANDLER_H
