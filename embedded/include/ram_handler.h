#ifndef RAM_HANDLER_H
#define RAM_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

// Function declarations for the common interface
void store_session_key(const uint8_t* key);
bool erase_all_key_slots(void);
void write_key_to_slot(uint32_t offset, const uint8_t* key);
bool read_key_from_slot(uint32_t offset, uint8_t* out);

#endif // RAM_HANDLER_H
