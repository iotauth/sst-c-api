#ifndef CMD_HANDLER_H
#define CMD_HANDLER_H

#include <stdint.h>

void handle_commands(const char *cmd, uint8_t *session_key, int *current_slot);

#endif // CMD_HANDLER_H