#ifndef CMD_HANDLER_H
#define CMD_HANDLER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Handles text-based control commands for managing session keys and
 * slots.
 *
 * This function interprets and executes a range of commands received via UART
 * or other user input. These commands can be used to inspect, clear, switch, or
 * receive new cryptographic session keys, as well as reboot the device or show
 * help text.
 *
 * @param cmd            Null-terminated input string (command).
 * @param session_key    Pointer to the session key buffer in RAM.
 * @param current_slot   Pointer to the current flash slot index (0 = A, 1 = B).
 *
 * @return true if the effective session key was changed (loaded or cleared),
 * false otherwise.
 *
 * @note Supported commands:
 *   - " print key"
 *   - " print key sender"
 *   - " print key *"
 *   - " slot status"
 *   - " clear slot A" / "B" / "*"
 *   - " use slot A" / "B"
 *   - " new key"
 *   - " new key -f"
 *   - " print slot keys *"
 *   - " reboot"
 *   - " help"
 */

#endif  // CMD_HANDLER_H
