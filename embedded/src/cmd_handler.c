#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sst_crypto_embedded.h"  // Ensure this is included for functions like print_hex, read_key_from_slot, etc.
#include "mbedtls_time_alt.h"      // Include mbedtls_time_alt.h if functions like get_random_bytes() are defined there

#include "ram_handler.h"  // This will call the correct flash handler based on the platform

extern uint8_t session_key[SST_KEY_SIZE];
extern int current_slot;

void handle_commands(const char *cmd) {
    if (strcmp(cmd, " print key") == 0 || strcmp(cmd, " print key sender") == 0) {
        print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
    } else if (strcmp(cmd, " print key receiver") == 0) {
        printf("Check receiver printed key.\n");
    } else if (strcmp(cmd, " print key *") == 0) {
        print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
        printf("Check receiver printed key.\n");
    } else if (strcmp(cmd, " slot status") == 0) {
        printf("Slot Status:\n");
        if (current_slot == 0) {
            printf("  Current slot: A\n");
        } else {
            printf("  Current slot: B\n");
        }
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
    } else if (strcmp(cmd, " clear slot A") == 0) {
        flash_range_erase(FLASH_SLOT_A_OFFSET, FLASH_SLOT_SIZE);
        printf("Slot A cleared.\n");
    } else if (strcmp(cmd, " clear slot B") == 0) {
        flash_range_erase(FLASH_SLOT_B_OFFSET, FLASH_SLOT_SIZE);
        printf("Slot B cleared.\n");
    } else if (strcmp(cmd, " use slot A") == 0) {
        current_slot = 0;
        store_last_used_slot(current_slot);
        if (read_key_from_slot(FLASH_SLOT_A_OFFSET, session_key)) {
            print_hex("Using session key from Slot A: ", session_key, SST_KEY_SIZE);
        } else {
            printf("Slot A is empty or invalid. Ready to receive new key.\n");
            zero_key(session_key);
        }
    } else if (strcmp(cmd, " use slot B") == 0) {
        current_slot = 1;
        store_last_used_slot(current_slot);
        if (read_key_from_slot(FLASH_SLOT_B_OFFSET, session_key)) {
            print_hex("Using session key from Slot B: ", session_key, SST_KEY_SIZE);
        } else {
            printf("Slot B is empty or invalid. Ready to receive new key.\n");
            zero_key(session_key);
        }
    } else if (strcmp(cmd, " entropy test") == 0) {
        uint8_t entropy_sample[16];
        get_random_bytes(entropy_sample, sizeof(entropy_sample));
        print_hex("Entropy Sample: ", entropy_sample, sizeof(entropy_sample));
    } else if (strcmp(cmd, " new key -f") == 0) {
        printf("Waiting 3 seconds for new key (forced)...\n");
        uint8_t new_key[SST_KEY_SIZE] = {0};
        if (receive_new_key_with_timeout(new_key, 3000)) {
            print_hex("Received new key: ", new_key, SST_KEY_SIZE);
            uint32_t offset = current_slot == 0 ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
            write_key_to_slot(offset, new_key);
            memcpy(session_key, new_key, SST_KEY_SIZE);
            printf("New session key forcibly stored in Slot %c.\n", current_slot == 0 ? 'A' : 'B');
        } else {
            printf("No key received. Aborting.\n");
        }
    } else if (strcmp(cmd, " new key") == 0) {
        uint32_t offset = current_slot == 0 ? FLASH_SLOT_A_OFFSET : FLASH_SLOT_B_OFFSET;
        uint8_t tmp[SST_KEY_SIZE];
        if (read_key_from_slot(offset, tmp)) {
            printf("Slot %c is already occupied. Use 'new key -f' to overwrite.\n", current_slot == 0 ? 'A' : 'B');
        } else {
            printf("Waiting 3 seconds for new key...\n");
            uint8_t new_key[SST_KEY_SIZE] = {0};
            if (receive_new_key_with_timeout(new_key, 5000)) {
                print_hex("Received new key: ", new_key, SST_KEY_SIZE);
                write_key_to_slot(offset, new_key);
                memcpy(session_key, new_key, SST_KEY_SIZE);
                printf("New session key stored in Slot %c.\n", current_slot == 0 ? 'A' : 'B');
            } else {
                printf("No key received. Aborting.\n");
            }
        }
    } else if (strcmp(cmd, " print slot key A") == 0) {
        uint8_t tmp[SST_KEY_SIZE];
        if (read_key_from_slot(FLASH_SLOT_A_OFFSET, tmp)) {
            print_hex("Slot A key: ", tmp, SST_KEY_SIZE);
        } else {
            printf("Slot A is invalid.\n");
        }
    } else if (strcmp(cmd, " print slot key B") == 0) {
        uint8_t tmp[SST_KEY_SIZE];
        if (read_key_from_slot(FLASH_SLOT_B_OFFSET, tmp)) {
            print_hex("Slot B key: ", tmp, SST_KEY_SIZE);
        } else {
            printf("Slot B is invalid.\n");
        }
    } else if (strcmp(cmd, " print slot key *") == 0) {
        uint8_t tmp[SST_KEY_SIZE];
        if (read_key_from_slot(FLASH_SLOT_A_OFFSET, tmp)) {
            print_hex("Slot A key: ", tmp, SST_KEY_SIZE);
        } else {
            printf("Slot A is invalid.\n");
        }
        if (read_key_from_slot(FLASH_SLOT_B_OFFSET, tmp)) {
            print_hex("Slot B key: ", tmp, SST_KEY_SIZE);
        } else {
            printf("Slot B is invalid.\n");
        }
    } else if (strcmp(cmd, " reboot") == 0) {
        printf("Rebooting...\n");
        sleep_ms(500);
        watchdog_reboot(0, 0, 0);
    } else if (strcmp(cmd, " help") == 0) {
        printf("Available Commands:\n");
        printf("  CMD: print key\n");
        printf("  CMD: print key sender\n");
        printf("  CMD: print key receiver\n");
        printf("  CMD: print key *\n");
        printf("  CMD: print slot key A\n");
        printf("  CMD: print slot key B\n");
        printf("  CMD: print slot key *\n");
        printf("  CMD: clear slot A\n");
        printf("  CMD: clear slot B\n");
        printf("  CMD: clear slot *\n");
        printf("  CMD: use slot A\n");
        printf("  CMD: use slot B\n");
        printf("  CMD: new key         (request new key only if current slot is empty)\n");
        printf("  CMD: new key -f      (force overwrite current slot)\n");
        printf("  CMD: slot status     (show slot validity and active slot)\n");
        printf("  CMD: entropy test    (view entropy sample)\n");
        printf("  CMD: reboot\n");
        printf("  CMD: help\n");
    } else {
        printf("Unknown command. Type CMD: help\n");
    }
}
