#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sst_crypto_embedded.h"  // Ensure this is included for functions like print_hex, read_key_from_slot, etc.
#include "mbedtls_time_alt.h"      // Include mbedtls_time_alt.h if functions like get_random_bytes() are defined there

#include "ram_handler.h"  // This will call the correct flash handler based on the platform
#include "pico_handler.h"  // Include the pico handler for specific flash operations
#include "pico/time.h"      // Include for sleep_ms

void handle_commands(const char *cmd, uint8_t *session_key, int *current_slot) {
    if (strcmp(cmd, " print key") == 0 || strcmp(cmd, " print key sender") == 0) {
        print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
    } else if (strcmp(cmd, " print key receiver") == 0) {
        printf("Check receiver printed key.\n");
    } else if (strcmp(cmd, " print key *") == 0) {
        print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
        printf("Check receiver printed key.\n");
    } else if (strcmp(cmd, " slot status") == 0) {
        pico_print_slot_status(*current_slot);
    } else if (strcmp(cmd, " clear slot A") == 0) {
        pico_clear_slot_verify(0);
        printf("Slot A cleared.\n");
    } else if (strcmp(cmd, " clear slot B") == 0) {
        pico_clear_slot_verify(1);
        printf("Slot B cleared.\n");
    } else if (strcmp(cmd, " use slot A") == 0) {
        *current_slot = 0;
        uint8_t k[SST_KEY_SIZE];
        if (pico_read_key_from_slot(0, k)) {
            keyram_set(k);
            printf("Using key from Slot A.\n");
        } else {
            keyram_clear();
            printf("Slot A invalid or empty. Ready to receive new key.\n");
        }
    } else if (strcmp(cmd, " use slot B") == 0) {
        *current_slot = 1;
        uint8_t k[SST_KEY_SIZE];
        if (pico_read_key_from_slot(1, k)) {
            printf("Using key from slot B");
        } else {
            keyram_clear();
            printf("Slot B invalid or empty. Ready to receive new key.\n");
        }
    } else if (strcmp(cmd, " new key -f") == 0) {
        printf("Waiting 3 seconds for new key (forced)...\n");
        uint8_t newk[SST_KEY_SIZE] = {0};
        if (receive_new_key_with_timeout(newk, 3000)) {
            uint8_t tmp[SST_KEY_SIZE];
            if (!store_session_key(newk)) {
                printf("Flash write failed.\n");
            } else {
                keyram_set(newk);
                printf("New key stored (forced) and loaded to RAM (slot %c).\n", current_slot?'B':'A');
                print_hex("Received new key: ", newk, SST_KEY_SIZE);

            }
        } else {
            printf("No key received.\n");
        }
    } else if (strcmp(cmd, " new key") == 0) {
        uint8_t tmp[SST_KEY_SIZE];
        if (pico_read_key_from_slot(*current_slot, tmp)) {
            printf("Slot %c occupied. Use 'new key -f' to overwrite.\n", *current_slot ? 'B':'A');
        } else {
            printf("Waiting 3 seconds for new key...\n");
            uint8_t newk[SST_KEY_SIZE] = {0};
            if (receive_new_key_with_timeout(newk, 3000)) {
                //--- add CRC or verify section here ---
                if (!store_session_key(newk)) {
                    printf("Flash write failed.\n");
                } else {
                    keyram_set(newk);
                    printf("new key stored and loaded to RAM (slot %c).\n");
                    print_hex("Received new key: ", newk, SST_KEY_SIZE);
                }
            } else {
                printf("No key received.\n");
            }
        }
    } else if (strcmp(cmd, " print slot keys *") == 0) {
        pico_print_key_from_slot(0);
        pico_print_key_from_slot(1);
    } else if (strcmp(cmd, " reboot") == 0) {
        printf("Rebooting...\n");
        sleep_ms(500);
        pico_reboot();
    } else if (strcmp(cmd, " help") == 0) {
        printf("Available Commands:\n");
        printf("  CMD: print key\n");
        printf("  CMD: print key sender\n");
        printf("  CMD: print key receiver\n");
        printf("  CMD: print key *\n");
        printf("  CMD: print slot keys *\n");
        printf("  CMD: clear slot A\n");
        printf("  CMD: clear slot B\n");
        printf("  CMD: clear slot *\n");
        printf("  CMD: use slot A\n");
        printf("  CMD: use slot B\n");
        printf("  CMD: new key         (request new key only if current slot is empty)\n");
        printf("  CMD: new key -f      (force overwrite current slot)\n");
        printf("  CMD: slot status     (show slot validity and active slot)\n");
        printf("  CMD: reboot\n");
        printf("  CMD: help\n");
    } else {
        printf("Unknown command. Type CMD: help\n");
    }
}
