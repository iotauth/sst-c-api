#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sst_crypto_embedded.h"   // print_hex, secure_zero, etc.
#include "mbedtls_time_alt.h"
#include "ram_handler.h"
#include "pico_handler.h"
#include "pico/time.h"

// Return true iff the effective session key changed (loaded, replaced, or cleared)
bool handle_commands(const char *cmd, uint8_t *session_key, int *current_slot) {
    if (strcmp(cmd, " print key") == 0 || strcmp(cmd, " print key sender") == 0) {
        print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
        return false;
    } else if (strcmp(cmd, " print key receiver") == 0) {
        printf("Check receiver printed key.\n");
        return false;
    } else if (strcmp(cmd, " print key *") == 0) {
        print_hex("Sender's session key: ", session_key, SST_KEY_SIZE);
        printf("Check receiver printed key.\n");
        return false;
    } else if (strcmp(cmd, " slot status") == 0) {
        pico_print_slot_status(*current_slot);
        return false;
    } else if (strcmp(cmd, " clear slot A") == 0) {
        pico_clear_slot_verify(0);
        printf("Slot A cleared.\n");
        if (*current_slot == 0) {
            keyram_clear();
            memset(session_key, 0, SST_KEY_SIZE);
            return true; // effective key now none
        }
        return false;
    } else if (strcmp(cmd, " clear slot B") == 0) {
        pico_clear_slot_verify(1);
        printf("Slot B cleared.\n");
        if (*current_slot == 1) {
            keyram_clear();
            memset(session_key, 0, SST_KEY_SIZE);
            return true;
        }
        return false;
    } else if (strcmp(cmd, " clear slot *") == 0) {
        pico_clear_slot_verify(0);
        pico_clear_slot_verify(1);
        printf("Both slots cleared.\n");
        keyram_clear();
        memset(session_key, 0, SST_KEY_SIZE);
        return true;

    } else if (strcmp(cmd, " use slot A") == 0) {
        *current_slot = 0;
        uint8_t k[SST_KEY_SIZE];
        if (pico_read_key_from_slot(0, k)) {
            keyram_set(k);
            memcpy(session_key, k, SST_KEY_SIZE);
            store_last_used_slot((uint8_t)*current_slot);
            print_hex("Using key from Slot A. RAM key: ", k, SST_KEY_SIZE);
            secure_zero(k, sizeof(k));
            return true;
        } else {
            keyram_clear();
            memset(session_key, 0, SST_KEY_SIZE);
            store_last_used_slot((uint8_t)*current_slot);
            printf("Slot A invalid or empty. Ready to receive new key.\n");
            return true; // effective key changed (now none)
        }

    } else if (strcmp(cmd, " use slot B") == 0) {
        *current_slot = 1;
        uint8_t k[SST_KEY_SIZE];
        if (pico_read_key_from_slot(1, k)) {
            keyram_set(k);
            memcpy(session_key, k, SST_KEY_SIZE);
            store_last_used_slot((uint8_t)*current_slot);
            print_hex("Using key from Slot B. RAM key: ", k, SST_KEY_SIZE);
            secure_zero(k, sizeof(k));
            return true;
        } else {
            keyram_clear();
            memset(session_key, 0, SST_KEY_SIZE);
            store_last_used_slot((uint8_t)*current_slot);
            printf("Slot B invalid or empty. Ready to receive new key.\n");
            return true;
        }

    } else if (strcmp(cmd, " new key -f") == 0) {
        printf("Waiting 3 seconds for new key (forced)...\n");
        uint8_t newk[SST_KEY_SIZE] = {0};
        if (!receive_new_key_with_timeout(newk, 3000)) {
            printf("No key received.\n");
            return false;
        }
        if (!store_session_key(newk)) {
            printf("Flash write failed.\n");
            secure_zero(newk, sizeof(newk));
            return false;
        }

        // Figure out which slot now holds the new key
        int written_slot = -1;
        uint8_t tmp[SST_KEY_SIZE];
        if (pico_read_key_from_slot(0, tmp) && memcmp(tmp, newk, SST_KEY_SIZE) == 0) written_slot = 0;
        else if (pico_read_key_from_slot(1, tmp) && memcmp(tmp, newk, SST_KEY_SIZE) == 0) written_slot = 1;
        secure_zero(tmp, sizeof(tmp));

        if (written_slot >= 0) {
            *current_slot = written_slot;
            store_last_used_slot((uint8_t)*current_slot);
        }

        keyram_set(newk);
        memcpy(session_key, newk, SST_KEY_SIZE);
        printf("New key stored (forced) and loaded to RAM (slot %c).\n", *current_slot ? 'B' : 'A');
        print_hex("Received new key: ", newk, SST_KEY_SIZE);
        secure_zero(newk, sizeof(newk));
        return true;

    } else if (strcmp(cmd, " new key") == 0) {
        // Only accept if current slot is empty
        uint8_t tmp[SST_KEY_SIZE];
        if (pico_read_key_from_slot(*current_slot, tmp)) {
            printf("Slot %c occupied. Use 'new key -f' to overwrite.\n", *current_slot ? 'B' : 'A');
            secure_zero(tmp, sizeof(tmp));
            return false;
        }
        secure_zero(tmp, sizeof(tmp));

        printf("Waiting 3 seconds for new key...\n");
        uint8_t newk[SST_KEY_SIZE] = {0};
        if (!receive_new_key_with_timeout(newk, 3000)) {
            printf("No key received.\n");
            return false;
        }
        if (!store_session_key(newk)) {
            printf("Flash write failed.\n");
            secure_zero(newk, sizeof(newk));
            return false;
        }

        // Determine which slot took it
        int written_slot = -1;
        if (pico_read_key_from_slot(0, tmp) && memcmp(tmp, newk, SST_KEY_SIZE) == 0) written_slot = 0;
        else if (pico_read_key_from_slot(1, tmp) && memcmp(tmp, newk, SST_KEY_SIZE) == 0) written_slot = 1;
        secure_zero(tmp, sizeof(tmp));

        if (written_slot >= 0) {
            *current_slot = written_slot;
            store_last_used_slot((uint8_t)*current_slot);
        }

        keyram_set(newk);
        memcpy(session_key, newk, SST_KEY_SIZE);
        printf("New key stored and loaded to RAM (slot %c).\n", *current_slot ? 'B' : 'A');
        print_hex("Received new key: ", newk, SST_KEY_SIZE);
        secure_zero(newk, sizeof(newk));
        return true;

    } else if (strcmp(cmd, " print slot keys *") == 0) {
        pico_print_key_from_slot(0);
        pico_print_key_from_slot(1);
        return false;

    } else if (strcmp(cmd, " reboot") == 0) {
        printf("Rebooting...\n");
        sleep_ms(500);
        pico_reboot();
        return false;

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
        return false;
    } else {
        printf("Unknown command. Type CMD: help\n");
        return false;
    }
}
