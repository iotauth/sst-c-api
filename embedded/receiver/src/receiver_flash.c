#include <stdbool.h>  // to use bool type check if key is valid
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "../../../c_api.h"
#include "../../../include/protocol.h"  //global vars for speed, serial settings, etc
#include "../../include/config_handler.h"  // For change_directory_to_config_path and get_config_path
#include "../../include/sst_crypto_embedded.h"
#include "key_exchange.h"
#include "replay_window.h"
#include "serial_linux.h"
#include "utils.h"

static inline int timespec_passed(const struct timespec* dl) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec > dl->tv_sec) ||
           (now.tv_sec == dl->tv_sec && now.tv_nsec >= dl->tv_nsec);
}

// write_exact: loop until all bytes are written (or error)
static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue; // interrupted -> retry
            return -1;                    // real error
        }
        if (n == 0) break;                // shouldn't happen on tty, treat as error
        sent += (size_t)n;
    }
    return (sent == len) ? 0 : -1;
}


int main(int argc, char* argv[]) {
    const char* config_path = NULL;

    if (argc > 2) {
        fprintf(stderr, "Error: Too many arguments.\n");
        fprintf(stderr, "Usage: %s [<path/to/sst.config>]\n", argv[0]);
        return 1;
    } else if (argc == 2) {
        config_path = argv[1];
    }

    // Resolve / chdir and pick the config filename (host-only; Pico stub is
    // no-op)
    change_directory_to_config_path(config_path);
    config_path = get_config_path(config_path);
    printf("Using config file: %s\n", config_path);

    // --- Fetch session key from SST ---
    printf("Retrieving session key from SST...\n");
    SST_ctx_t* sst = init_SST(config_path);
    if (!sst) {
        fprintf(stderr, "SST init failed.\n");
        return 1;
    }

    session_key_list_t* key_list =
        get_session_key(sst, init_empty_session_key_list());
    if (!key_list || key_list->num_key == 0) {
        fprintf(stderr, "No session key.\n");
        return 1;
    }

    session_key_t s_key = key_list->s_key[0];
    print_hex("Session Key: ", s_key.cipher_key, SESSION_KEY_SIZE);

    bool key_valid = true;                        // track if current key usable
    uint8_t pending_key[SESSION_KEY_SIZE] = {0};  // for rotations

    // --- Receiver state + replay window ---
    receiver_state_t state = STATE_IDLE;
    struct timespec state_deadline = (struct timespec){0, 0};
    time_t last_key_req_time = 0;

    // nonce setup
    replay_window_t rwin;
    replay_window_init(&rwin, NONCE_SIZE, NONCE_HISTORY_SIZE);

    // --- Serial setup ---
    int fd = init_serial(UART_DEVICE, UART_BAUDRATE_TERMIOS);  // termios for
                                                               // pi4
    if (fd < 0) return 1;

    // Initial key push retry machinery
    struct timespec next_send = {0};
    clock_gettime(CLOCK_MONOTONIC, &next_send);  // send immediately

    const uint8_t preamble[2] = {PREAMBLE_BYTE_1, PREAMBLE_BYTE_2};
    // Send preamble + session key (robust, handles partial writes)
    if (write_all(fd, preamble, sizeof preamble) < 0) {
        perror("write preamble");
        // handle error (return -1; or set a flag)
    }
    if (write_all(fd, s_key.cipher_key, SESSION_KEY_SIZE) < 0) {
        perror("write session key");
        // handle error
    }
    tcdrain(fd);  // ensure bytes actually leave the UART
    printf("Sent preamble + session key over UART.\n");

    // UART framing state
    uint8_t byte = 0;
    int uart_state = 0;

    printf("Listening for encrypted message...\n");
    tcflush(fd, TCIFLUSH);

    while (1) {
        // --- Handle State Timeouts ---
        if (state != STATE_IDLE && timespec_passed(&state_deadline)) {
            if (state == STATE_WAITING_FOR_YES) {
                printf(
                    "Confirmation for 'new key' timed out. Returning to "
                    "idle.\n");
                // nothing to wipe here
            } else if (state == STATE_WAITING_FOR_ACK) {
                printf(
                    "Timeout waiting for key update ACK. Discarding new "
                    "key.\n");
                explicit_bzero(pending_key, sizeof pending_key);
                // keep old key; key_valid stays true
            }
            state = STATE_IDLE;
            state_deadline = (struct timespec){0, 0};
        }

        if (read(fd, &byte, 1) == 1) {
            switch (uart_state) {
                case 0:
                    if (byte == PREAMBLE_BYTE_1) {
                        uart_state = 1;
                    } else {
                        printf(
                            "Waiting: got 0x%02X, expecting PREAMBLE_BYTE_1\n",
                            byte);
                    }
                    break;
                case 1:
                    if (byte == PREAMBLE_BYTE_2) {
                        uart_state = 2;
                    } else {
                        printf("Bad second preamble byte: 0x%02X\n", byte);
                        uart_state = 0;
                    }
                    break;

                case 2:
                    if (byte == MSG_TYPE_ENCRYPTED) {
                        uint8_t nonce[NONCE_SIZE];
                        uint8_t len_bytes[2];

                        // Read nonce + length
                        if (read_exact(fd, nonce, NONCE_SIZE) != NONCE_SIZE ||
                            read_exact(fd, len_bytes, 2) != 2) {
                            printf("Failed to read nonce or length\n");
                            uart_state = 0;
                            continue;
                        }

                        // --- Nonce Replay Check ---
                        if (replay_window_seen(&rwin, nonce)) {
                            printf("Nonce replayed! Rejecting message.\n");
                            uart_state = 0;
                            continue;
                        }
                        replay_window_add(&rwin, nonce);

                        // Length -> host order + bounds check
                        uint16_t msg_len =
                            ((uint16_t)len_bytes[0] << 8) | len_bytes[1];
                        if (msg_len == 0 ||
                            msg_len >
                                1024) {  // or use MAX_MSG_LEN from protocol.h
                            printf("Message too long: %u bytes\n", msg_len);
                            uart_state = 0;
                            continue;
                        }

                        // read payload
                        uint8_t ciphertext[msg_len];
                        uint8_t tag[TAG_SIZE];
                        uint8_t decrypted[msg_len + 1];  // for null-terminator

                        ssize_t c = read_exact(fd, ciphertext, msg_len);
                        ssize_t t = read_exact(fd, tag, TAG_SIZE);

                        if (c == msg_len && t == TAG_SIZE) {
                            if (!key_valid) {  // Skip decryption if key was
                                               // cleared and not yet rotated
                                printf(
                                    "No valid session key. Rejecting encrypted "
                                    "message.\n");
                                uart_state = 0;
                                continue;
                            }

                            int ret = sst_decrypt_gcm(s_key.cipher_key, nonce,
                                                      ciphertext, msg_len, tag,
                                                      decrypted);

                            if (ret == 0) {  // Successful decryption
                                decrypted[msg_len] =
                                    '\0';  // Null-terminate the decrypted
                                           // message
                                printf("Decrypted: %s\n", decrypted);

                                // If the decrypted message is "I have the key",
                                // stop sending the key.
                                if (strcmp((char*)decrypted,
                                           "I have the key") == 0) {
                                    printf(
                                        "Pico has confirmed receiving the "
                                        "key.\n");
                                }

                                // Handle "new key" commands (if the flag for
                                // sending new key is set)
                                else if (strcmp((char*)decrypted,
                                                "new key -f") == 0) {
                                    // Logic to request a new key and forcefully
                                    // overwrite current one
                                    printf(
                                        "Received 'new key -f' command. "
                                        "Requesting new key...\n");

                                    free_session_key_list_t(key_list);
                                    key_list = get_session_key(
                                        sst, init_empty_session_key_list());

                                    if (!key_list || key_list->num_key == 0) {
                                        fprintf(stderr,
                                                "Failed to fetch new session "
                                                "key.\n");
                                    } else {
                                        memcpy(pending_key,
                                               key_list->s_key[0].cipher_key,
                                               SESSION_KEY_SIZE);
                                        print_hex(
                                            "New Session Key (pending ACK): ",
                                            pending_key, SESSION_KEY_SIZE);
                                        key_valid = true;

                                        uint8_t preamble[2] = {0xAB, 0xCD};
                                        write(fd, preamble, 2);
                                        write(fd, pending_key,
                                              SESSION_KEY_SIZE);
                                        usleep(5000);  // 5ms sleep to let
                                                       // transmission complete
                                        printf(
                                            "Sent new session key to Pico. "
                                            "Waiting 5s for ACK...\n");
                                        state = STATE_WAITING_FOR_ACK;
                                        clock_gettime(CLOCK_MONOTONIC,
                                                      &state_deadline);
                                        state_deadline.tv_sec += 5;
                                    }
                                }

                                // Handle other "new key" commands
                                else if (strcmp((char*)decrypted, "new key") ==
                                         0) {
                                    // Logic to check key cooldown and request a
                                    // new key
                                    time_t now = time(NULL);
                                    if (now - last_key_req_time <
                                        KEY_UPDATE_COOLDOWN_S) {
                                        printf(
                                            "Rate limit: another new key "
                                            "request too soon. Ignoring.\n");
                                    } else {
                                        last_key_req_time = now;
                                        printf(
                                            "Received 'new key' command. "
                                            "Waiting 5s for 'yes' "
                                            "confirmation...\n");
                                        state = STATE_WAITING_FOR_YES;
                                        clock_gettime(CLOCK_MONOTONIC,
                                                      &state_deadline);
                                        state_deadline.tv_sec += 5;
                                    }
                                }

                                // Handle key confirmation ACK (after new key
                                // sent)
                                else if (state == STATE_WAITING_FOR_ACK &&
                                         strcmp((char*)decrypted, "ACK") == 0) {
                                    printf(
                                        "ACK received. Finalizing key "
                                        "update.\n");
                                    memcpy(s_key.cipher_key, pending_key,
                                           SESSION_KEY_SIZE);
                                    explicit_bzero(pending_key,
                                                   sizeof(pending_key));
                                    print_hex("New key is now active: ",
                                              s_key.cipher_key,
                                              SESSION_KEY_SIZE);
                                    state = STATE_IDLE;
                                }

                            } else {
                                // AES-GCM decryption failed
                                printf("AES-GCM decryption failed: %d\n", ret);
                            }

                        } else {
                            printf("Incomplete ciphertext or tag.\n");
                        }
                        uart_state = 0;  // Reset uart_state machine
                    } else {
                        uart_state = 0;
                    }
                    break;
                default:
                    uart_state = 0;
            }
        }
    }

    close(fd);
    free_session_key_list_t(key_list);
    free_SST_ctx_t(sst);
    return 0;
}
