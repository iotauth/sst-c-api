#include <fcntl.h>
#include <libgen.h>        // Required for dirname() and basename()
#include <linux/limits.h>  // Required for PATH_MAX
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdbool.h> // to use bool type check if key is valid
#include <time.h>


#include "../../../c_api.h"
#include "../../include/sst_crypto_embedded.h"
#include "../../include/config_handler.h" // For change_directory_to_config_path and get_config_path

#define UART_DEVICE "/dev/serial0"
#define BAUDRATE B1000000
#define SESSION_KEY_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define PREAMBLE_BYTE_1 0xAB
#define PREAMBLE_BYTE_2 0xCD
#define MSG_TYPE_ENCRYPTED 0x02

#define NONCE_HISTORY_SIZE 64 // For replay protection
#define KEY_UPDATE_COOLDOWN_S 15 // For rate limiting

// --- State Machine Enums ---
typedef enum {
    STATE_IDLE,
    STATE_WAITING_FOR_YES,
    STATE_WAITING_FOR_ACK
} receiver_state_t;

void get_random_bytes(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        perror("FATAL: Failed to open /dev/urandom. Cannot generate nonces");
        // On a critical failure like this, we should not continue.
        exit(EXIT_FAILURE);
    }
    size_t read_len = fread(buf, 1, len, f);
    if (read_len < len) {
        fprintf(stderr, "FATAL: Could not read enough random bytes from /dev/urandom.\n");
        fclose(f);
        exit(EXIT_FAILURE);
    }
    fclose(f);
}

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; ++i) printf("%02X ", data[i]);
    printf("\n");
}

ssize_t read_exact(int fd, uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, buf + total, len - total);
        if (r <= 0) break;
        total += r;
    }
    return total;
}

int init_serial(const char* device, int baudrate) {
    int fd = open(device, O_RDWR | O_NOCTTY);
    if (fd == -1) {
        perror("Failed to open serial device");
        return -1;
    }

    struct termios options;
    tcgetattr(fd, &options);
    cfsetispeed(&options, baudrate);
    cfsetospeed(&options, baudrate);
    options.c_cflag |= (CLOCAL | CREAD);
    options.c_cflag &= ~PARENB & ~CSTOPB & ~CSIZE;
    options.c_cflag |= CS8;
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    options.c_iflag &= ~(IXON | IXOFF | IXANY);
    options.c_oflag &= ~OPOST;
    options.c_cc[VMIN] = 1;
    options.c_cc[VTIME] = 1;
    tcsetattr(fd, TCSANOW, &options);
    return fd;
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
    
    // Call the function to handle the config path logic
    change_directory_to_config_path(config_path);
    // Now we can safely use the config path
    config_path = get_config_path(config_path);
    // Continue with the rest of the program logic...
    printf("Using config file: %s\n", config_path);

    printf("Retrieving session key from SST...\n");
    SST_ctx_t* sst = init_SST(config_path);
    if (!sst) return fprintf(stderr, "SST init failed.\n"), 1;

    session_key_list_t* key_list =
        get_session_key(sst, init_empty_session_key_list());
    if (!key_list || key_list->num_key == 0)
        return fprintf(stderr, "No session key.\n"), 1;

    session_key_t s_key = key_list->s_key[0];
    print_hex("Session Key: ", s_key.cipher_key, SESSION_KEY_SIZE);
    bool key_valid = true; // Flag to check if key is valid
    uint8_t pending_key[SESSION_KEY_SIZE]; // For key updates
    uint8_t nonce_history[NONCE_HISTORY_SIZE][NONCE_SIZE] = {0};
    int nonce_history_idx = 0;

    receiver_state_t state = STATE_IDLE;
    struct timespec state_deadline;
    time_t last_key_req_time = 0;

    int fd = init_serial(UART_DEVICE, BAUDRATE);
    if (fd < 0) return 1;

    bool stop_sending_key = false; // Flag to stop sending key after confirmation

    // Step 1: Send preamble + key to Pico, 5 times with a 3-second delay
    uint8_t preamble[2] = {0xAB, 0xCD};
    for (int i = 0; i < 5; i++) {
        if (!stop_sending_key) { // Only send key if flag is not set
            write(fd, preamble, 2);
            write(fd, s_key.cipher_key, SESSION_KEY_SIZE);
            usleep(50000); // Wait 50ms for the write to complete before printing/sleeping
            printf("Sent session key to Pico (attempt %d/5).\n", i + 1);
        }
        if (i < 4) { // Don't sleep after the last attempt
            sleep(3);
        }
    }

    // Step 2: Listen for encrypted message
    printf("Listening for encrypted message...\n");

    uint8_t byte;
    int uart_state = 0;

    // Flush any stale data in the input buffer before starting the loop.
    tcflush(fd, TCIFLUSH);

    while (1) {
        // --- Handle State Timeouts ---
        if (state != STATE_IDLE) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > state_deadline.tv_sec ||
                (now.tv_sec == state_deadline.tv_sec && now.tv_nsec >= state_deadline.tv_nsec)) {
                if (state == STATE_WAITING_FOR_YES) {
                    printf("Confirmation for 'new key' timed out. Returning to idle.\n");
                } else if (state == STATE_WAITING_FOR_ACK) {
                    printf("Timeout waiting for key update ACK. Discarding new key.\n");
                    explicit_bzero(pending_key, sizeof(pending_key));
                }
                state = STATE_IDLE;
            }
        }

        if (read(fd, &byte, 1) == 1) {
            switch (uart_state) {
                case 0:
                    if (byte == PREAMBLE_BYTE_1) {
                        uart_state = 1;
                    } else {
                        printf("Waiting: got 0x%02X, expecting PREAMBLE_BYTE_1\n", byte);
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

                        if (read_exact(fd, nonce, NONCE_SIZE) != NONCE_SIZE ||
                            read_exact(fd, len_bytes, 2) != 2) {
                            printf("Failed to read nonce or length\n");
                            uart_state = 0;
                            continue;
                        }

                        // --- Nonce Replay Check ---
                        bool nonce_replayed = false;
                        for (int i = 0; i < NONCE_HISTORY_SIZE; i++) {
                            if (memcmp(nonce_history[i], nonce, NONCE_SIZE) == 0) {
                                nonce_replayed = true;
                                break;
                            }
                        }
                        if (nonce_replayed) {
                            printf("Nonce replayed! Rejecting message.\n");
                            uart_state = 0;
                            continue;
                        }
                        memcpy(nonce_history[nonce_history_idx], nonce, NONCE_SIZE);
                        nonce_history_idx = (nonce_history_idx + 1) % NONCE_HISTORY_SIZE;


                        uint16_t msg_len = (len_bytes[0] << 8) | len_bytes[1];
                        if (msg_len > 1024) {
                            printf("Message too long: %u bytes\n", msg_len);
                            uart_state = 0;
                            continue;
                        }

                        uint8_t ciphertext[msg_len];
                        uint8_t tag[TAG_SIZE];
                        uint8_t decrypted[msg_len + 1];  // for null-terminator

                        ssize_t c = read_exact(fd, ciphertext, msg_len);
                        ssize_t t = read_exact(fd, tag, TAG_SIZE);

                        if (c == msg_len && t == TAG_SIZE) {
                            if (!key_valid) { // Skip decryption if key was cleared and not yet rotated
                                printf("No valid session key. Rejecting encrypted message.\n");
                                uart_state = 0;
                                continue;
                            }

                            int ret = sst_decrypt_gcm(
                                s_key.cipher_key, nonce, ciphertext,
                                msg_len, tag, decrypted);

                            if (ret == 0) {  // Successful decryption
                                decrypted[msg_len] = '\0';  // Null-terminate the decrypted message
                                printf("Decrypted: %s\n", decrypted);

                                // If the decrypted message is "I have the key", stop sending the key.
                                if (strcmp((char*)decrypted, "I have the key") == 0) {
                                    printf("Pico has confirmed receiving the key.\n");
                                    stop_sending_key = true; // Set flag to stop key transmission
                                }

                                // Handle "new key" commands (if the flag for sending new key is set)
                                else if (strcmp((char*)decrypted, "CMD: new key -f") == 0) {
                                    // Logic to request a new key and forcefully overwrite current one
                                    printf("Received 'new key -f' command. Requesting new key...\n");

                                    free_session_key_list_t(key_list);
                                    key_list = get_session_key(sst, init_empty_session_key_list());

                                    if (!key_list || key_list->num_key == 0) {
                                        fprintf(stderr, "Failed to fetch new session key.\n");
                                    } else {
                                        memcpy(pending_key, key_list->s_key[0].cipher_key, SESSION_KEY_SIZE);
                                        print_hex("New Session Key (pending ACK): ", pending_key, SESSION_KEY_SIZE);
                                        key_valid = true;

                                        uint8_t preamble[2] = {0xAB, 0xCD};
                                        write(fd, preamble, 2);
                                        write(fd, pending_key, SESSION_KEY_SIZE);
                                        usleep(5000);  // 5ms sleep to let transmission complete
                                        printf("Sent new session key to Pico. Waiting 5s for ACK...\n");
                                        state = STATE_WAITING_FOR_ACK;
                                        clock_gettime(CLOCK_MONOTONIC, &state_deadline);
                                        state_deadline.tv_sec += 5;
                                    }
                                }

                                // Handle other "new key" commands
                                else if (strcmp((char*)decrypted, "CMD: new key") == 0) {
                                    // Logic to check key cooldown and request a new key
                                    time_t now = time(NULL);
                                    if (now - last_key_req_time < KEY_UPDATE_COOLDOWN_S) {
                                        printf("Rate limit: another new key request too soon. Ignoring.\n");
                                    } else {
                                        last_key_req_time = now;
                                        printf("Received 'new key' command. Waiting 5s for 'yes' confirmation...\n");
                                        state = STATE_WAITING_FOR_YES;
                                        clock_gettime(CLOCK_MONOTONIC, &state_deadline);
                                        state_deadline.tv_sec += 5;
                                    }
                                }

                                // Handle key confirmation ACK (after new key sent)
                                else if (state == STATE_WAITING_FOR_ACK && strcmp((char*)decrypted, "ACK") == 0) {
                                    printf("ACK received. Finalizing key update.\n");
                                    memcpy(s_key.cipher_key, pending_key, SESSION_KEY_SIZE);
                                    explicit_bzero(pending_key, sizeof(pending_key));
                                    print_hex("New key is now active: ", s_key.cipher_key, SESSION_KEY_SIZE);
                                    state = STATE_IDLE;
                                }

                                // Handle "clear key" command
                                else if (strcmp((char*)decrypted, "CMD: clear key") == 0) {
                                    printf("Received 'clear key' command. Zeroing session key (no new key sent).\n");
                                    explicit_bzero(s_key.cipher_key, SESSION_KEY_SIZE); // Zero out session key
                                    key_valid = false; // Mark the key as invalid
                                }

                                // Handle unknown commands or print the current key
                                else if (strcmp((char*)decrypted, "CMD: print key receiver") == 0 || strcmp((char*)decrypted, "CMD: print key *") == 0) {
                                    print_hex("Receiver's session key: ", s_key.cipher_key, SESSION_KEY_SIZE);
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
