#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include "c_api.h"
#include "../../include/sst_crypto_embedded.h"

#define UART_DEVICE "/dev/serial0"
#define BAUDRATE B1000000
#define SESSION_KEY_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define PREAMBLE_BYTE_1 0xAA
#define PREAMBLE_BYTE_2 0x55
#define MSG_TYPE_ENCRYPTED 0x02

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

int main() {
    printf("Retrieving session key from SST...\n");
    SST_ctx_t *sst = init_SST("../sst.config");
    if (!sst) return fprintf(stderr, "SST init failed.\n"), 1;

    session_key_list_t *key_list = get_session_key(sst, init_empty_session_key_list());
    if (!key_list || key_list->num_key == 0) return fprintf(stderr, "No session key.\n"), 1;

    session_key_t s_key = key_list->s_key[0];
    print_hex("Session Key: ", s_key.cipher_key, SESSION_KEY_SIZE);

    int fd = init_serial(UART_DEVICE, BAUDRATE);
    if (fd < 0) return 1;

    // Step 1: Send preamble + key to Pico
    uint8_t preamble[2] = {0xAB, 0xCD};
    write(fd, preamble, 2);
    write(fd, s_key.cipher_key, SESSION_KEY_SIZE);
    usleep(5000); // short delay to flush
    printf("Sent preamble + session key over UART.\n");

    // Step 2: Listen for encrypted message
    printf("📡 Listening for encrypted message...\n");

    uint8_t byte;
    int state = 0;

    while (1) {
        if (read(fd, &byte, 1) == 1) {
            if (state == 0 && byte == PREAMBLE_BYTE_1) state = 1;
            else if (state == 1 && byte == PREAMBLE_BYTE_2) state = 2;
            else if (state == 2 && byte == MSG_TYPE_ENCRYPTED) {
                uint8_t nonce[NONCE_SIZE];
                uint8_t len_bytes[2];
                if (read_exact(fd, nonce, NONCE_SIZE) != NONCE_SIZE ||
                    read_exact(fd, len_bytes, 2) != 2) {
                    printf("Failed to read nonce or length\n");
                    state = 0;
                    continue;
                }

                uint16_t msg_len = (len_bytes[0] << 8) | len_bytes[1];
                printf("Reading %u bytes of ciphertext and %u bytes of tag...\n", msg_len, TAG_SIZE);

                if (msg_len > 1024) {
                    printf("Message too long: %u bytes\n", msg_len);
                    state = 0;
                    continue;
                }

                uint8_t ciphertext[msg_len];
                uint8_t tag[TAG_SIZE];
                uint8_t decrypted[msg_len];

                ssize_t c = read_exact(fd, ciphertext, msg_len);
                ssize_t t = read_exact(fd, tag, TAG_SIZE);

                if (c == msg_len && t == TAG_SIZE) {
                    print_hex("Nonce: ", nonce, NONCE_SIZE);
                    print_hex("Ciphertext: ", ciphertext, c);
                    print_hex("Tag: ", tag, TAG_SIZE);

                    int ret = sst_decrypt_gcm(
                        s_key.cipher_key,
                        nonce,
                        ciphertext, msg_len,
                        tag,
                        decrypted
                    );

                    if (ret == 0) {
                        printf("Decrypted: %.*s\n\n", msg_len, decrypted);
                    } else {
                        printf("AES-GCM decryption failed: %d\n\n", ret);
                    }
                } else {
                    printf("Incomplete ciphertext or tag\n");
                }

                state = 0;
            } else {
                state = 0;
            }
        }
    }

    close(fd);
    free_session_key_list_t(key_list);
    free_SST_ctx_t(sst);
    return 0;
}
