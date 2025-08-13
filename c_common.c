#include "c_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void SST_print_debug(const char *fmt, ...) {
    if (SST_DEBUG_ENABLED) {
        va_list args;
        va_start(args, fmt);
        printf("DEBUG: ");
        vprintf(fmt, args);
        va_end(args);
    }
}

void SST_print_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

// Print out error messages along with errno if set.
void SST_print_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    // Print the "ERROR:" prefix to stderr
    fprintf(stderr, "ERROR: ");
    // Print the formatted error message to stderr (without adding a newline)
    vfprintf(stderr, fmt, args);
    // Print errno if it is set
    if (errno != 0) {
        fprintf(stderr, " (errno: %d, %s)", errno, strerror(errno));
    }
    // End the line after the error message and errno
    fprintf(stderr, "\n");

    va_end(args);
}

void SST_print_error_exit(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    SST_print_error(fmt, args);
    va_end(args);
    exit(1);
}

void *SST_print_error_return_null(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    SST_print_error(fmt, args);
    va_end(args);
    return NULL;
}

void print_buf_debug(const unsigned char *buf, size_t size) {
    char hex[size * 3 + 1];
    for (size_t i = 0; i < size; i++) {
        // 4 = space(1) + two hex digits(2) + null charactor(1)
        snprintf(hex + 3 * i, 4, " %.2x", buf[i]);
    }
    SST_print_debug("Hex:%s\n", hex);
}

void print_buf_log(const unsigned char *buf, size_t size) {
    char hex[size * 3 + 1];
    for (size_t i = 0; i < size; i++) {
        // 4 = space(1) + two hex digits(2) + null charactor(1)
        snprintf(hex + 3 * i, 4, " %.2x", buf[i]);
    }
    SST_print_log("Hex:%s\n", hex);
}

void generate_nonce(int length, unsigned char *buf) {
    int x = RAND_bytes(buf, length);
    if (x == -1) {
        SST_print_error("Failed to create Random Nonce");
        exit(1);
    }
}

void write_in_n_bytes(uint64_t num, int n, unsigned char *buf) {
    for (int i = 0; i < n; i++) {
        buf[i] |= num >> 8 * (n - 1 - i);
    }
}

unsigned int read_unsigned_int_BE(unsigned char *buf, int byte_length) {
    unsigned int num = 0;
    for (int i = 0; i < byte_length; i++) {
        num |= buf[i] << 8 * (byte_length - 1 - i);
    }
    return num;
}

uint64_t read_unsigned_long_int_BE(unsigned char *buf, int byte_length) {
    uint64_t num_valid = 1ULL;
    for (int i = 0; i < byte_length; i++) {
        uint64_t num = 1ULL << 8 * (byte_length - 1 - i);
        num_valid |= num * buf[i];
    }
    return num_valid;
}

void var_length_int_to_num(unsigned char *buf, unsigned int buf_length,
                           unsigned int *num, int *var_len_int_buf_size) {
    *num = 0;
    *var_len_int_buf_size = 0;
    for (unsigned int i = 0; i < buf_length; i++) {
        *num |= (buf[i] & 127) << (7 * i);
        if ((buf[i] & 128) == 0) {
            *var_len_int_buf_size = i + 1;
            break;
        }
    }
}

void num_to_var_length_int(unsigned int num, unsigned char *var_len_int_buf,
                           unsigned int *var_len_int_buf_size) {
    *var_len_int_buf_size = 1;
    while (num > 127) {
        var_len_int_buf[*var_len_int_buf_size - 1] = 128 | (num & 127);
        *var_len_int_buf_size += 1;
        num >>= 7;
    }
    var_len_int_buf[*var_len_int_buf_size - 1] = num;
}

unsigned char *parse_received_message(unsigned char *received_buf,
                                      unsigned int received_buf_length,
                                      unsigned char *message_type,
                                      unsigned int *data_buf_length) {
    *message_type = received_buf[0];
    if (*message_type == AUTH_ALERT) {
        return received_buf + 1;
    }
    int var_length_buf_size;
    var_length_int_to_num(received_buf + MESSAGE_TYPE_SIZE, received_buf_length,
                          data_buf_length, &var_length_buf_size);
    return received_buf + MESSAGE_TYPE_SIZE + var_length_buf_size;
}

int read_variable_length_one_byte_each(int socket, unsigned char *buf) {
    int length = 1;
    int received_buf_length = sst_read_from_socket(socket, buf, 1);
    if (received_buf_length < 0) {
        SST_print_error(
            "Socket read error in read_variable_length_one_byte_each().\n");
        return -1;
    }
    if (buf[0] > 127) {
        return length + read_variable_length_one_byte_each(socket, buf + 1);
    } else {
        return length;
    }
}

int read_header_return_data_buf_pointer(int socket, unsigned char *message_type,
                                        unsigned char *buf,
                                        unsigned int buf_length) {
    unsigned char received_buf[MAX_PAYLOAD_BUF_SIZE];
    // Read the first byte.
    int received_buf_length =
        sst_read_from_socket(socket, received_buf, MESSAGE_TYPE_SIZE);
    if (received_buf_length < 0) {
        SST_print_error(
            "Socket read error in read_header_return_data_buf_pointer().\n");
        return -1;
    }
    *message_type = received_buf[0];
    // Read one bytes each, until the variable length buffer ends.
    int var_length_buf_size = read_variable_length_one_byte_each(
        socket, received_buf + MESSAGE_TYPE_SIZE);
    if (var_length_buf_size < 0) {
        SST_print_error("Failed to read_variable_length_one_byte_each().");
        return -1;
    }
    int var_length_buf_size_checked;
    unsigned int ret_length;
    // Decode the variable length buffer and get the bytes to read.
    var_length_int_to_num(received_buf + MESSAGE_TYPE_SIZE, var_length_buf_size,
                          &ret_length, &var_length_buf_size_checked);
    if (var_length_buf_size != var_length_buf_size_checked) {
        SST_print_error("Wrong header calculation... Exiting...");
        return -1;
    }
    if (ret_length > buf_length) {
        SST_print_error("Larger buffer size required.");
        return -1;
    }
    int bytes_read = sst_read_from_socket(socket, buf, buf_length);
    if ((unsigned int)bytes_read != ret_length) {
        SST_print_error("Wrong read... Exiting..");
        return -1;
    }
    return bytes_read;
}

void make_buffer_header(unsigned int data_length, unsigned char MESSAGE_TYPE,
                        unsigned char *header, unsigned int *header_length) {
    unsigned char payload_buf[MAX_PAYLOAD_BUF_SIZE];
    unsigned int payload_buf_len;
    num_to_var_length_int(data_length, payload_buf, &payload_buf_len);
    *header_length = MESSAGE_TYPE_SIZE + payload_buf_len;
    header[0] = MESSAGE_TYPE;
    memcpy(header + MESSAGE_TYPE_SIZE, payload_buf, payload_buf_len);
}

void concat_buffer_header_and_payload(
    unsigned char *header, unsigned int header_length, unsigned char *payload,
    unsigned int payload_length, unsigned char *ret, unsigned int *ret_length) {
    memcpy(ret, header, header_length);
    memcpy(ret + header_length, payload, payload_length);
    *ret_length = header_length + payload_length;
}

void make_sender_buf(unsigned char *payload, unsigned int payload_length,
                     unsigned char MESSAGE_TYPE, unsigned char *sender,
                     unsigned int *sender_length) {
    unsigned char header[MAX_PAYLOAD_BUF_SIZE + 1];
    unsigned int header_length;
    make_buffer_header(payload_length, MESSAGE_TYPE, header, &header_length);
    concat_buffer_header_and_payload(header, header_length, payload,
                                     payload_length, sender, sender_length);
}

int connect_as_client(const char *ip_addr, int port_num, int *sock) {
    struct sockaddr_in serv_addr;
    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if (*sock == -1) {
        SST_print_error("socket() error");
        return -1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  // IPv4
    serv_addr.sin_addr.s_addr =
        inet_addr(ip_addr);  // the ip_address to connect to
    serv_addr.sin_port = htons(port_num);

    int count_retries = 0;
    int ret = -1;
    // FIXME(Dongha Kim): Make the maximum number of retries configurable.
    while (count_retries++ < 10) {
        ret = connect(*sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (ret < 0) {
            SST_print_error("Connection attempt %d failed. Retrying...\n",
                            count_retries);
            usleep(500);  // Wait 500 microseconds before retrying.
            continue;
        } else {
            SST_print_debug("Successfully connected to %s:%d on attempt %d.\n",
                            ip_addr, port_num, count_retries);
            break;
        }
    }
    if (ret < 0) {
        SST_print_error("Failed to connect to %s:%d after %d attempts.\n",
                        ip_addr, port_num, count_retries - 1);
    }
    return ret;
}

int serialize_handshake(unsigned char *nonce, unsigned char *reply_nonce,
                        unsigned char *ret) {
    if (nonce == NULL && reply_nonce == NULL) {
        SST_print_error("Handshake should include at least one nonce.");
        return -1;
    }
    unsigned char indicator = 0;
    if (nonce != NULL) {
        indicator += 1;
        memcpy(ret + 1, nonce, HS_NONCE_SIZE);
    }
    if (reply_nonce != NULL) {
        indicator += 2;
        memcpy(ret + 1 + HS_NONCE_SIZE, reply_nonce, HS_NONCE_SIZE);
    }
    // TODO: add dhParam options.
    ret[0] = indicator;
    return 0;
}

void parse_handshake(unsigned char *buf, HS_nonce_t *ret) {
    if ((buf[0] & 1) != 0) {
        memcpy(ret->nonce, buf + 1, HS_NONCE_SIZE);
    }
    if ((buf[0] & 2) != 0) {
        memcpy(ret->reply_nonce, buf + 1 + HS_NONCE_SIZE, HS_NONCE_SIZE);
    }
    if ((buf[0] & 4) != 0) {
        memcpy(ret->dhParam, buf + 1 + HS_NONCE_SIZE * 2, HS_NONCE_SIZE);
    }
}

int mod(int a, int b) {
    int r = a % b;
    return r < 0 ? r + b : r;
}

int sst_read_from_socket(int socket, unsigned char *buf,
                         unsigned int buf_length) {
    if (socket < 0) {
        // Socket is not open.
        errno = EBADF;
        return -1;
    }
    int length_read = read(socket, buf, buf_length);
    if (length_read < 0) {
        SST_print_error("Reading from socket %d failed.", socket);
    } else if (length_read == 0) {
        SST_print_error("Connection closed from socket %d.", socket);
    }
    return length_read;
}

int sst_write_to_socket(int socket, const unsigned char *buf,
                        unsigned int buf_length) {
    if (socket < 0) {
        // Socket is not open.
        errno = EBADF;
        return -1;
    }

    unsigned int total_written = 0;
    ssize_t length_written;

    // Continue writing until the entire buffer is written
    while (total_written < buf_length) {
        length_written =
            write(socket, buf + total_written, buf_length - total_written);

        if (length_written <= 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            continue;
        }
        if (length_written < 0) {
            // Error occurred while writing
            SST_print_error_exit("Writing to socket failed.");
        } else if (length_written == 0) {
            // Socket closed unexpectedly
            SST_print_error_exit("Connection closed while writing.");
        }

        // Update the total number of bytes written
        total_written += length_written;
    }

    return total_written;
}

int check_SECURE_COMM_MSG_type(unsigned char message_type) {
    if (message_type == SECURE_COMM_MSG) {
        return 0;
    } else {
        return -1;
    }
}
