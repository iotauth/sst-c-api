#ifndef C_COMMON_H
#define C_COMMON_H

#include <stddef.h>
#include <stdint.h>

// Message Type //
#define AUTH_HELLO 0
#define ENTITY_HELLO 1
#define AUTH_SESSION_KEY_REQ 10
#define AUTH_SESSION_KEY_RESP 11
#define SESSION_KEY_REQ_IN_PUB_ENC 20
#define SESSION_KEY_RESP_WITH_DIST_KEY 21
#define SESSION_KEY_REQ 22
#define SESSION_KEY_RESP 23
#define SKEY_HANDSHAKE_1 30
#define SKEY_HANDSHAKE_2 31
#define SKEY_HANDSHAKE_3 32
#define SECURE_COMM_MSG 33
#define FIN_SECURE_COMM 34
#define SECURE_PUB 40
#define MIGRATION_REQ_WITH_SIGN 50
#define MIGRATION_RESP_WITH_SIGN 51
#define MIGRATION_REQ_WITH_MAC 52
#define MIGRATION_RESP_WITH_MAC 53
#define ADD_READER_REQ_IN_PUB_ENC 60
#define ADD_READER_RESP_WITH_DIST_KEY 61
#define ADD_READER_REQ 62
#define ADD_READER_RESP 63
#define AUTH_ALERT 100

// Size //
#define MESSAGE_TYPE_SIZE 1
#define MAX_PAYLOAD_BUF_SIZE 5
#define HS_NONCE_SIZE 8
#define HS_INDICATOR_SIZE 1 + HS_NONCE_SIZE * 2
#define MAX_HS_BUF_LENGTH 256
#define MAX_ERROR_MESSAGE_LENGTH 128

// Auth Hello //
#define AUTH_ID_LEN 4
#define NUMKEY_SIZE 4
#define NONCE_SIZE 8

// Session key Resp //
#define MAC_SIZE 32
#define KEY_ID_SIZE 8

// Handshake struct including nonce, reply_nonce(received),
// and Diffie Helman parameter

typedef struct {
    unsigned char nonce[HS_NONCE_SIZE];
    unsigned char reply_nonce[HS_NONCE_SIZE];
    unsigned char dhParam[];  // TODO: The buffer size is temporarily defined
                              // none. Need to implement diffie_helman protocol.
} HS_nonce_t;

#if defined(__GNUC__)
#define ATTRIBUTE_FORMAT_PRINTF(f, s) __attribute__((format(printf, f, s)))
#else
#define ATTRIBUTE_FORMAT_PRINTF(f, s)
#endif

// Debug logging (only enabled in DEBUG mode)
#ifdef DEBUG
#define SST_DEBUG_ENABLED 1
#else
#define SST_DEBUG_ENABLED 0
#endif

// Utility function for printing unsigned char buffer in hex string.
// Only prints when dcmake -DCMAKE_BUILD_TYPE=DEBUG is on.
// @param buf given buffer of unsigned chars.
// @param size length of the given buffer.
void print_buf_debug(const unsigned char *buf, size_t size);

// Utility function for printing unsigned char buffer in hex string.
// @param buf given buffer of unsigned chars.
// @param size length of the given buffer.
void print_buf_log(const unsigned char *buf, size_t size);

// Generate secure random nonce using OpenSSL.
// @param length length to generate the nonce.
// @param buf buffer to save the generated nonce.
// @return 0 for success, -1 for fail
int generate_nonce(int length, unsigned char *buf);

// Write number num in buffer size of n.
// @param num number to write in buffer
// @param n buffer size
// @param buf output buffer
void write_in_n_bytes(uint64_t num, int n, unsigned char *buf);

// Make the total int number in big endian buffer.
// @param buf input buffer
// @param byte_length buffer length to make the total number
// @return total number of input buffer
unsigned int read_unsigned_int_BE(unsigned char *buf, int byte_length);

uint64_t read_unsigned_long_int_BE(unsigned char *buf, int byte_length);

// Extracts number value of variable length integer from given buffer.
// When
//     buf = (variable_length_buf) + (data_buf)
//     reads (variable_length_buf) to unsigned int (payload_length)
//     reads (variable_length_buf)'s buf_length to unsigned int
//     (payload_buf_length)
//  @param buf input buffer
//  @param buf_length length of input buffer
//  @param num number value of the variable length integer.
//  @param var_len_int_buf_size size of the buffer containing the variable
//  length integer
void var_length_int_to_num(unsigned char *buf, unsigned int buf_length,
                           unsigned int *num, int *var_len_int_buf_size);

// Make the data_length to a variable length.
// @param num number to be converted into variable length integer.
// @param var_len_int_buf buffer to contain the variable length integer.
// @param var_len_int_buf_size size of the buffer containing the variable
// length integer.
void num_to_var_length_int(unsigned int num, unsigned char *var_len_int_buf,
                           unsigned int *var_len_int_buf_size);

// Parses received message into 'message_type',
// and data after msg_type+payload_buf to 'data_buf'.
// Message type from received message and
// information which we needs from received message.
// @param received_buf input buffer
// @param received_buf_length length of input buffer
// @param message_type message type of received input buffer
// @param data_buf_length length of return information
// @return starting address of information from input buffer
unsigned char *parse_received_message(unsigned char *received_buf,
                                      unsigned int received_buf_length,
                                      unsigned char *message_type,
                                      unsigned int *data_buf_length);

// Reads the SST header, and returns the message type, start pointer of the
// SST's payload, and the payload's length.
// @param socket socket to read
// @param message_type SST message type
// @param buf Return buffer
// @param buf_length Return buffer's length
int read_header_return_data_buf_pointer(int socket, unsigned char *message_type,
                                        unsigned char *buf,
                                        unsigned int buf_length);

// Make the buffer sending to Auth by using make_buffer_header() and
// concat_buffer_header_and_payload().
// @param payload input data buffer
// @param payload_length length of input data buffer
// @param MESSAGE_TYPE message type according to purpose
// @param sender buffer to send to Auth
// @param sender_length length of sender buffer
void make_sender_buf(unsigned char *payload, unsigned int payload_length,
                     unsigned char MESSAGE_TYPE, unsigned char *sender,
                     unsigned int *sender_length);

// Connect to the server as client by using ip address, port number, and sock.
// May be the entity_client-Auth, entity_client - entity_server, entity_server -
// Auth.
// @param ip_addr IP address of server
// @param port_num port number to connect IP address
// @param sock socket number
int connect_as_client(const char *ip_addr, int port_num, int *sock);

// Serializes a buffer based on the nonce type such as nonce and reply nonce.
// @param nonce a nonce made by yourself
// @param reply_nonce nonce received from the other entity or Auth
// @param ret return_buffer:indicator_1byte + nonce_8byte + reply_nonce_8byte
// @return 0 for success, -1 for fail
int serialize_handshake(unsigned char *nonce, unsigned char *reply_nonce,
                        unsigned char *ret);

// Parses the received buffer to struct HS_nonce_t
// See parse_handshake() for details.
// @param buf input buffer incluing nonce.
// @param ret return buffer
void parse_handshake(unsigned char *buf, HS_nonce_t *ret);

// Computes the positive remainder of a modulo operation.
// This function ensures that the result is always non-negative, even if the
// first operand (a) is negative. It adjusts the result by adding the modulus
// (b) when the computed remainder is negative.
// @param a The dividend (integer to be divided).
// @param b The divisor (modulus).
// @return The positive remainder when a is divided by b.
int mod(int a, int b);

// Reads data from a socket into a buffer.
// This function reads up to `buf_length` bytes from the specified socket into
// the provided buffer. It handles error cases, including invalid sockets, read
// failures, and connection closures.
// @param socket The socket file descriptor to read from.
// @param buf A pointer to the buffer where the data will be stored.
// @param buf_length The maximum number of bytes to read into the buffer.
// @return The number of bytes successfully read, or -1 if an error occurred.
int sst_read_from_socket(int socket, unsigned char *buf,
                         unsigned int buf_length);

// Writes data to a socket from a buffer.
// This function writes up to `buf_length` bytes from the provided buffer
// to the specified socket. It handles partial writes, socket errors, and
// connection closures, ensuring that the full buffer is written.
// @param socket The socket file descriptor to write to.
// @param buf A pointer to the buffer containing the data to be written.
// @param buf_length The number of bytes to write from the buffer.
// @return The number of bytes successfully written, or -1 if an error occurred.
int sst_write_to_socket(int socket, const unsigned char *buf,
                        unsigned int buf_length);

// Checks message type if it is SECURE_COMM_MSG. This is needed as a separate
// function not to define SECURE_COMM_MSG in c_api.h
// @param message type to check.
// @return int 0 for true, -1 for false.
int check_SECURE_COMM_MSG_type(unsigned char message_type);

#endif  // C_COMMON_H
