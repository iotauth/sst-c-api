#ifndef C_API_H
#define C_API_H

#include <arpa/inet.h>
#include <pthread.h>

#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define MAC_KEY_SIZE 32
#define MAX_CIPHER_KEY_SIZE 32
#define MAX_SESSION_KEY 10
#define MAX_ENTITY_NAME_LENGTH 32
#define MAX_PURPOSE_LENGTH 64
#define NETWORK_PROTOCOL_NAME_LENGTH 4

#define AES_IV_SIZE 16
#define SEQ_NUM_SIZE 8
#define MAX_PAYLOAD_LENGTH 1024
#define ROUND_UP_TO_Y(X, Y) ((((X) / Y) + 1) * Y)
#define MAX_SECURE_COMM_MSG_LENGTH                                      \
    1 + 2 + AES_IV_SIZE +                                               \
        ROUND_UP_TO_Y(SEQ_NUM_SIZE + MAX_PAYLOAD_LENGTH, AES_IV_SIZE) + \
        MAC_KEY_SIZE  // Should be 1091

typedef enum {
    AES_128_CBC,
    AES_128_CTR,
    AES_128_GCM,
} AES_encryption_mode_t;

typedef enum {
    USE_HMAC,
    NO_HMAC,
} hmac_mode_t;

typedef struct {
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    uint64_t abs_validity;
    uint64_t rel_validity;
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    AES_encryption_mode_t enc_mode;
    hmac_mode_t hmac_mode;
} session_key_t;

typedef struct {
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    uint64_t abs_validity;
    AES_encryption_mode_t enc_mode;
} distribution_key_t;

typedef struct {
    char name[MAX_ENTITY_NAME_LENGTH + 1];
    // Currently, the config struct can hold up to two purposes.
    unsigned short purpose_index;
    char purpose[2][MAX_PURPOSE_LENGTH + 1];
    int numkey;
    AES_encryption_mode_t encryption_mode;
    hmac_mode_t hmac_mode;
    int auth_id;
    char *auth_pubkey_path;
    char *entity_privkey_path;
    char auth_ip_addr[INET_ADDRSTRLEN];
    int auth_port_num;
    char entity_server_ip_addr[INET_ADDRSTRLEN];
    int entity_server_port_num;
    char network_protocol[NETWORK_PROTOCOL_NAME_LENGTH];
    char file_system_manager_ip_addr[INET_ADDRSTRLEN];
    int file_system_manager_port_num;
} config_t;

// This struct is used in receive_thread_read_one_each()
typedef struct {
    int sock;
    session_key_t s_key;
    unsigned int sent_seq_num;
    unsigned int received_seq_num;
} SST_session_ctx_t;

// This struct is a session_key_list.
// num_key is the number of keys in this list.
// rear_idx is a indicator that points the next position to add to the list.
// The session_key_list as a circular array.
typedef struct {
    int num_key;
    int rear_idx;
    session_key_t *s_key;
} session_key_list_t;

// This struct contains distribution_key, loaded config, public and private
// keys.
typedef struct {
    distribution_key_t dist_key;
    config_t *config;
    void *pub_key;
    void *priv_key;
    pthread_mutex_t mutex;
} SST_ctx_t;

// Load config file from path and save the information in ctx struct.
// Also loads public and private key in EVP_PKEY struct.
// Stores the distribution_key.
// @param path config file path
// @return SST_ctx_t struct stores config, public and private keys, and
// distribution key.
SST_ctx_t *init_SST(const char *config_path);

// Initializes empty session_key_list.
// Mallocs session_key_list_t and the session_key_t as much as the
// MAX_SESSION_KEY.
// @return Empty session key list.
session_key_list_t *init_empty_session_key_list(void);

// Request and get session key from Auth according to secure connection
// by using OpenSSL which provides the cryptography, MAC, and Block cipher etc..
// @param config_info config struct obtained from load_config()
// @return secure session key list.
session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list);

// Connect to entity_server using the session key. This function can be called
// after the connect() function, and uses the user's socket.
// @param s_key session key struct received by Auth
// @param sock Connected socket number
// @return Connected session_ctx.
SST_session_ctx_t *secure_connect_to_server_with_socket(session_key_t *s_key,
                                                        int sock);

// Connect with other entity such as entity servers using the session key. This
// function contains the connect() function, and uses the
// secure_connect_to_server_with_socket() function.
// @param s_key session key struct received by Auth
// @param ctx config struct obtained from load_config()
// @return Connected session_ctx.
SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx);

// Try finding a target session key with its ID. If the entity has the target
// session key, return the session key. Otherwise, request and receive the
// target session key by ID from Auth and return the session key.
// @param target_session_key_id ID of the target session key.
// @param ctx SST context to communicate with Auth.
// @param existing_s_key_list list of session keys that currently exist.
// @param return The session key received with the target ID.
session_key_t *get_session_key_by_ID(unsigned char *target_session_key_id,
                                     SST_ctx_t *ctx,
                                     session_key_list_t *existing_s_key_list);

// Wait the entity client to get the session key and
// make a secure connection using session key.
// Returns the session context for the secure communication if it succeeds,
// or returns NULL otherwise.
// @param config config struct for information
// @param clnt_sock entity client socket number
// @return session key struct
SST_session_ctx_t *server_secure_comm_setup(
    SST_ctx_t *ctx, int clnt_sock, session_key_list_t *existing_s_key_list);

// Read SECURE_COMM_MESSAGE, and return buffer, and bytes read.
// @param plaintext The decrypted plaintext
// @param session_ctx session ctx struct
// @return the total number of bytes read from the socket, or -1 on failure.
int read_secure_message(unsigned char *plaintext,
                        SST_session_ctx_t *session_ctx);

// Creates a thread to receive messages, by reading one bytes each at the SST
// header. Max buffer length is 1000 bytes currently.
// @param arguments struct including session key and socket number
void *receive_thread_read_one_each(void *SST_session_ctx);

// Encrypt the message with session key and send the encrypted message to
// the socket.
// @param msg message to send
// @param msg_length length of message
// @param SST_session_ctx_t session ctx struct
// @return the total number of bytes written to the socket, or -1 on failure.
int send_secure_message(char *msg, unsigned int msg_length,
                        SST_session_ctx_t *session_ctx);

// Encrypt buffer with session key. This mallocs data, so the buffer must be
// freed after use.
// @param s_key session key to encrypt
// @param plaintext plaintext to be encrypted
// @param plaintext_length length of plaintext to be encrypted
// @param encrypted double pointer of returned encrypted buffer
// @param encrypted_length length of returned encrypted buffer
// @return 0 for success, -1 for fail
int encrypt_buf_with_session_key(session_key_t *s_key, unsigned char *plaintext,
                                 unsigned int plaintext_length,
                                 unsigned char **encrypted,
                                 unsigned int *encrypted_length);

// Decrypt buffer with session key. This mallocs data, so the buffer must be
// freed after use.
// @param s_key session key to decrypt
// @param encrypted encrypted buffer to be decrypted
// @param encrypted_length length of encrypted buffer to be decrypted
// @param decrypted double pointer of returned decrypted buffer
// @param decrypted_length length of returned decrypted buffer
// @return 0 for success, -1 for fail
int decrypt_buf_with_session_key(session_key_t *s_key, unsigned char *encrypted,
                                 unsigned int encrypted_length,
                                 unsigned char **decrypted,
                                 unsigned int *decrypted_length);

// Encrypts buffer with session key without mallocing the return buffer. The
// user must provide the ciphertext buffer.
// @param s_key session key to encrypt
// @param plaintext plaintext to be encrypted
// @param plaintext_length length of plaintext to be encrypted
// @param encrypted pointer the user should provide to get the encrypted buffer
// filled
// @param encrypted_length length of returned encrypted buffer
// @return 0 for success, -1 for fail
int encrypt_buf_with_session_key_without_malloc(session_key_t *s_key,
                                                unsigned char *plaintext,
                                                unsigned int plaintext_length,
                                                unsigned char *encrypted,
                                                unsigned int *encrypted_length);

// Decrypt buffer with session key without mallocing the return buffer. The user
// must provide the plaintext buffer.
// @param s_key session key to decrypt
// @param encrypted encrypted buffer to be decrypted
// @param encrypted_length length of encrypted buffer to be decrypted
// @param decrypted pointer the user should provide to get the encrypted buffer
// filled
// @param decrypted_length length of returned decrypted buffer
// @return 0 for success, -1 for fail
int decrypt_buf_with_session_key_without_malloc(session_key_t *s_key,
                                                unsigned char *encrypted,
                                                unsigned int encrypted_length,
                                                unsigned char *decrypted,
                                                unsigned int *decrypted_length);

// Saves session key list recursively.
// @param session_key_list_t session_key_list to save
// @param file_path file_path to save
// @return 0 for success, -1 for fail
int save_session_key_list(session_key_list_t *session_key_list,
                          const char *file_path);

// Loads session key list recursively.
// @param session_key_list_t session_key_list to load
// @param file_path file_path to load
// @return 0 for success, -1 for fail
int load_session_key_list(session_key_list_t *session_key_list,
                          const char *file_path);

// Saves session key list using a password and salt, additionally encrypting the
// session_key_list
// @param session_key_list_t session_key_list to save
// @param file_path file_path to save
// @param password password to encrypt the session_key_list
// @param password_len length of the password
// @param salt salt char to salt the password
// @param salt_len length of the salt
// @return 0 for success, -1 for fail
int save_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len);

// Loads session key list using a password and salt, additionally encrypting the
// session_key_list
// @param session_key_list_t session_key_list to save
// @param file_path file_path to save
// @param password password to encrypt the session_key_list
// @param password_len length of the password
// @param salt salt char to salt the password
// @param salt_len length of the salt
// @return 0 for success, -1 for fail
int load_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len);

// Returns the session key id buffer to be saved in unsigned integer.
// @param buf session key id buffer to convert to int
// @param byte_length length of session key id buffer
// @return Session key id converted to integer.
unsigned int convert_skid_buf_to_int(unsigned char *buf, int byte_length);

// Generates a random nonce.
// This is used not to directly #include OpenSSL libraries.
// @param length Length of the nonce
// @param buf Pointer of the buffer with the random nonce.
// @return 0 for success, -1 for fail
int generate_random_nonce(int length, unsigned char *buf);

// Frees memory used in session_key_list recursively.
// @param session_key_list_t session_key_list to free
void free_session_key_list_t(session_key_list_t *session_key_list);

// Free memory used in SST_ctx recursively.
// @param SST_ctx_t loaded SST_ctx_t to free
void free_SST_ctx_t(SST_ctx_t *ctx);

/**
 * @brief Generates a cryptographically secure random integer within a given
 * range.
 *
 * This function uses OpenSSL's RAND_bytes() to generate cryptographically
 * strong random numbers. It securely converts these bytes into an integer
 * within the specified inclusive range [min, max].
 *
 * @param min The minimum integer value (inclusive) of the desired random range.
 * @param max The maximum integer value (inclusive) of the desired random range.
 * @return A cryptographically secure random integer between min and max
 * (inclusive). On error, returns -1 (e.g., if RAND_bytes fails).
 *
 * @note Ensure OpenSSL is properly initialized before calling this function.
 *
 * @example
 * @code
 * int num = secure_rand(56, 144);
 * if (num != -1) {
 *     printf("Random number: %d\n", num);
 * } else {
 *     fprintf(stderr, "Random number generation failed.\n");
 * }
 * @endcode
 */
int secure_rand(int min, int max);

#if defined(__GNUC__)
#define ATTRIBUTE_FORMAT_PRINTF(f, s) __attribute__((format(printf, f, s)))
#else
#define ATTRIBUTE_FORMAT_PRINTF(f, s)
#endif

// Print out debug messages. This will be printed only when the
// cmake -DCMAKE_BUILD_TYPE=DEBUG is on.
// Uses printf-style formatting.
// @param fmt Format string for the debug message.
// @param ... Additional arguments for formatting.
void SST_print_debug(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

// Print out log messages.
// Uses printf-style formatting.
// @param fmt Format string for the debug message.
// @param ... Additional arguments for formatting.
void SST_print_log(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

// Print out error messages along with errno if set.
// Uses printf-style formatting.
// @param fmt Format string for the debug message.
// @param ... Additional arguments for formatting.
void SST_print_error(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

// Print out error message and exit program.
// Uses printf-style formatting.
// @param fmt Format string for the debug message.
// @param ... Additional arguments for formatting.
void SST_print_error_exit(const char *fmt, ...);

#endif  // C_API_H
