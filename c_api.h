#ifndef C_API_H
#define C_API_H

#include <pthread.h>
#include <stdint.h>

#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define MAC_KEY_SIZE 32
#define MAX_CIPHER_KEY_SIZE 32
#define MAX_SESSION_KEY 10

#define SECURE_COMM_MSG 33

typedef struct {
    unsigned char key_id[SESSION_KEY_ID_SIZE];
    unsigned char abs_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char rel_validity[KEY_EXPIRATION_TIME_SIZE];
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    char enc_mode;
    char no_hmac_mode;
} session_key_t;

typedef struct {
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned int mac_key_size;
    unsigned char cipher_key[MAX_CIPHER_KEY_SIZE];
    unsigned int cipher_key_size;
    unsigned char abs_validity[DIST_KEY_EXPIRATION_TIME_SIZE];
    char enc_mode;
} distribution_key_t;

typedef struct {
    char name[32];
    // Currently, the config struct can hold up to two purposes.
    unsigned short purpose_index;
    char purpose[2][36];
    int numkey;
    char encryption_mode;
    char no_hmac_mode;
    char *auth_pubkey_path;
    char *entity_privkey_path;
    char auth_ip_addr[17];
    char auth_port_num[6];
    char entity_server_ip_addr[17];
    char entity_server_port_num[6];
    char network_protocol[4];
    char file_system_manager_ip_addr[17];
    char file_system_manager_port_num[6];
} config_t;

// This struct is used in receive_thread()
typedef struct {
    int sock;
    session_key_t s_key;
    unsigned int sent_seq_num;
    unsigned int received_seq_num;

} SST_session_ctx_t;

// This struct is a session_key_list. It can be easily initialized with macro
// INIT_SESSION_KEY_LIST(X)
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
session_key_list_t *init_empty_session_key_list();

// Request and get session key from Auth according to secure connection
// by using OpenSSL which provides the cryptography, MAC, and Block cipher etc..
// @param config_info config struct obtained from load_config()
// @return secure session key
session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list);

// Connect to entity_server using the session key. This function can be called
// after the connect() function, and uses the user's socket.
SST_session_ctx_t *secure_connect_to_server_with_socket(session_key_t *s_key,
                                                        int sock);

// Connect with other entity such as entity servers using the session key. This
// function contains the connect() function, and uses the
// secure_connect_to_server_with_socket() function.
// @param s_key session key struct received by Auth
// @return secure socket number
SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx);

// Try finding a target session key with its ID. If the entity has the target
// session key, return the session key. Otherwise, request and receive the
// target session key by ID from Auth and return the session key.
// @param target_session_key_id ID of the target session key.
// @param ctx SST context to communicate with Auth.
// @param existing_s_key_list list of session keys that currently exist.
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
int read_secure_message(int socket, unsigned char *buf,
                        unsigned int buf_length);

// Creates a thread to receive messages.
// Max buffer length is 1000 bytes currently.
// Use function receive_message() below for longer read buffer.
// @param arguments struct including session key and socket number
void *receive_thread(void *SST_session_ctx);

// Creates a thread to receive messages, by reading one bytes each at the SST
// header. Max buffer length is 1000 bytes currently.
// @param arguments struct including session key and socket number
void *receive_thread_read_one_each(void *SST_session_ctx);

// Receive the message and print the message after decrypting with session key.
// @param received_buf received message buffer
// @param received_buf_length length of received_buf
// @param SST_session_ctx_t session ctx struct
void receive_message(unsigned char *received_buf,
                     unsigned int received_buf_length,
                     SST_session_ctx_t *session_ctx);

// Return the buffer pointer of the decrypted buffer.
// If the user gives the read buffer as input, it will return the decrypted
// buffer. If an error occurs, returns NULL.
// @param received_buf received message buffer
// @param received_buf_length length of received_buf
// @param SST_session_ctx_t session ctx struct
unsigned char *return_decrypted_buf(unsigned char *received_buf,
                                    unsigned int received_buf_length,
                                    unsigned int *decrypted_buf_length,
                                    SST_session_ctx_t *session_ctx);

// Encrypt the message with session key and send the encrypted message to
// the socket.
// @param msg message to send
// @param msg_length length of message
// @param SST_session_ctx_t session ctx struct
int send_secure_message(char *msg, unsigned int msg_length,
                        SST_session_ctx_t *session_ctx);

// Encrypt buffer with session key.
// @param s_key session key to encrypt
// @param plaintext plaintext to be encrypted
// @param plaintext_length length of plaintext to be encrypted
// @param encrypted double pointer of returned encrypted buffer
// @param encrypted_length length of returned encrypted buffer
// @return 0 for success, 1 for fail
int encrypt_buf_with_session_key(session_key_t *s_key, unsigned char *plaintext,
                                 unsigned int plaintext_length,
                                 unsigned char **encrypted,
                                 unsigned int *encrypted_length);

// Decrypt buffer with session key.
// @param s_key session key to decrypt
// @param encrypted encrypted buffer to be decrypted
// @param encrypted_length length of encrypted buffer to be decrypted
// @param decrypted double pointer of returned decrypted buffer
// @param decrypted_length length of returned decrypted buffer
// @return 0 for success, 1 for fail
int decrypt_buf_with_session_key(session_key_t *s_key, unsigned char *encrypted,
                                 unsigned int encrypted_length,
                                 unsigned char **decrypted,
                                 unsigned int *decrypted_length);

int encrypt_buf_with_session_key_without_malloc(session_key_t *s_key,
                                                unsigned char *plaintext,
                                                unsigned int plaintext_length,
                                                unsigned char *encrypted,
                                                unsigned int *encrypted_length);
                                                
int decrypt_buf_with_session_key_without_malloc(session_key_t *s_key,
                                                unsigned char *encrypted,
                                                unsigned int encrypted_length,
                                                unsigned char *decrypted,
                                                unsigned int *decrypted_length);

// Frees memory used in session_key_list recursively.
// @param session_key_list_t session_key_list to free
void free_session_key_list_t(session_key_list_t *session_key_list);

// Free memory used in SST_ctx recursively.
// @param SST_ctx_t loaded SST_ctx_t to free
void free_SST_ctx_t(SST_ctx_t *ctx);

// Save session key list recursively.
// @param session_key_list_t session_key_list to save
// @param file_path file_path to save
// @return 0 for success, 1 for fail
int save_session_key_list(session_key_list_t *session_key_list,
                          const char *file_path);

// Load session key list recursively.
// @param session_key_list_t session_key_list to load
// @param file_path file_path to load
// @return 0 for success, 1 for fail
int load_session_key_list(session_key_list_t *session_key_list,
                          const char *file_path);

int save_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len);

int load_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len);

// Returns the session key id buffer to be saved in unsigned integer.
// @param buf session key id buffer to convert to int
// @param byte_length length of session key id buffer
unsigned int convert_skid_buf_to_int(unsigned char *buf, int byte_length);

int CTR_encrypt_buf_with_session_key(
    session_key_t *s_key, const uint64_t initial_iv_high,
    const uint64_t initial_iv_low, uint64_t file_offset,
    const unsigned char *data, size_t data_size, unsigned char *out_data,
    size_t out_data_buf_length, unsigned int *processed_size);

int CTR_decrypt_buf_with_session_key(
    session_key_t *s_key, const uint64_t initial_iv_high,
    const uint64_t initial_iv_low, uint64_t file_offset,
    const unsigned char *data, size_t data_size, unsigned char *out_data,
    size_t out_data_buf_length, unsigned int *processed_size);

void generate_random_nonce(int length, unsigned char *buf);

#endif  // C_API_H
