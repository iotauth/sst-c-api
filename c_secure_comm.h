#ifndef C_SECURE_COMM_H
#define C_SECURE_COMM_H

#include <stdbool.h>

#include "c_api.h"

// This file includes functions that uses the struct "session_key"

#define MAX_AUTH_COMM_LENGTH 1024

#define IDLE 0
#define HANDSHAKE_1_SENT 10
#define HANDSHAKE_1_RECEIVED 21
#define HANDSHAKE_2_SENT 22
#define IN_COMM 30
#define SESSION_KEY_EXPIRATION_TIME_SIZE 6
#define HANDSHAKE_1_LENGTH 74
#define HANDSHAKE_3_LENGTH 82

#define MAX_SESSION_KEY 10

typedef enum {
    INVALID_DISTRIBUTION_KEY,
    INVALID_SESSION_KEY_REQ,
    UNKNOWN_INTERNAL_ERROR,
} auth_alert_code;

// Parses the the reply message sending to Auth.
// Concat entity, auth nonce and information such as sender
// and purpose obtained from the config file.
// @param entity_nonce entity's nonce
// @param auth_nonce received auth's nonce
// @param num_key number of keys to receive from auth
// @param sender name of sender
// @param sender_length length of sender
// @param purpose purpose to get session key
// @param purpose_length length of purpose
// @param ret_length length of return buffer
// @return concated total buffer
unsigned char *serialize_message_for_auth(unsigned char *entity_nonce,
                                          unsigned char *auth_nonce,
                                          int num_key, char *sender,
                                          char *purpose,
                                          unsigned int *ret_length);

// Handles the AUTH_HELLO message.
// Checks if the auth_id received from the Auth matches with the auth_id loaded
// from the config. Then, creates the entity_nonce, and sends an auth request
// message with the correct number of keys, purpose, and requestIndex.
// @param data_buf input buffer with auth id, and auth nonce.
// @param ctx SST context to communicate with Auth.
// @param entity_nonce entity's nonce
// @param sock socket number
// @param num_key number of keys to receive from auth
// @param purpose purpose to get session key
// @param requestIndex request index for purpose
// @return 0 for success, -1 for fail
int handle_AUTH_HELLO(unsigned char *data_buf, SST_ctx_t *ctx,
                      unsigned char *entity_nonce, int sock, int num_key,
                      char *purpose, int requestIndex);

// Encrypt the message and send the request message to Auth.
// @param serialized total message
// @param serialized_length length of message
// @param ctx config struct obtained from load_config()
// @param sock socket number
// @param requestIndex request index for purpose
void send_auth_request_message(unsigned char *serialized,
                               unsigned int serialized_length, SST_ctx_t *ctx,
                               int sock, int requestIndex);

// Parse the data buffer and save distribution key into ctx
// @param data_buf total data buffer
// @param ctx config struct obtained from load_config()
// @param key_size size of the public crypto key
void save_distribution_key(unsigned char *data_buf, SST_ctx_t *ctx,
                           size_t key_size);

// Used in parse_session_key_response() for index.
// @param buf input buffer with crypto spec
// @param buf_length length of buf
// @param offset buffer index
// @param return_to_length length of return buffer
// @return buffer with crypto spec
unsigned char *parse_string_param(unsigned char *buf, unsigned int buf_length,
                                  int offset, unsigned int *return_to_length);

// Store the session key in the session key struct
// Must free when session_key expired or usage finished.
// @param ret session key struct to save key info
// @param buf input buffer with session key
// @return index number for another session key
unsigned int parse_session_key(session_key_t *ret, unsigned char *buf);

// Parses the handshake1 buffer to send.
// First generates the entity client's nonce to send to entity server,
// encrypts the nonce with session key, and
// make the total message including the session key id and encrypted nonce.
// @param s_key session key struct to encrypt the message
// @param entity_nonce nonce to protect the reply attack
// @param ret_length length of return buffer
// @return total buffer with session key id and encrypted message
unsigned char *parse_handshake_1(session_key_t *s_key,
                                 unsigned char *entity_nonce,
                                 unsigned int *ret_length);

// Check the nonce obtained in decryption with own nonce and
// make the encrypted message with other entity's nonce.
// @param data_buf input data buffer
// @param data_buf_length length of data buffer
// @param entity_nonce own nonce
// @param s_key session key struct
// @param ret_length length of return buffer
// @return buffer with encrypted message
unsigned char *check_handshake_2_send_handshake_3(unsigned char *data_buf,
                                                  unsigned int data_buf_length,
                                                  unsigned char *entity_nonce,
                                                  session_key_t *s_key,
                                                  unsigned int *ret_length);

// Sends a secure communication message using an encrypted session key-based
// protocol. The function constructs a message with a sequence number prepended,
// encrypts the message, wraps it into a sender buffer, and writes it to the
// socket.
// @param msg pointer to the plaintext message to be sent.
// @param msg_length length of the plaintext message in bytes.
// @param session_ctx pointer to the session context containing session key and
// socket information.
// @return the total number of bytes written to the socket, or -1 on failure.
int send_SECURE_COMM_message(char *msg, unsigned int msg_length,
                             SST_session_ctx_t *session_ctx);

// Returns the pointer of the decrypted buffer.
// @param encrypted_data input data buffer
// @param encrypted_data_length length of data buffer
// @param decrypted_data decrypted buffer including sequence number and payload
// @param decrypted_buf_length length of decrypted buffer
// @param SST_session_ctx_t session ctx struct

void decrypt_received_message(unsigned char *encrypted_data,
                              unsigned int encrypted_data_length,
                              unsigned char *decrypted_data,
                              unsigned int *decrypted_buf_length,
                              SST_session_ctx_t *session_ctx);

// Check the validity of session key by checking abs_validity
// @param session_key_t session_key to check validity
// @return 1 when expired, 0 when valid
int check_session_key_validity(session_key_t *session_key);

// Check if entity has session key and if not, request the session key to Auth.
// @param ctx config struct obtained from load_config()
// @param target_key_id id of session key
// @return session key struct according to key id
session_key_list_t *send_session_key_request_check_protocol(
    SST_ctx_t *ctx, unsigned char *target_key_id);

// Request the session key to Auth according to session key id via TCP
// connection
// @param config_info config struct for the entity information
// @return session_key_t struct according to key id
session_key_list_t *send_session_key_req_via_TCP(SST_ctx_t *ctx);

// TODO:(Dongha Kim): Implement session key request via UDP.
// Request the session key to Auth according to session key id via UDP
// connection.
// @param
// @return session key struct according to key id
// session_key_list_t *send_session_key_req_via_UDP(SST_ctx_t *ctx);

// Check the nonce obtained in decryption with own nonce and
// make the encrypted message with other entity's nonce.
// @param received_buf received buffer
// @param received_buf_length length of received buffer
// @param server_nonce own nonce
// @param s_key session key struct
// @param ret_length length of return buffer
// @return buffer with encrypted message
unsigned char *check_handshake1_send_handshake2(
    unsigned char *received_buf, unsigned int received_buf_length,
    unsigned char *server_nonce, session_key_t *s_key,
    unsigned int *ret_length);

// This function is used to find the session_key by its identifier (key_id)
// in the given session key list and returns the index of the found key.
// @param key_id the target key id to be found
// @param s_key_list the cached session_key_list
// @return index of the s_key_list if the key is found or -1 otherwise
int find_session_key(unsigned int key_id, session_key_list_t *s_key_list);

// Adds session key to the list.
// Appends at the destination list's rear_idx.
// @param s_key Session key to add
// @param existing_s_key_list Destination session_key_list
void add_session_key_to_list(session_key_t *s_key,
                             session_key_list_t *existing_s_key_list);

// Copys session key from src to dest.
// Does not free the src's session key. Free must needed.
// @param dest Session key destination pointer to copy to.
// @param src Session key src pointer to copy.
void copy_session_key(session_key_t *dest, session_key_t *src);

// Appends src list to dest list.
// Appends at the destination list's rear_idx.
// @param dest Destination session_key_list
// @param src Source session_key_list
void append_session_key_list(session_key_list_t *dest, session_key_list_t *src);

// Updates the validity of session key with the rel_validity.
// Makes the abs_validity to add the current time, and rel_validity.
// @param session_key_t the session_key to update.
void update_validity(session_key_t *session_key);

// Checks the session_key_list's left space to add new keys, and if full, checks
// if the keys are valid.
// @param requested_num_key the requested number of keys to add.
// @param session_key_list_t session_key list to check left space for list, and
// @return 1 when unaddable, 0 when addable
int check_session_key_list_addable(int requested_num_key,
                                   session_key_list_t *s_ley_list);

// Encrypts or decrypts a buffer using the provided session key. This function
// dynamically allocates memory for the output buffer based on the input length.
// @param s_key session_key_t structure containing encryption and authentication
// keys.
// @param input pointer to the input buffer to encrypt or decrypt.
// @param input_length size of the input buffer in bytes.
// @param output pointer to the dynamically allocated output buffer (allocated
// inside the function).
// @param output_length pointer to store the size of the output buffer in bytes.
// @param is_encrypt true for encryption, false for decryption.
// @return 0 on success, -1 if the session key is invalid or expired.
int encrypt_or_decrypt_buf_with_session_key(
    session_key_t *s_key, unsigned char *input, unsigned int input_length,
    unsigned char **output, unsigned int *output_length, bool is_encrypt);

// Encrypts or decrypts a buffer using the provided session key without dynamic
// memory allocation. The caller must allocate sufficient memory for the output
// buffer.
// @param s_key session_key_t structure containing encryption and authentication
// keys.
// @param input pointer to the input buffer to encrypt or decrypt.
// @param input_length size of the input buffer in bytes.
// @param output pointer to the pre-allocated output buffer.
// @param output_length pointer to store the size of the output buffer in bytes.
// @param is_encrypt true for encryption, false for decryption.
// @return 0 on success, -1 if the session key is invalid or expired.
int encrypt_or_decrypt_buf_with_session_key_without_malloc(
    session_key_t *s_key, unsigned char *input, unsigned int input_length,
    unsigned char *output, unsigned int *output_length, bool is_encrypt);

#endif  // C_SECURE_COMM_H
