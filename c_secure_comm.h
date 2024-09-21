#ifndef C_SECURE_COMM_H
#define C_SECURE_COMM_H

#include "c_api.h"
#include "c_common.h"
#include "c_crypto.h"
#include "load_config.h"

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

// Encrypt the message and send the request message to Auth.
// @param serialized total message
// @param serialized_length length of message
// @param ctx config struct obtained from load_config()
// @param sock socket number
// @param requestIndex request index for purpose
void send_auth_request_message(unsigned char *serialized,
                               unsigned int serialized_length, SST_ctx_t *ctx,
                               int sock, int requestIndex);

// Encrypt the message and sign the encrypted message.
// @param buf input buffer
// @param buf_len length of buf
// @param ctx config struct obtained from load_config()
// @param message message with encrypted message and signature
// @param message_length length of message
unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len,
                                SST_ctx_t *ctx, unsigned int *message_length);

// Separate the message received from Auth and
// store the distribution key in the distribution key struct
// Must free distribution_key.mac_key, distribution_key.cipher_key
// @param parsed_distribution_key distribution key struct to save information
// @param buf input buffer with distribution key
void parse_distribution_key(distribution_key_t *parsed_distribution_key,
                            unsigned char *buf);

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

// Separate the session key, nonce, and crypto spec from the message.
// @param buf input buffer with session key, nonce, and crypto spec
// @param buf_length length of buf
// @param reply_nonce nonce to compare with
// @param session_key_list session key list struct
void parse_session_key_response(SST_ctx_t *ctx, unsigned char *buf,
                                unsigned int buf_length,
                                unsigned char *reply_nonce,
                                session_key_list_t *session_key_list);

// Serializes the session_key request.
// Symmetric encrypt authenticates the serialize_message_for_auth with the
// distribution key. Serializes the sender_length, sender_name, and encrypted
// message above.
// @param serialized return buffer of serialize_message_for_auth
// @param serialized_length buffer length of return of
// serialize_message_for_auth buffer
// @param dist_key key to symmetric encrypt & authenticate
// @param name entity_sender name.
// @param ret_length
// @return unsigned char * return buffer
unsigned char *serialize_session_key_req_with_distribution_key(
    unsigned char *serialized, unsigned int serialized_length,
    distribution_key_t *dist_key, char *name, unsigned int *ret_length);

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

// Decrypts message, reads seq_num, checks validity, and prints message
// Print the received message and sequence number after check validity of
// session key.
// @param data input data buffer
// @param data_length length of data buffer
// @param SST_session_ctx_t session ctx struct
void print_received_message(unsigned char *data, unsigned int data_length,
                            SST_session_ctx_t *session_ctx);

// Returns the pointer of the decrypted buffer.
// @param data input data buffer
// @param data_length length of data buffer
// @param SST_session_ctx_t session ctx struct

unsigned char *decrypt_received_message(unsigned char *data,
                                        unsigned int data_length,
                                        unsigned int *decrypted_buf_length,
                                        SST_session_ctx_t *session_ctx);

// Check the validity of session key by checking abs_validity
// @param session_key_t session_key to check validity
// @return 1 when expired, 0 when valid
int check_session_key_validity(session_key_t *session_key);

// Check the validity of the buffer.
// @param validity unsigned char buffer to check.
// @return 1 when expired, 0 when valid
int check_validity(unsigned char *validity);

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

// This function is used when checking if the server already has the session_key
// requested Checks if the s_key_list's idx'th session_key_id equals with the
// key_id
// @param key_id the target key id to obtain
// @param s_key_list the cached session_key_list
// @param idx current index
// @return index of the s_key_list
int check_session_key(unsigned int key_id, session_key_list_t *s_key_list,
                      int idx);

// Copys session key from src to dest.
// Does not free the src's session key. Free must needed.
// @param dest Session key destination pointer to copy to.
// @param src Session key src pointer to copy.
void copy_session_key(session_key_t *dest, session_key_t *src);

// Adds session key to the list.
// Appends at the destination list's rear_idx.
// @param s_key Session key to add
// @param existing_s_key_list Destination session_key_list
void add_session_key_to_list(session_key_t *s_key,
                             session_key_list_t *existing_s_key_list);

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

int encrypt_or_decrypt_buf_with_session_key(
    session_key_t *s_key, unsigned char *input, unsigned int input_length,
    unsigned char **output, unsigned int *output_length, int encrypt);

int encrypt_or_decrypt_buf_with_session_key_without_malloc(
    session_key_t *s_key, unsigned char *input, unsigned int input_length,
    unsigned char *output, unsigned int *output_length, int encrypt);

int CTR_encrypt_or_decrypt_buf_with_session_key(
    session_key_t *s_key, const uint64_t initial_iv_high,
    const uint64_t initial_iv_low, uint64_t file_offset,
    const unsigned char *data, unsigned char *out_data, size_t data_size,
    size_t out_data_size, unsigned int *processed_size, int encrypt);

#endif  // C_SECURE_COMM_H
