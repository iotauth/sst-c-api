#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"

// Load config file from path and save the information in ctx struct.
// Also loads public and private key in EVP_PKEY struct.
// Stores the distribution_key.
// @param path config file path
// @return SST_ctx_t struct stores config, public and private keys, and
// distribution key.
SST_ctx_t *init_SST(const char *config_path);

// Request and get session key from Auth according to secure connection
// by using OpenSSL which provides the cryptography, MAC, and Block cipher etc..
// @param config_info config struct obtained from load_config()
// @return secure session key
session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list);

// Connect with other entity such as entity servers using secure session key.
// @param s_key session key struct received by Auth
// @param ctx config struct obtained from load_config()
// @return secure socket number
SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx);

// Try finding a target session key with its ID. If the entity has the target session key, return the session key.
// Otherwise, request and receive the target session key by ID from Auth and return the session key.
// @param target_session_key_id ID of the target session key.
// @param ctx SST context to communicate with Auth.
// @param existing_s_key_list list of session keys that currently exist.
session_key_t *get_session_key_by_ID(unsigned char* target_session_key_id, SST_ctx_t *ctx, session_key_list_t *existing_s_key_list);

// Wait the entity client to get the session key and
// make a secure connection using session key.
// Returns the session context for the secure communication if it succeeds,
// or returns NULL otherwise.
// @param config config struct for information
// @param clnt_sock entity client socket number
// @return session key struct
SST_session_ctx_t *server_secure_comm_setup(
    SST_ctx_t *ctx, int clnt_sock, session_key_list_t *existing_s_key_list);

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
                                    SST_session_ctx_t *session_ctx);

// Encrypt the message with session key and send the encrypted message to
// the socket.
// @param msg message to send
// @param msg_length length of message
// @param SST_session_ctx_t session ctx struct
void send_secure_message(char *msg, unsigned int msg_length,
                         SST_session_ctx_t *session_ctx);

// Encrypt buffer with session key.
// @param s_key session key to encrypt
// @param plaintext plaintext to be encrypted
// @param plaintext_length length of plaintext to be encrypted
// @param encrypted returned encrypted buffer
// @param encrypted_length length of returned encrypted buffer
int encrypt_buf_with_session_key(session_key_t *s_key, unsigned char *plaintext, size_t plaintext_length, unsigned char *encrypted, size_t *encrypted_length);

// Decrypt buffer with session key.
// @param s_key session key to decrypt
// @param encrypted encrypted buffer to be decrypted
// @param encrypted_length length of encrypted buffer to be decrypted
// @param decrypted returned decrypted buffer
// @param decrypted_length length of returned decrypted buffer
int decrypt_buf_with_session_key(session_key_t *s_key, unsigned char *encrypted, size_t encrypted_length, unsigned char *decrypted, size_t *decrypted_length);

// Frees memory used in session_key_list recursively.
// @param session_key_list_t session_key_list to free
void free_session_key_list_t(session_key_list_t *session_key_list);

// Free memory used in SST_ctx recursively.
// @param SST_ctx_t loaded SST_ctx_t to free
void free_SST_ctx_t(SST_ctx_t *ctx);


// Save session key list recursively.
// @param session_key_list_t session_key_list to save
// @param file_path file_path to save
void save_session_key_list(session_key_list_t *session_key_list, const char *file_path);

// Load session key list recursively.
// @param session_key_list_t session_key_list to load
// @param file_path file_path to load
void load_session_key_list(session_key_list_t *session_key_list, const char *file_path);

#endif  // C_API_H
