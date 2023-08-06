#ifndef C_API_H
#define C_API_H

#include "c_secure_comm.h"

// Load config file from path and save the information in ctx struct.
// Also loads public and private key in EVP_PKEY struct.
// Stores the distribution_key.
// @param path config file path
// @return SST_ctx_t struct stores config, public and private keys, and
// distribution key.
SST_ctx_t *init_SST(char *config_path);

// Add the server's ip address and port number to the SST_ctx_t.
// @param ctx Configuration struct obtained from init_SST().
void get_server_ip_addr_and_port_num(SST_ctx_t *ctx,
                                     struct sockaddr_in server_fd);

// Request and get session key from Auth according to secure connection
// by using OpenSSL which provides the cryptography, MAC, and Block cipher etc..
// @param ctx Configuration struct obtained from init_SST()
// @param existing_s_key_list The original session_key_list
// @return session_key_list_t
session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list);

// Connect to entity_server using the session key. This function can be called
// after the connect() function, and uses the user's socket.
SST_session_ctx_t *secure_connect_to_server_with_socket(session_key_t *s_key,
                                                        SST_ctx_t *ctx,
                                                        int sock);

// Connect with other entity such as entity servers using the session key. This
// function contains the connect() function, and uses the
// secure_connect_to_server_with_socket() function.
// @param s_key session key struct received by Auth
// @return secure socket number
SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx);

// Wait the entity client to get the session key and
// make a secure connection using session key.
// @param ctx Configuration struct obtained from init_SST()
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
// @param ctx Configuration struct obtained from init_SST()
void send_secure_message(char *msg, unsigned int msg_length,
                         SST_session_ctx_t *session_ctx);

// Frees memory used in session_key_list recursively.
// @param session_key_list_t session_key_list to free
void free_session_key_list_t(session_key_list_t *session_key_list);

// Free memory used in SST_ctx recursively.
// @param SST_ctx_t loaded SST_ctx_t to free
void free_SST_ctx_t(SST_ctx_t *ctx);

#endif  // C_API_H
