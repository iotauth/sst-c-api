#include "c_secure_comm.h"

#include <unistd.h>

#include "c_common.h"
#include "c_crypto.h"

unsigned char entity_client_state;
unsigned char entity_server_state;

typedef enum {
    INIT,
    AUTH_HELLO_RECEIVED,
    SESSION_KEY_RESP_RECEIVED,
    SESSION_KEY_RESP_WITH_DIST_KEY_RECEIVED,
    FINISHED,
} send_state;

unsigned char *serialize_message_for_auth(unsigned char *entity_nonce,
                                          unsigned char *auth_nonce,
                                          int num_key, char *sender,
                                          char *purpose,
                                          unsigned int *ret_length) {
    size_t sender_length = strlen(sender);
    size_t purpose_length = strlen(purpose);

    unsigned char *ret = (unsigned char *)malloc(
        NONCE_SIZE * 2 + NUMKEY_SIZE + sender_length + purpose_length +
        8 /* +8 for two var length ints */);

    size_t offset = 0;
    memcpy(ret + offset, entity_nonce, NONCE_SIZE);
    offset += NONCE_SIZE;

    memcpy(ret + offset, auth_nonce, NONCE_SIZE);
    offset += NONCE_SIZE;
    if (num_key != 0) {
        unsigned char num_key_buf[NUMKEY_SIZE];
        memset(num_key_buf, 0, NUMKEY_SIZE);
        write_in_n_bytes(num_key, NUMKEY_SIZE, num_key_buf);

        memcpy(ret + offset, num_key_buf, NUMKEY_SIZE);
        offset += NUMKEY_SIZE;
    }

    unsigned char var_length_int_buf[4];
    unsigned int var_length_int_len;

    num_to_var_length_int(sender_length, var_length_int_buf,
                          &var_length_int_len);
    memcpy(ret + offset, var_length_int_buf, var_length_int_len);
    offset += var_length_int_len;

    memcpy(ret + offset, sender, sender_length);
    offset += sender_length;

    num_to_var_length_int(purpose_length, var_length_int_buf,
                          &var_length_int_len);
    memcpy(ret + offset, var_length_int_buf, var_length_int_len);
    offset += var_length_int_len;

    memcpy(ret + offset, purpose, purpose_length);
    offset += purpose_length;

    *ret_length = offset;

    return ret;
}

int handle_AUTH_HELLO(unsigned char *data_buf, SST_ctx_t *ctx,
                      unsigned char *entity_nonce, int sock, int num_key,
                      char *purpose, int requestIndex) {
    unsigned char auth_nonce[NONCE_SIZE];
    unsigned int auth_id = read_unsigned_int_BE(data_buf, AUTH_ID_LEN);
    if (auth_id != (unsigned int)ctx->config->auth_id) {
        SST_print_error("Auth ID NOT matched.");
        return -1;
    }
    memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE);
    RAND_bytes(entity_nonce, NONCE_SIZE);
    unsigned int serialized_length;
    unsigned char *serialized = serialize_message_for_auth(
        entity_nonce, auth_nonce, num_key, ctx->config->name, purpose,
        &serialized_length);
    send_auth_request_message(serialized, serialized_length, ctx, sock,
                              requestIndex);
    return 0;
}

// Encrypt the message and sign the encrypted message.
// @param buf input buffer
// @param buf_len length of buf
// @param ctx config struct obtained from load_config()
// @param message message with encrypted message and signature
// @param message_length length of message
static unsigned char *encrypt_and_sign(unsigned char *buf, unsigned int buf_len,
                                       SST_ctx_t *ctx,
                                       unsigned int *message_length) {
    size_t encrypted_length;
    unsigned char *encrypted =
        public_encrypt(buf, buf_len, RSA_PKCS1_OAEP_PADDING,
                       (EVP_PKEY *)ctx->pub_key, &encrypted_length);
    size_t sigret_length;
    unsigned char *sigret = SHA256_sign(
        encrypted, encrypted_length, (EVP_PKEY *)ctx->priv_key, &sigret_length);
    *message_length = sigret_length + encrypted_length;
    unsigned char *message = (unsigned char *)malloc(*message_length);
    memcpy(message, encrypted, encrypted_length);
    memcpy(message + encrypted_length, sigret, sigret_length);
    OPENSSL_free(encrypted);
    OPENSSL_free(sigret);
    return message;
}

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
static unsigned char *serialize_session_key_req_with_distribution_key(
    unsigned char *serialized, unsigned int serialized_length,
    distribution_key_t *dist_key, char *name, unsigned int *ret_length) {
    unsigned int temp_length;
    unsigned char *temp = NULL;
    if (symmetric_encrypt_authenticate(
            serialized, serialized_length, dist_key->mac_key,
            dist_key->mac_key_size, dist_key->cipher_key,
            dist_key->cipher_key_size, AES_128_CBC_IV_SIZE, dist_key->enc_mode,
            0, &temp, &temp_length)) {
        SST_print_error_exit(
            "Error during encryption while "
            "serialize_session_key_req_with_distribution_key\n");
    }
    unsigned int name_length = strlen(name);
    unsigned char length_buf[] = {name_length};
    unsigned char *ret = malloc(1 + name_length + temp_length);
    unsigned int offset = 0;
    memcpy(ret, length_buf, 1);
    offset += 1;
    memcpy(ret + offset, name, name_length);
    offset += name_length;
    memcpy(ret + offset, temp, temp_length);
    OPENSSL_free(temp);
    *ret_length = 1 + strlen(name) + temp_length;
    return ret;
}

// Check the validity of the buffer.
// @param validity unsigned char buffer to check.
// @return -1 when expired, 0 when valid
static int check_validity(unsigned char *validity) {
    if ((uint64_t)time(NULL) >
        read_unsigned_long_int_BE(validity, KEY_EXPIRATION_TIME_SIZE) / 1000) {
        return -1;
    } else {
        return 0;
    }
}

// Separate the message received from Auth and
// store the distribution key in the distribution key struct
// Must free distribution_key.mac_key, distribution_key.cipher_key
// @param parsed_distribution_key distribution key struct to save information
// @param buf input buffer with distribution key
static void parse_distribution_key(distribution_key_t *parsed_distribution_key,
                                   unsigned char *buf) {
    memcpy(parsed_distribution_key->abs_validity, buf,
           DIST_KEY_EXPIRATION_TIME_SIZE);
    unsigned int cur_index = DIST_KEY_EXPIRATION_TIME_SIZE;
    unsigned int cipher_key_size = buf[cur_index];
    parsed_distribution_key->cipher_key_size = cipher_key_size;
    cur_index += 1;
    memcpy(parsed_distribution_key->cipher_key, buf + cur_index,
           cipher_key_size);
    cur_index += cipher_key_size;
    unsigned int mac_key_size = buf[cur_index];
    parsed_distribution_key->mac_key_size = mac_key_size;
    cur_index += 1;
    memcpy(parsed_distribution_key->mac_key, buf + cur_index, mac_key_size);
}

// Set the session key's encryption mode and hmac_mode to the SST_ctx's
// modes.
// @param ctx The SST_ctx_t to get the config.
// @param s_key The target session key to set the modes.
static void update_enc_mode_and_hmac_mode_to_session_key(SST_ctx_t *ctx,
                                                         session_key_t *s_key) {
    s_key->enc_mode = ctx->config->encryption_mode;
    s_key->hmac_mode = ctx->config->hmac_mode;
}

// Separate the session key, nonce, and crypto spec from the message.
// @param buf input buffer with session key, nonce, and crypto spec
// @param buf_length length of buf
// @param reply_nonce nonce to compare with
// @param session_key_list session key list struct
static void parse_session_key_response(SST_ctx_t *ctx, unsigned char *buf,
                                       unsigned int buf_length,
                                       unsigned char *reply_nonce,
                                       session_key_list_t *session_key_list) {
    memcpy(reply_nonce, buf, NONCE_SIZE);
    unsigned int buf_idx = NONCE_SIZE;
    unsigned int ret_length;
    unsigned char *ret =
        parse_string_param(buf, buf_length, buf_idx, &ret_length);
    // TODO: need to apply cryptoSpec?
    //~~use ret~~
    free(ret);
    buf_idx += ret_length;
    unsigned int session_key_list_length =
        read_unsigned_int_BE(&buf[buf_idx], 4);

    buf_idx += 4;
    for (unsigned int i = 0; i < session_key_list_length; i++) {
        buf = buf + buf_idx;
        buf_idx = parse_session_key(&session_key_list->s_key[i], buf);
        update_enc_mode_and_hmac_mode_to_session_key(
            ctx, &session_key_list->s_key[i]);
    }
    session_key_list->num_key = (int)session_key_list_length;
    session_key_list->rear_idx = session_key_list->num_key % MAX_SESSION_KEY;
}

void send_auth_request_message(unsigned char *serialized,
                               unsigned int serialized_length, SST_ctx_t *ctx,
                               int sock, int requestIndex) {
    if (check_validity(ctx->dist_key.abs_validity)) {  // when dist_key expired
        SST_print_debug(
            "Current distribution key expired, requesting new "
            "distribution key as well...\n");
        unsigned int enc_length;
        unsigned char *enc =
            encrypt_and_sign(serialized, serialized_length, ctx, &enc_length);
        free(serialized);
        unsigned char message[MAX_AUTH_COMM_LENGTH];
        unsigned int message_length;
        if (requestIndex) {
            make_sender_buf(enc, enc_length, SESSION_KEY_REQ_IN_PUB_ENC,
                            message, &message_length);
        } else {
            make_sender_buf(enc, enc_length, ADD_READER_REQ_IN_PUB_ENC, message,
                            &message_length);
        }
        int bytes_written = write_to_socket(sock, message, message_length);
        if ((unsigned int)bytes_written != message_length) {
            SST_print_error_exit("Failed to write data to socket.");
        }
        OPENSSL_free(enc);
    } else {
        unsigned int enc_length;
        unsigned char *enc = serialize_session_key_req_with_distribution_key(
            serialized, serialized_length, &ctx->dist_key, ctx->config->name,
            &enc_length);
        free(serialized);
        unsigned char message[MAX_AUTH_COMM_LENGTH];
        unsigned int message_length;
        if (requestIndex) {
            make_sender_buf(enc, enc_length, SESSION_KEY_REQ, message,
                            &message_length);
        } else {
            make_sender_buf(enc, enc_length, ADD_READER_REQ, message,
                            &message_length);
        }
        int bytes_written = write_to_socket(sock, message, message_length);
        if ((unsigned int)bytes_written != message_length) {
            SST_print_error_exit("Failed to write data to socket.");
        }
        OPENSSL_free(enc);
    }
}

void save_distribution_key(unsigned char *data_buf, SST_ctx_t *ctx,
                           size_t key_size) {
    signed_data_t signed_data;

    // parse data
    memcpy(signed_data.data, data_buf, key_size);
    memcpy(signed_data.sign, data_buf + key_size, key_size);

    // verify
    SHA256_verify(signed_data.data, key_size, signed_data.sign, key_size,
                  (EVP_PKEY *)ctx->pub_key);
    SST_print_debug("Auth signature verified.\n");

    // decrypt encrypted_distribution_key
    size_t decrypted_dist_key_buf_length;
    unsigned char *decrypted_dist_key_buf = private_decrypt(
        signed_data.data, key_size, RSA_PKCS1_OAEP_PADDING,
        (EVP_PKEY *)ctx->priv_key, &decrypted_dist_key_buf_length);

    // parse decrypted_dist_key_buf to mac_key & cipher_key
    parse_distribution_key(&ctx->dist_key, decrypted_dist_key_buf);
    ctx->dist_key.enc_mode = ctx->config->encryption_mode;
    free(decrypted_dist_key_buf);
}

unsigned char *parse_string_param(unsigned char *buf, unsigned int buf_length,
                                  int offset, unsigned int *return_to_length) {
    unsigned int num;
    unsigned int var_len_int_buf_size;
    var_length_int_to_num(buf + offset, buf_length, &num,
                          &var_len_int_buf_size);
    if (var_len_int_buf_size == 0) {
        SST_print_error_exit(
            "Buffer size of the variable length integer cannot be 0.");
    }
    *return_to_length = num + var_len_int_buf_size;
    unsigned char *return_to = (unsigned char *)malloc(*return_to_length);
    memcpy(return_to, buf + offset + var_len_int_buf_size, num);
    return return_to;
}

unsigned int parse_session_key(session_key_t *ret, unsigned char *buf) {
    memcpy(ret->key_id, buf, SESSION_KEY_ID_SIZE);
    unsigned int cur_idx = SESSION_KEY_ID_SIZE;
    memcpy(ret->abs_validity, buf + cur_idx, ABS_VALIDITY_SIZE);
    cur_idx += ABS_VALIDITY_SIZE;
    memcpy(ret->rel_validity, buf + cur_idx, REL_VALIDITY_SIZE);
    cur_idx += REL_VALIDITY_SIZE;

    // copy cipher_key
    ret->cipher_key_size = buf[cur_idx];
    cur_idx += 1;
    memcpy(ret->cipher_key, buf + cur_idx, ret->cipher_key_size);
    cur_idx += ret->cipher_key_size;

    // copy mac_key
    ret->mac_key_size = buf[cur_idx];
    cur_idx += 1;
    memcpy(ret->mac_key, buf + cur_idx, ret->mac_key_size);
    cur_idx += ret->mac_key_size;

    return cur_idx;
}

unsigned char *parse_handshake_1(session_key_t *s_key,
                                 unsigned char *entity_nonce,
                                 unsigned int *ret_length) {
    RAND_bytes(entity_nonce, HS_NONCE_SIZE);
    unsigned char indicator_entity_nonce[1 + HS_NONCE_SIZE];
    memcpy(indicator_entity_nonce + 1, entity_nonce, HS_NONCE_SIZE);
    indicator_entity_nonce[0] = 1;

    unsigned int encrypted_length;
    unsigned char *encrypted = NULL;
    if (symmetric_encrypt_authenticate(
            indicator_entity_nonce, 1 + HS_NONCE_SIZE, s_key->mac_key,
            MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE,
            AES_128_CBC_IV_SIZE, s_key->enc_mode, 0, &encrypted,
            &encrypted_length)) {
        SST_print_error_exit(
            "Error during encryption while parse_handshake_1\n");
    }

    *ret_length = encrypted_length + KEY_ID_SIZE;
    unsigned char *ret = (unsigned char *)malloc(*ret_length);
    memcpy(ret, s_key->key_id, KEY_ID_SIZE);
    memcpy(ret + KEY_ID_SIZE, encrypted, encrypted_length);
    free(encrypted);
    return ret;
}

unsigned char *check_handshake_2_send_handshake_3(unsigned char *data_buf,
                                                  unsigned int data_buf_length,
                                                  unsigned char *entity_nonce,
                                                  session_key_t *s_key,
                                                  unsigned int *ret_length) {
    SST_print_debug("Received session key handshake2!\n");
    unsigned int decrypted_length;
    unsigned char *decrypted = NULL;
    if (symmetric_decrypt_authenticate(
            data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE,
            s_key->cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
            s_key->enc_mode, 0, &decrypted, &decrypted_length)) {
        SST_print_error_exit(
            "Error during decryption in checking handshake2.\n");
    }
    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);

    // compare my_nonce and received_nonce
    if (strncmp((const char *)hs.reply_nonce, (const char *)entity_nonce,
                HS_NONCE_SIZE) != 0) {
        SST_print_error_exit(
            "Comm init failed: server NOT verified, nonce NOT matched, "
            "disconnecting...\n");
    } else {
        SST_print_debug("Server authenticated/authorized by solving nonce!\n");
    }

    // send handshake_3
    unsigned char buf[HS_INDICATOR_SIZE];
    memset(buf, 0, HS_INDICATOR_SIZE);
    serialize_handshake(entity_nonce, hs.nonce, buf);

    unsigned char *ret = NULL;
    if (symmetric_encrypt_authenticate(buf, HS_INDICATOR_SIZE, s_key->mac_key,
                                       MAC_KEY_SIZE, s_key->cipher_key,
                                       CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
                                       s_key->enc_mode, 0, &ret, ret_length)) {
        SST_print_error_exit(
            "Error during encryption while send_handshake_3.\n");
    }
    return ret;
}

int send_SECURE_COMM_message(char *msg, unsigned int msg_length,
                             SST_session_ctx_t *session_ctx) {
    if (check_session_key_validity(&session_ctx->s_key)) {
        SST_print_error_exit("Session key expired!\n");
    }
    unsigned char buf[SEQ_NUM_SIZE + msg_length];
    memset(buf, 0, SEQ_NUM_SIZE + msg_length);
    write_in_n_bytes(session_ctx->sent_seq_num, SEQ_NUM_SIZE, buf);
    memcpy(buf + SEQ_NUM_SIZE, (unsigned char *)msg, msg_length);

    unsigned int estimate_encrypted_length =
        get_expected_encrypted_total_length(
            SEQ_NUM_SIZE + msg_length, AES_128_IV_SIZE, MAC_KEY_SHA256_SIZE,
            session_ctx->s_key.enc_mode, session_ctx->s_key.hmac_mode);
    unsigned char encrypted_stack[estimate_encrypted_length];
    unsigned int encrypted_length;
    if (encrypt_buf_with_session_key_without_malloc(
            &session_ctx->s_key, buf, SEQ_NUM_SIZE + msg_length,
            encrypted_stack, &encrypted_length)) {
        SST_print_error_exit("Encryption failed.");
    }

    session_ctx->sent_seq_num++;
    unsigned char
        sender_buf[MAX_PAYLOAD_LENGTH];  // TODO: Currently the send message
                                         // does not support dynamic sizes,
                                         // the max length is shorter than
                                         // 1024. Must need to decide static
                                         // or dynamic buffer size.
    unsigned int sender_buf_length;
    make_sender_buf(encrypted_stack, encrypted_length, SECURE_COMM_MSG,
                    sender_buf, &sender_buf_length);

    int bytes_written =
        write_to_socket(session_ctx->sock, sender_buf, sender_buf_length);
    if ((unsigned int)bytes_written != sender_buf_length) {
        SST_print_error_exit("Failed to write data to socket.");
    }
    return bytes_written;
}

void print_received_message(unsigned char *data, unsigned int data_length,
                            SST_session_ctx_t *session_ctx) {
    unsigned int decrypted_length;
    unsigned char *decrypted = decrypt_received_message(
        data, data_length, &decrypted_length, session_ctx);
    printf("%s\n", decrypted + SEQ_NUM_SIZE);
    free(decrypted);
}

unsigned char *decrypt_received_message(unsigned char *data,
                                        unsigned int data_length,
                                        unsigned int *decrypted_buf_length,
                                        SST_session_ctx_t *session_ctx) {
    unsigned char *decrypted = NULL;
    if (symmetric_decrypt_authenticate(
            data, data_length, session_ctx->s_key.mac_key, MAC_KEY_SIZE,
            session_ctx->s_key.cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
            session_ctx->s_key.enc_mode, session_ctx->s_key.hmac_mode,
            &decrypted, decrypted_buf_length)) {
        SST_print_error_exit("Error during decrypting received message.\n");
    }
    unsigned int received_seq_num =
        read_unsigned_int_BE(decrypted, SEQ_NUM_SIZE);
    if (received_seq_num != session_ctx->received_seq_num) {
        SST_print_error_exit("Wrong sequence number expected.");
    }
    if (check_session_key_validity(&session_ctx->s_key)) {
        SST_print_error_exit("Session key expired!\n");
    }
    session_ctx->received_seq_num++;
    SST_print_debug("Received seq_num: %d.\n", received_seq_num);
    // This returns SEQ_NUM_BUFFER(8) + decrypted_buffer;
    return decrypted;
}

int check_session_key_validity(session_key_t *session_key) {
    return check_validity(session_key->abs_validity);
}

session_key_list_t *send_session_key_request_check_protocol(
    SST_ctx_t *ctx, unsigned char *target_key_id) {
    // TODO: check if needed
    // Temporary code. need to load?
    unsigned char target_session_key_cache[10];
    unsigned int target_session_key_cache_length;
    target_session_key_cache_length =
        (unsigned char)sizeof("none") / sizeof(unsigned char) - 1;
    memcpy(target_session_key_cache, "none", target_session_key_cache_length);
    if (strcmp((const char *)ctx->config->network_protocol, "TCP") ==
        0) {  // TCP
        session_key_list_t *s_key_list = send_session_key_req_via_TCP(ctx);
        if (s_key_list == NULL) {
            return NULL;
        }
        SST_print_debug("Received %d keys.n", ctx->config->numkey);

        // SecureCommServer.js handleSessionKeyResp
        //  if(){} //TODO: migration
        //  if(){} //TODO: check received_dist_key null;
        //  if(strncmp(callback_params.target_session_key_cache, "Clients",
        //  callback_params.target_session_key_cache_length) == 0){}
        if (strncmp((const char *)target_session_key_cache, "none",
                    target_session_key_cache_length) == 0) {
            // check received (keyId from auth == keyId from entity_client)
            if (strncmp((const char *)s_key_list->s_key[0].key_id,
                        (const char *)target_key_id,
                        SESSION_KEY_ID_SIZE) != 0) {
                SST_print_error_exit("Session key id is NOT as expected\n");
            } else {
                SST_print_debug("Session key id is as expected.\n");
            }
            return s_key_list;
        }
    } else if (strcmp((const char *)ctx->config->network_protocol, "UDP") ==
               0) {
        // TODO:(Dongha Kim): Implement session key request via UDP.
        // session_key_list_t *s_key_list = send_session_key_req_via_UDP(NULL);
        // return s_key_list;
    }
    return SST_print_error_return_null("Invalid network protocol name.");
}

session_key_list_t *send_session_key_req_via_TCP(SST_ctx_t *ctx) {
    int sock;
    connect_as_client((const char *)ctx->config->auth_ip_addr,
                      ctx->config->auth_port_num, &sock);

    session_key_list_t *session_key_list = malloc(sizeof(session_key_list_t));

    session_key_list->s_key = malloc(sizeof(session_key_t) * MAX_SESSION_KEY);

    unsigned char entity_nonce[NONCE_SIZE];

    int state = INIT;
    while (state == INIT || state == AUTH_HELLO_RECEIVED) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
        int received_buf_length =
            read_from_socket(sock, received_buf, sizeof(received_buf));

        if (received_buf_length < 0) {
            SST_print_error_exit(
                "Socket read eerror in send_session_key_req_via_TCP().\n");
        }
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (state == INIT && message_type == AUTH_HELLO) {
            state = AUTH_HELLO_RECEIVED;
            if (handle_AUTH_HELLO(
                    data_buf, ctx, entity_nonce, sock, ctx->config->numkey,
                    ctx->config->purpose[ctx->config->purpose_index], 1)) {
                return NULL;
            }
        } else if (state == AUTH_HELLO_RECEIVED &&
                   message_type == SESSION_KEY_RESP) {
            state = SESSION_KEY_RESP_RECEIVED;
            SST_print_debug(
                "Received session key response encrypted with distribution "
                "key.\n");
            unsigned int decrypted_length;
            unsigned char *decrypted;
            if (symmetric_decrypt_authenticate(
                    data_buf, data_buf_length, ctx->dist_key.mac_key,
                    ctx->dist_key.mac_key_size, ctx->dist_key.cipher_key,
                    ctx->dist_key.cipher_key_size, AES_128_CBC_IV_SIZE,
                    ctx->config->encryption_mode, 0, &decrypted,
                    &decrypted_length)) {
                SST_print_error_exit(
                    "Error during decryption after receiving "
                    "SESSION_KEY_RESP.\n");
            }
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(ctx, decrypted, decrypted_length,
                                       reply_nonce, session_key_list);
            free(decrypted);
            SST_print_debug("Reply_nonce in sessionKeyResp: ");
            print_buf_debug(reply_nonce, NONCE_SIZE);
            if (strncmp((const char *)reply_nonce, (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {
                return SST_print_error_return_null("Auth nonce NOT verified.");
            } else {
                SST_print_debug("Auth nonce verified!\n");
            }
            close(sock);
            state = FINISHED;
            return session_key_list;

        } else if (state == AUTH_HELLO_RECEIVED &&
                   message_type == SESSION_KEY_RESP_WITH_DIST_KEY) {
            state = SESSION_KEY_RESP_WITH_DIST_KEY_RECEIVED;
            size_t key_size = RSA_KEY_SIZE;
            unsigned int encrypted_session_key_length =
                data_buf_length - (key_size * 2);
            unsigned char encrypted_session_key[encrypted_session_key_length];
            memcpy(encrypted_session_key, data_buf + key_size * 2,
                   encrypted_session_key_length);
            save_distribution_key(data_buf, ctx, key_size);

            // decrypt session_key with decrypted_dist_key_buf
            unsigned int decrypted_session_key_response_length;
            unsigned char *decrypted_session_key_response;
            if (symmetric_decrypt_authenticate(
                    encrypted_session_key, encrypted_session_key_length,
                    ctx->dist_key.mac_key, ctx->dist_key.mac_key_size,
                    ctx->dist_key.cipher_key, ctx->dist_key.cipher_key_size,
                    AES_128_CBC_IV_SIZE, ctx->config->encryption_mode, 0,
                    &decrypted_session_key_response,
                    &decrypted_session_key_response_length)) {
                SST_print_error_exit(
                    "Error during decryption after receiving "
                    "SESSION_KEY_RESP_WITH_DIST_KEY\n");
            }

            // parse decrypted_session_key_response for nonce comparison &
            // session_key.
            unsigned char reply_nonce[NONCE_SIZE];
            parse_session_key_response(ctx, decrypted_session_key_response,
                                       decrypted_session_key_response_length,
                                       reply_nonce, session_key_list);
            free(decrypted_session_key_response);
            SST_print_debug("Reply_nonce in sessionKeyResp: ");
            print_buf_debug(reply_nonce, NONCE_SIZE);
            if (strncmp((const char *)reply_nonce, (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                return SST_print_error_return_null("Auth nonce NOT verified.");
            } else {
                SST_print_debug("Auth nonce verified!\n");
            }
            close(sock);
            state = FINISHED;
            return session_key_list;
        } else if (message_type == AUTH_ALERT) {
            session_key_list->num_key = 0;
            switch (data_buf[0]) {
                case INVALID_DISTRIBUTION_KEY:
                    SST_print_error("Invalid Distribution Key.\n");
                    break;
                case INVALID_SESSION_KEY_REQ:
                    SST_print_error("Invalid Session Key Request.\n");
                    break;
                case UNKNOWN_INTERNAL_ERROR:
                    SST_print_error("Unknown Internal Error.\n");
                    break;
                default:
                    SST_print_error("Unknown Code.\n");
                    break;
            }
            return NULL;
        }
    }
    // Should not come here.
    return NULL;
}
// TODO:(Dongha Kim): Implement session key request via UDP.
// session_key_list_t *send_session_key_req_via_UDP(SST_ctx_t *ctx) {
//     session_key_list_t *s_key_list;
//     return s_key_list;
//     SST_print_error_exit("This function is not implemented yet.");
// }

unsigned char *check_handshake1_send_handshake2(
    unsigned char *received_buf, unsigned int received_buf_length,
    unsigned char *server_nonce, session_key_t *s_key,
    unsigned int *ret_length) {
    unsigned int decrypted_length;
    unsigned char *decrypted = NULL;
    if (symmetric_decrypt_authenticate(
            received_buf + SESSION_KEY_ID_SIZE,
            received_buf_length - SESSION_KEY_ID_SIZE, s_key->mac_key,
            MAC_KEY_SIZE, s_key->cipher_key, CIPHER_KEY_SIZE,
            AES_128_CBC_IV_SIZE, s_key->enc_mode, 0, &decrypted,
            &decrypted_length)) {
        SST_print_error_exit("Error during decrypting handshake1.\n");
    }

    HS_nonce_t hs;
    parse_handshake(decrypted, &hs);
    free(decrypted);

    SST_print_debug("Client's nonce: ");
    print_buf_debug(hs.nonce, HS_NONCE_SIZE);

    RAND_bytes(server_nonce, HS_NONCE_SIZE);
    SST_print_debug("Server's nonce: ");
    print_buf_debug(server_nonce, HS_NONCE_SIZE);

    // send handshake 2
    unsigned char buf[HS_INDICATOR_SIZE];
    memset(buf, 0, HS_INDICATOR_SIZE);
    serialize_handshake(server_nonce, hs.nonce, buf);

    unsigned char *ret = NULL;
    if (symmetric_encrypt_authenticate(buf, HS_INDICATOR_SIZE, s_key->mac_key,
                                       MAC_KEY_SIZE, s_key->cipher_key,
                                       CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
                                       s_key->enc_mode, 0, &ret, ret_length)) {
        SST_print_error_exit(
            "Error during encryption while send_handshake2.\n");
    }
    return ret;
}

int find_session_key(unsigned int key_id, session_key_list_t *s_key_list) {
    // TODO: Fix integer size 32 or 64
    for (int idx = 0; idx < s_key_list->num_key; idx++) {
        unsigned int list_key_id = read_unsigned_int_BE(
            s_key_list->s_key[idx].key_id, SESSION_KEY_ID_SIZE);
        if (key_id == list_key_id) {
            return idx;
        }
    }
    return -1;
}

void add_session_key_to_list(session_key_t *s_key,
                             session_key_list_t *existing_s_key_list) {
    existing_s_key_list->num_key++;
    if (existing_s_key_list->num_key > MAX_SESSION_KEY) {
        SST_print_debug(
            "Warning: Session_key_list is full. Deleting oldest key, and "
            "adding new "
            "key.\n");
        existing_s_key_list->num_key = MAX_SESSION_KEY;
    }
    copy_session_key(&existing_s_key_list->s_key[existing_s_key_list->rear_idx],
                     s_key);
    existing_s_key_list->rear_idx =
        (existing_s_key_list->rear_idx + 1) % MAX_SESSION_KEY;
}

void copy_session_key(session_key_t *dest, session_key_t *src) {
    memcpy(dest, src, sizeof(session_key_t));
    memcpy(dest->mac_key, src->mac_key, src->mac_key_size);
    memcpy(dest->cipher_key, src->cipher_key, src->cipher_key_size);
}

void append_session_key_list(session_key_list_t *dest,
                             session_key_list_t *src) {
    if (dest->num_key + src->num_key > MAX_SESSION_KEY) {
        int temp = dest->num_key + src->num_key - MAX_SESSION_KEY;
        SST_print_debug(
            "Warning: Losing %d keys from original list. Overwriting %d more "
            "keys.\n",
            temp, temp);
    }
    for (int i = 0; i < src->num_key; i++) {
        add_session_key_to_list(
            &src->s_key[mod((i + src->rear_idx - src->num_key),
                            MAX_SESSION_KEY)],
            dest);
    }
}

void update_validity(session_key_t *session_key) {
    write_in_n_bytes(
        (time(NULL) + read_unsigned_long_int_BE(session_key->rel_validity,
                                                KEY_EXPIRATION_TIME_SIZE) /
                          1000) *
            1000,
        KEY_EXPIRATION_TIME_SIZE, session_key->abs_validity);
}

int check_session_key_list_addable(int requested_num_key,
                                   session_key_list_t *s_key_list) {
    if (MAX_SESSION_KEY - s_key_list->num_key < requested_num_key) {
        // Checks (num_key) number from the oldest session_keys.
        int ret = 1;
        int expired;
        int temp;
        for (int i = 0; i < requested_num_key; i++) {
            temp = mod((i + s_key_list->rear_idx - s_key_list->num_key),
                       MAX_SESSION_KEY);
            expired = check_session_key_validity(&s_key_list->s_key[temp]);
            if (expired) {
                s_key_list->num_key -= 1;
            }
            ret = ret && expired;
        }
        return !ret;
    } else {
        return 0;
    }
}

int encrypt_or_decrypt_buf_with_session_key(
    session_key_t *s_key, unsigned char *input, unsigned int input_length,
    unsigned char **output, unsigned int *output_length, bool is_encrypt) {
    if (!check_session_key_validity(s_key)) {
        if (is_encrypt) {
            // Encryption mode.
            if (symmetric_encrypt_authenticate(
                    input, input_length, s_key->mac_key, s_key->mac_key_size,
                    s_key->cipher_key, s_key->cipher_key_size,
                    AES_128_CBC_IV_SIZE, s_key->enc_mode, s_key->hmac_mode,
                    output, output_length)) {
                SST_print_error_exit(
                    "Error during encrypting buffer with session key.\n");
            }
            return 0;
        } else {
            //
            if (symmetric_decrypt_authenticate(
                    input, input_length, s_key->mac_key, s_key->mac_key_size,
                    s_key->cipher_key, s_key->cipher_key_size,
                    AES_128_CBC_IV_SIZE, s_key->enc_mode, s_key->hmac_mode,
                    output, output_length)) {
                SST_print_error_exit(
                    "Error during decrypting buffer with session key.\n");
            }
            return 0;
        }
    } else {
        SST_print_error("Session key is expired.\n");
        return -1;
    }
}

int encrypt_or_decrypt_buf_with_session_key_without_malloc(
    session_key_t *s_key, unsigned char *input, unsigned int input_length,
    unsigned char *output, unsigned int *output_length, bool is_encrypt) {
    if (!check_session_key_validity(s_key)) {
        if (is_encrypt) {
            if (symmetric_encrypt_authenticate_without_malloc(
                    input, input_length, s_key->mac_key, s_key->mac_key_size,
                    s_key->cipher_key, s_key->cipher_key_size,
                    AES_128_CBC_IV_SIZE, s_key->enc_mode, s_key->hmac_mode,
                    output, output_length)) {
                SST_print_error_exit(
                    "Error during encrypting buffer with session key.\n");
            }
            return 0;
        } else {
            if (symmetric_decrypt_authenticate_without_malloc(
                    input, input_length, s_key->mac_key, s_key->mac_key_size,
                    s_key->cipher_key, s_key->cipher_key_size,
                    AES_128_CBC_IV_SIZE, s_key->enc_mode, s_key->hmac_mode,
                    output, output_length)) {
                SST_print_error_exit(
                    "Error during decrypting buffer with session key.\n");
            }
            return 0;
        }
    } else {
        SST_print_error("Session key is expired.\n");
        return -1;
    }
}
