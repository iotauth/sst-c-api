#include "c_api.h"

#include "c_secure_comm.h"

extern unsigned char entity_client_state;
extern unsigned char entity_server_state;

SST_ctx_t *init_SST(const char *config_path) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);
    SST_ctx_t *ctx = malloc(sizeof(SST_ctx_t));
    ctx->config = load_config(config_path);
    int numkey = ctx->config->numkey;

    ctx->pub_key = (void *)load_auth_public_key(ctx->config->auth_pubkey_path);
    ctx->priv_key =
        (void *)load_entity_private_key(ctx->config->entity_privkey_path);
    if (numkey > MAX_SESSION_KEY) {
        printf(
            "Too much requests of session keys. The max number of requestable "
            "session keys are %d",
            MAX_SESSION_KEY);
    }
    bzero(&ctx->dist_key, sizeof(distribution_key_t));
    return ctx;
}

session_key_list_t *init_empty_session_key_list() {
    session_key_list_t *session_key_list = malloc(sizeof(session_key_list_t));
    session_key_list->num_key = 0;
    session_key_list->rear_idx = 0;
    session_key_list->s_key = malloc(sizeof(session_key_t) * MAX_SESSION_KEY);
    return session_key_list;
}

session_key_list_t *get_session_key(SST_ctx_t *ctx,
                                    session_key_list_t *existing_s_key_list) {
    if (existing_s_key_list != NULL) {
        if (check_session_key_list_addable(ctx->config->numkey,
                                           existing_s_key_list)) {
            printf("Unable to get_session_key().\n");
            return existing_s_key_list;
        }
    }
    session_key_list_t *earned_s_key_list;
    if (strcmp((const char *)ctx->config->network_protocol, "TCP") == 0) {
        earned_s_key_list = send_session_key_req_via_TCP(ctx);
    } else if (strcmp((const char *)ctx->config->network_protocol, "UDP") ==
               0) {
        // earned_s_key_list = send_session_key_req_via_UDP(ctx);
    }
    if (earned_s_key_list == NULL) {
        printf("Failed to get session key. Returning NULL.\n");
        return NULL;
    }

    if (existing_s_key_list == NULL) {
        return earned_s_key_list;
    } else {
        append_session_key_list(existing_s_key_list, earned_s_key_list);
        free_session_key_list_t(earned_s_key_list);
        return existing_s_key_list;
    }
}

SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key,
                                            SST_ctx_t *ctx) {
    int sock;
    connect_as_client((const char *)ctx->config->entity_server_ip_addr,
                      (const char *)ctx->config->entity_server_port_num, &sock);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server_with_socket(s_key, sock);
    return session_ctx;
}

SST_session_ctx_t *secure_connect_to_server_with_socket(session_key_t *s_key,
                                                        int sock) {
    // Initialize SST_session_ctx_t
    SST_session_ctx_t *session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->received_seq_num = 0;
    session_ctx->sent_seq_num = 0;

    unsigned char entity_nonce[HS_NONCE_SIZE];
    unsigned int parsed_buf_length;
    unsigned char *parsed_buf =
        parse_handshake_1(s_key, entity_nonce, &parsed_buf_length);
    unsigned char sender_HS_1[MAX_HS_BUF_LENGTH];
    unsigned int sender_HS_1_length;
    make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_1,
                    sender_HS_1, &sender_HS_1_length);
    write(sock, sender_HS_1, sender_HS_1_length);
    free(parsed_buf);
    entity_client_state = HANDSHAKE_1_SENT;

    // received handshake 2
    unsigned char received_buf[MAX_HS_BUF_LENGTH];
    unsigned int received_buf_length =
        read_from_socket(sock, received_buf, sizeof(received_buf));
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SKEY_HANDSHAKE_2) {
        if (entity_client_state != HANDSHAKE_1_SENT) {
            error_exit(
                "Comm init failed: wrong sequence of handshake, "
                "disconnecting...\n");
        }
        unsigned int parsed_buf_length;
        unsigned char *parsed_buf = check_handshake_2_send_handshake_3(
            data_buf, data_buf_length, entity_nonce, s_key, &parsed_buf_length);
        unsigned char sender_HS_2[MAX_HS_BUF_LENGTH];
        unsigned int sender_HS_2_length;
        make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_3,
                        sender_HS_2, &sender_HS_2_length);
        write(sock, sender_HS_2, sender_HS_2_length);
        free(parsed_buf);
        update_validity(s_key);
        printf("switching to IN_COMM\n");
        entity_client_state = IN_COMM;
    }
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
    session_ctx->sock = sock;
    return session_ctx;
}

session_key_t *get_session_key_by_ID(unsigned char *target_session_key_id,
                                     SST_ctx_t *ctx,
                                     session_key_list_t *existing_s_key_list) {
    session_key_t *s_key;
    // TODO: Fix integer size 32 or 64
    unsigned int target_session_key_id_int =
        read_unsigned_int_BE(target_session_key_id, SESSION_KEY_ID_SIZE);

    // If the entity_server already has the corresponding session key,
    // it does not have to request session key from Auth
    int session_key_found = -1;
    if (existing_s_key_list == NULL) {
        error_exit("Session key list must be not NULL.\n");
    }
    for (int i = 0; i < existing_s_key_list->num_key; i++) {
        session_key_found = check_session_key(target_session_key_id_int,
                                              existing_s_key_list, i);
    }
    if (session_key_found >= 0) {
        s_key = &existing_s_key_list->s_key[session_key_found];
    } else if (session_key_found == -1) {
        // WARNING: The following line overwrites the purpose.
        sprintf(ctx->config->purpose[ctx->config->purpose_index],
                "{\"keyId\":%d}", target_session_key_id_int);

        session_key_list_t *s_key_list;
        s_key_list =
            send_session_key_request_check_protocol(ctx, target_session_key_id);
        if (s_key_list == NULL) {
            printf("Getting target session key by id failed. Returning NULL.");
            return NULL;
        }
        s_key = s_key_list->s_key;
        add_session_key_to_list(s_key, existing_s_key_list);
        free(s_key_list);
    }
    return s_key;
}

SST_session_ctx_t *server_secure_comm_setup(
    SST_ctx_t *ctx, int clnt_sock, session_key_list_t *existing_s_key_list) {
    // Initialize SST_session_ctx_t
    SST_session_ctx_t *session_ctx = malloc(sizeof(SST_session_ctx_t));

    session_ctx->received_seq_num = 0;
    session_ctx->sent_seq_num = 0;
    session_ctx->sock = clnt_sock;

    entity_server_state = IDLE;
    unsigned char server_nonce[HS_NONCE_SIZE];

    session_key_t *s_key;

    if (entity_server_state == IDLE) {
        unsigned char received_buf[MAX_HS_BUF_LENGTH];
        // memset(received_buf, 0, MAX_HS_BUF_LENGTH);
        int received_buf_length =
            read_from_socket(clnt_sock, received_buf, HANDSHAKE_1_LENGTH);
        if (received_buf_length < 0) {
            perror("Read Error:");
        }
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_1) {
            printf("received session key handshake1\n");
            if (entity_server_state != IDLE) {
                error_exit(
                    "Error during comm init - in wrong state, expected: IDLE, "
                    "disconnecting...\n");
            }
            printf("switching to HANDSHAKE_1_RECEIVED state.\n");
            entity_server_state = HANDSHAKE_1_RECEIVED;
            unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
            memcpy(target_session_key_id, data_buf, SESSION_KEY_ID_SIZE);

            s_key = get_session_key_by_ID(target_session_key_id, ctx,
                                          existing_s_key_list);
            if (s_key == NULL) {
                error_exit("FAILED to get session key by ID.");
            }
            if (entity_server_state != HANDSHAKE_1_RECEIVED) {
                error_exit(
                    "Error during comm init - in wrong state, expected: "
                    "HANDSHAKE_1_RECEIVED, disconnecting...");
            }
            unsigned int parsed_buf_length;
            unsigned char *parsed_buf = check_handshake1_send_handshake2(
                data_buf, data_buf_length, server_nonce, s_key,
                &parsed_buf_length);

            unsigned char sender[MAX_HS_BUF_LENGTH];
            unsigned int sender_length;
            make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_2,
                            sender, &sender_length);
            write(clnt_sock, sender, sender_length);
            free(parsed_buf);
            printf("switching to HANDSHAKE_2_SENT\n");
            entity_server_state = HANDSHAKE_2_SENT;
        }
    }
    if (entity_server_state == HANDSHAKE_2_SENT) {
        unsigned char received_buf[MAX_HS_BUF_LENGTH];
        unsigned int received_buf_length =
            read_from_socket(clnt_sock, received_buf, HANDSHAKE_3_LENGTH);
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_3) {
            printf("received session key handshake3!\n");
            if (entity_server_state != HANDSHAKE_2_SENT) {
                error_exit(
                    "Error during comm init - in wrong state, expected: "
                    "HANDSHAKE_2_SENT, "
                    "disconnecting...\n");
            }
            unsigned int decrypted_length;
            unsigned char *decrypted;
            if (symmetric_decrypt_authenticate(
                    data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE,
                    s_key->cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
                    AES_128_CBC, 0, &decrypted, &decrypted_length)) {
                error_exit(
                    "Error during decryption in HANDSHAKE_2_SENT state.\n");
            }
            HS_nonce_t hs;
            parse_handshake(decrypted, &hs);
            free(decrypted);
            // compare my_nonce and received_nonce
            if (strncmp((const char *)hs.reply_nonce,
                        (const char *)server_nonce, HS_NONCE_SIZE) != 0) {
                error_exit(
                    "Comm init failed: server NOT verified, nonce NOT matched, "
                    "disconnecting...\n");
            } else {
                printf("server authenticated/authorized by solving nonce!\n");
            }
            update_validity(s_key);
            printf("switching to IN_COMM\n");
            entity_server_state = IN_COMM;
            memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
            return session_ctx;
        }
    }
    return error_return_null("Unrecognized or invalid state for server.\n");
}

int read_secure_message(int socket, unsigned char *buf,
                        unsigned int buf_length) {
    unsigned char message_type;
    unsigned int bytes_read;
    bytes_read = read_header_return_data_buf_pointer(socket, &message_type, buf,
                                                     buf_length);
    if (message_type != SECURE_COMM_MSG) {
        error_exit("Wrong message_type.");
    }
    return bytes_read;
}

void *receive_thread(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length;
    while (1) {
        received_buf_length = read_from_socket(session_ctx->sock, received_buf,
                                               sizeof(received_buf));
        receive_message(received_buf, received_buf_length, session_ctx);
    }
}

void *receive_thread_read_one_each(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char data_buf[MAX_PAYLOAD_LENGTH];
    unsigned int data_buf_length = 0;
    while (1) {
        unsigned char message_type;

        data_buf_length = read_header_return_data_buf_pointer(
            session_ctx->sock, &message_type, data_buf, MAX_PAYLOAD_LENGTH);
        if (message_type == SECURE_COMM_MSG) {
            print_received_message(data_buf, data_buf_length, session_ctx);
        }
    }
}

void receive_message(unsigned char *received_buf,
                     unsigned int received_buf_length,
                     SST_session_ctx_t *session_ctx) {
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SECURE_COMM_MSG) {
        print_received_message(data_buf, data_buf_length, session_ctx);
    }
}

unsigned char *return_decrypted_buf(unsigned char *received_buf,
                                    unsigned int received_buf_length,
                                    unsigned int *decrypted_buf_length,
                                    SST_session_ctx_t *session_ctx) {
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SECURE_COMM_MSG) {
        // This returns SEQ_NUM_BUFFER(8) + decrypted_buffer;
        // Must free() after use.
        return decrypt_received_message(data_buf, data_buf_length,
                                        decrypted_buf_length, session_ctx);
    }
    return error_return_null(
        "Invalid message type while in secure communication.\n");
}

int send_secure_message(char *msg, unsigned int msg_length,
                        SST_session_ctx_t *session_ctx) {
    if (check_session_key_validity(&session_ctx->s_key)) {
        error_exit("Session key expired!\n");
    }
    unsigned char buf[SEQ_NUM_SIZE + msg_length];
    memset(buf, 0, SEQ_NUM_SIZE + msg_length);
    write_in_n_bytes(session_ctx->sent_seq_num, SEQ_NUM_SIZE, buf);
    memcpy(buf + SEQ_NUM_SIZE, (unsigned char *)msg, msg_length);

    // encrypt
    unsigned int encrypted_length;
    unsigned char *encrypted;

    if (encrypt_buf_with_session_key(&session_ctx->s_key, buf,
                                     SEQ_NUM_SIZE + msg_length, &encrypted,
                                     &encrypted_length)) {
        error_exit("Encryption failed.");
    }

    session_ctx->sent_seq_num++;
    unsigned char
        sender_buf[MAX_PAYLOAD_LENGTH];  // TODO: Currently the send message
                                         // does not support dynamic sizes,
                                         // the max length is shorter than
                                         // 1024. Must need to decide static
                                         // or dynamic buffer size.
    unsigned int sender_buf_length;
    make_sender_buf(encrypted, encrypted_length, SECURE_COMM_MSG, sender_buf,
                    &sender_buf_length);
    free(encrypted);

    ssize_t bytes_written = 0;
    while (bytes_written < (ssize_t)msg_length) {
        ssize_t more = write(session_ctx->sock, sender_buf, sender_buf_length);
        if (more <= 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            usleep(100);
            continue;
        } else if (more < 0) {
            return -1;
        }
        bytes_written += more;
    }
    return bytes_written;
}

int encrypt_buf_with_session_key(session_key_t *s_key, unsigned char *plaintext,
                                 unsigned int plaintext_length,
                                 unsigned char **encrypted,
                                 unsigned int *encrypted_length) {
    return encrypt_or_decrypt_buf_with_session_key(
        s_key, plaintext, plaintext_length, encrypted, encrypted_length, 1);
}

int decrypt_buf_with_session_key(session_key_t *s_key, unsigned char *encrypted,
                                 unsigned int encrypted_length,
                                 unsigned char **decrypted,
                                 unsigned int *decrypted_length) {
    return encrypt_or_decrypt_buf_with_session_key(
        s_key, encrypted, encrypted_length, decrypted, decrypted_length, 0);
}

int encrypt_buf_with_session_key_without_malloc(session_key_t *s_key, unsigned char *plaintext,
                                 unsigned int plaintext_length,
                                 unsigned char *encrypted,
                                 unsigned int *encrypted_length) {
    return encrypt_or_decrypt_buf_with_session_key_without_malloc(
        s_key, plaintext, plaintext_length, encrypted, encrypted_length, 1);
}

int decrypt_buf_with_session_key_without_malloc(session_key_t *s_key, unsigned char *encrypted,
                                 unsigned int encrypted_length,
                                 unsigned char *decrypted,
                                 unsigned int *decrypted_length) {
    return encrypt_or_decrypt_buf_with_session_key_without_malloc(
        s_key, encrypted, encrypted_length, decrypted, decrypted_length, 0);
}

int CTR_encrypt_buf_with_session_key(
    session_key_t *s_key, const uint64_t initial_iv_high,
    const uint64_t initial_iv_low, uint64_t file_offset,
    const unsigned char *data, size_t data_size, unsigned char *out_data,
    size_t out_data_buf_length, unsigned int *processed_size) {
    return CTR_encrypt_or_decrypt_buf_with_session_key(
        s_key, initial_iv_high, initial_iv_low, file_offset, data, out_data,
        data_size, out_data_buf_length, processed_size, 1);
}

int CTR_decrypt_buf_with_session_key(
    session_key_t *s_key, const uint64_t initial_iv_high,
    const uint64_t initial_iv_low, uint64_t file_offset,
    const unsigned char *data, size_t data_size, unsigned char *out_data,
    size_t out_data_buf_length, unsigned int *processed_size) {
    return CTR_encrypt_or_decrypt_buf_with_session_key(
        s_key, initial_iv_high, initial_iv_low, file_offset, data, out_data,
        data_size, out_data_buf_length, processed_size, 0);
}

void free_session_key_list_t(session_key_list_t *session_key_list) {
    free(session_key_list->s_key);
    free(session_key_list);
}

void free_SST_ctx_t(SST_ctx_t *ctx) {
    EVP_PKEY_free((EVP_PKEY *)ctx->priv_key);
    EVP_PKEY_free((EVP_PKEY *)ctx->pub_key);
    free_config_t(ctx->config);
    free(ctx);
}

int save_session_key_list(session_key_list_t *session_key_list,
                          const char *file_path) {
    FILE *saved_file_fp = fopen(file_path, "wb");
    // Write the session_key_list_t structure
    fwrite(session_key_list, sizeof(session_key_list_t), 1, saved_file_fp);
    // Write the dynamically allocated memory pointed to by s_key
    fwrite(session_key_list->s_key, sizeof(session_key_t), MAX_SESSION_KEY,
           saved_file_fp);
    fclose(saved_file_fp);
    return 0;
}

int load_session_key_list(session_key_list_t *session_key_list,
                          const char *file_path) {
    FILE *load_file_fp;
    if ((load_file_fp = fopen(file_path, "rb")) == NULL) {
        return 1;
    } else {
        // Save the malloced pointer.
        session_key_t *s = session_key_list->s_key;
        // Read the session_key_list_t structure
        fread(session_key_list, sizeof(session_key_list_t), 1, load_file_fp);
        // Reload the saved pointer.
        session_key_list->s_key = s;
        // Read the dynamically allocated memory pointed to by s_key
        fread(session_key_list->s_key, sizeof(session_key_t), MAX_SESSION_KEY,
              load_file_fp);
        fclose(load_file_fp);
        return 0;
    }
}

int save_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len) {
    unsigned char salted_password[password_len + salt_len];
    // Combine the password with the salt
    memcpy(salted_password, password, password_len);
    memcpy(salted_password + password_len, salt, salt_len);

    // Create SHA256 HMAC.
    unsigned char temp_hash[MD5_DIGEST_LENGTH];
    generate_md5_hash(salted_password, sizeof(salted_password), temp_hash);

    // Generate IV.
    unsigned char iv[AES_BLOCK_SIZE];
    generate_nonce(AES_BLOCK_SIZE, iv);

    // Serialize session_key_list into buffer.
    unsigned int buffer_len =
        sizeof(session_key_list_t) + sizeof(session_key_t) * MAX_SESSION_KEY;
    unsigned char buffer[buffer_len];
    memcpy(buffer, session_key_list, sizeof(session_key_list_t));
    memcpy(buffer + sizeof(session_key_list_t), session_key_list->s_key,
           sizeof(session_key_t) * MAX_SESSION_KEY);

    unsigned char ciphertext[sizeof(buffer)];
    unsigned int ciphertext_len;
    // Encrypt in CTR mode.
    if (encrypt_AES(buffer, buffer_len, temp_hash, iv, AES_128_CTR, ciphertext,
                    &ciphertext_len)) {
        printf("AES encryption failed!");
        return 1;
    }

    FILE *saved_file_fp = fopen(file_path, "wb");
    // Write the IV
    fwrite(iv, 1, sizeof(iv), saved_file_fp);
    // Write the encrypted data
    fwrite(ciphertext, 1, ciphertext_len, saved_file_fp);
    fclose(saved_file_fp);
    return 0;
}

int load_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len) {
    unsigned char salted_password[password_len + salt_len];
    unsigned char temp_hash[MD5_DIGEST_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[sizeof(session_key_list_t) +
                             sizeof(session_key_t) * MAX_SESSION_KEY];
    unsigned char buffer[sizeof(session_key_list_t) +
                         sizeof(session_key_t) * MAX_SESSION_KEY];
    FILE *saved_file_fp;
    int ciphertext_len;

    // Combine the password with the salt
    memcpy(salted_password, password, password_len);
    memcpy(salted_password + password_len, salt, salt_len);

    // Create MD5 hash of the salted password
    generate_md5_hash(salted_password, sizeof(salted_password), temp_hash);

    saved_file_fp = fopen(file_path, "rb");
    if (!saved_file_fp) {
        printf("Failed to open file for reading!\n");
        return 1;
    }

    // Read the IV
    fread(iv, 1, sizeof(iv), saved_file_fp);

    // Read the encrypted data
    ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), saved_file_fp);
    fclose(saved_file_fp);

    if (ciphertext_len <= 0) {
        printf("Failed to read encrypted data!\n");
        return 1;
    }

    // Decrypt the data
    unsigned int plaintext_len;
    if (decrypt_AES(ciphertext, ciphertext_len, temp_hash, iv, AES_128_CTR,
                    buffer, &plaintext_len)) {
        printf("AES decryption failed!\n");
        return 1;
    }

    // Deserialize the buffer into session_key_list
    memcpy(session_key_list, buffer, sizeof(session_key_list_t));
    session_key_list->s_key = malloc(sizeof(session_key_t) * MAX_SESSION_KEY);
    if (!session_key_list->s_key) {
        printf("Memory allocation failed!\n");
        return 1;
    }
    memcpy(session_key_list->s_key, buffer + sizeof(session_key_list_t),
           sizeof(session_key_t) * MAX_SESSION_KEY);

    return 0;
}

unsigned int convert_skid_buf_to_int(unsigned char *buf, int byte_length) {
    return read_unsigned_int_BE(buf, byte_length);
}

void generate_random_nonce(int length, unsigned char *buf) {
    generate_nonce(length, buf);
}