#include "c_api.h"

#include <openssl/rand.h>

#include "c_common.h"
#include "c_crypto.h"
#include "c_secure_comm.h"
#include "load_config.h"

extern unsigned char entity_client_state;
extern unsigned char entity_server_state;

SST_ctx_t *init_SST(const char *config_path) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);
    // By default OpenSSL will attempt to clean itself up when the process exits
    // via an "atexit" handler. Using this option suppresses that behaviour.
    // This means that the application will have to clean up OpenSSL explicitly
    // using OPENSSL_cleanup().
    // This is needed because, Lingua Franca uses the "atexit" handler, and
    // there are still messages to be sent after the atexit handler.
    SST_ctx_t *ctx = malloc(sizeof(SST_ctx_t));
    ctx->config = load_config(config_path);
    if (ctx->config == NULL) {
        SST_print_error("Failed to load_config()");
        return NULL;
    }
    int numkey = ctx->config->numkey;

    ctx->pub_key = (void *)load_auth_public_key(ctx->config->auth_pubkey_path);
    if (ctx->pub_key == NULL) {
        SST_print_error("Failed load_auth_public_key().");
        return NULL;
    }
    ctx->priv_key =
        (void *)load_entity_private_key(ctx->config->entity_privkey_path);
    if (ctx->priv_key == NULL) {
        SST_print_error("Failed load_entity_private_key().");
        return NULL;
    }
    if (numkey > MAX_SESSION_KEY) {
        SST_print_error(
            "Too much requests of session keys. The max number of requestable "
            "session keys are %d",
            MAX_SESSION_KEY);
    }
    bzero(&ctx->dist_key, sizeof(distribution_key_t));
    return ctx;
}

session_key_list_t *init_empty_session_key_list(void) {
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
                                           existing_s_key_list) == 0) {
            SST_print_error("The session key list is not addable.");
            return existing_s_key_list;
        }
    }
    session_key_list_t *earned_s_key_list = NULL;
    if (strcmp((const char *)ctx->config->network_protocol, "TCP") == 0) {
        earned_s_key_list = send_session_key_req_via_TCP(ctx);
        if (earned_s_key_list == NULL) {
            SST_print_error("Failed to send_session_key_req_via_TCP().");
            return NULL;
        }
    } else if (strcmp((const char *)ctx->config->network_protocol, "UDP") ==
               0) {
        // TODO:(Dongha Kim): Implement session key request via UDP.
        // earned_s_key_list = send_session_key_req_via_UDP(ctx);
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
    if (connect_as_client((const char *)ctx->config->entity_server_ip_addr,
                          ctx->config->entity_server_port_num, &sock) < 0) {
        SST_print_error("Failed connect_as_client().");
        return NULL;
    }
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server_with_socket(s_key, sock);
    if (session_ctx == NULL) {
        SST_print_error("Failed secure_connect_to_server_with_socket().");
        return NULL;
    }
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
    if (parsed_buf == NULL) {
        SST_print_error("Failed parse_handshake_1().");
        return NULL;
    }
    unsigned char sender_HS_1[MAX_HS_BUF_LENGTH];
    unsigned int sender_HS_1_length;
    make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_1,
                    sender_HS_1, &sender_HS_1_length);
    int bytes_written =
        sst_write_to_socket(sock, sender_HS_1, sender_HS_1_length);
    if (bytes_written < 0) {
        SST_print_error("Failed sst_write_to_socket().");
        return NULL;
    }
    free(parsed_buf);
    entity_client_state = HANDSHAKE_1_SENT;

    // received handshake 2
    unsigned char received_buf[MAX_HS_BUF_LENGTH];
    int received_buf_length =
        sst_read_from_socket(sock, received_buf, sizeof(received_buf));
    if (received_buf_length < 0) {
        SST_print_error("Failed sst_read_from_socket().");
        return NULL;
    }
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SKEY_HANDSHAKE_2) {
        if (entity_client_state != HANDSHAKE_1_SENT) {
            SST_print_error(
                "Comm init failed: wrong sequence of handshake, "
                "disconnecting...");
            return NULL;
        }
        unsigned int parsed_buf_length;
        unsigned char *parsed_buf = check_handshake_2_send_handshake_3(
            data_buf, data_buf_length, entity_nonce, s_key, &parsed_buf_length);
        if (parsed_buf == NULL) {
            SST_print_error("Failed check_handshake_2_send_handshake_3().");
            return NULL;
        }
        unsigned char sender_HS_2[MAX_HS_BUF_LENGTH];
        unsigned int sender_HS_2_length;
        make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_3,
                        sender_HS_2, &sender_HS_2_length);
        int bytes_written =
            sst_write_to_socket(sock, sender_HS_2, sender_HS_2_length);
        if (bytes_written < 0) {
            SST_print_error("Failed sst_write_to_socket().");
            return NULL;
        }
        free(parsed_buf);
        update_validity(s_key);
        SST_print_debug("Switching to IN_COMM.");
        entity_client_state = IN_COMM;
    }
    memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
    session_ctx->sock = sock;
    return session_ctx;
}

session_key_t *get_session_key_by_ID(unsigned char *target_session_key_id,
                                     SST_ctx_t *ctx,
                                     session_key_list_t *existing_s_key_list) {
    session_key_t *s_key = NULL;
    // TODO: Fix integer size 32 or 64
    unsigned int target_session_key_id_int =
        read_unsigned_int_BE(target_session_key_id, SESSION_KEY_ID_SIZE);

    // If the entity_server already has the corresponding session key,
    // it does not have to request session key from Auth
    int session_key_idx = -1;
    if (existing_s_key_list == NULL) {
        SST_print_error("Session key list must be not NULL.");
        return NULL;
    }
    session_key_idx =
        find_session_key(target_session_key_id_int, existing_s_key_list);
    if (session_key_idx >= 0) {
        s_key = &existing_s_key_list->s_key[session_key_idx];
    } else if (session_key_idx < 0) {
        // WARNING: The following line overwrites the purpose.
        snprintf(ctx->config->purpose[ctx->config->purpose_index],
                 sizeof(ctx->config->purpose[ctx->config->purpose_index]),
                 "{\"keyId\":%d}", target_session_key_id_int);

        session_key_list_t *s_key_list;
        s_key_list =
            send_session_key_request_check_protocol(ctx, target_session_key_id);
        if (s_key_list == NULL) {
            SST_print_error(
                "Failed to send_session_key_request_check_protocol().");
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

    session_key_t *s_key = NULL;

    if (entity_server_state == IDLE) {
        unsigned char received_buf[MAX_HS_BUF_LENGTH];
        int received_buf_length =
            sst_read_from_socket(clnt_sock, received_buf, HANDSHAKE_1_LENGTH);
        if (received_buf_length < 0) {
            SST_print_error(
                "Failed sst_read_from_socket(). Socket read error in "
                "server_secure_comm_setup()");
            return NULL;
        }
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_1) {
            SST_print_debug("Received session key handshake1.");
            if (entity_server_state != IDLE) {
                SST_print_error(
                    "Error during comm init - in wrong state, expected: IDLE, "
                    "disconnecting...");
                return NULL;
            }
            SST_print_debug("Switching to HANDSHAKE_1_RECEIVED state.");
            entity_server_state = HANDSHAKE_1_RECEIVED;
            unsigned char target_session_key_id[SESSION_KEY_ID_SIZE];
            memcpy(target_session_key_id, data_buf, SESSION_KEY_ID_SIZE);

            s_key = get_session_key_by_ID(target_session_key_id, ctx,
                                          existing_s_key_list);
            if (s_key == NULL) {
                SST_print_error("Failed to get_session_key_by_ID().");
                return NULL;
            }
            if (entity_server_state != HANDSHAKE_1_RECEIVED) {
                SST_print_error(
                    "Error during comm init - in wrong state, expected: "
                    "HANDSHAKE_1_RECEIVED, disconnecting...");
                return NULL;
            }
            unsigned int parsed_buf_length;
            unsigned char *parsed_buf = check_handshake1_send_handshake2(
                data_buf, data_buf_length, server_nonce, s_key,
                &parsed_buf_length);
            if (parsed_buf == NULL) {
                SST_print_error("Failed check_handshake1_send_handshake2().");
                return NULL;
            }

            unsigned char sender[MAX_HS_BUF_LENGTH];
            unsigned int sender_length;
            make_sender_buf(parsed_buf, parsed_buf_length, SKEY_HANDSHAKE_2,
                            sender, &sender_length);
            int bytes_written =
                sst_write_to_socket(clnt_sock, sender, sender_length);
            if (bytes_written < 0) {
                SST_print_error("Failed sst_write_to_socket().");
                return NULL;
            }
            free(parsed_buf);
            SST_print_debug("Switching to HANDSHAKE_2_SENT.");
            entity_server_state = HANDSHAKE_2_SENT;
        }
    }
    if (entity_server_state == HANDSHAKE_2_SENT) {
        unsigned char received_buf[MAX_HS_BUF_LENGTH];
        int received_buf_length =
            sst_read_from_socket(clnt_sock, received_buf, HANDSHAKE_3_LENGTH);
        if (received_buf_length < 0) {
            SST_print_error(
                "Failed sst_read_from_socket().Socket read error in "
                "server_secure_comm_setup()");
            return NULL;
        }
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_3) {
            SST_print_debug("Received session key handshake3!");
            if (entity_server_state != HANDSHAKE_2_SENT) {
                SST_print_error(
                    "Error during comm init - in wrong state, expected: "
                    "HANDSHAKE_2_SENT, "
                    "disconnecting...");
                return NULL;
            }
            unsigned int decrypted_length;
            unsigned char *decrypted = NULL;
            if (symmetric_decrypt_authenticate(
                    data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE,
                    s_key->cipher_key, CIPHER_KEY_SIZE, AES_128_CBC_IV_SIZE,
                    AES_128_CBC, 0, &decrypted, &decrypted_length) < 0) {
                SST_print_error(
                    "Failed symmetric_decrypt_authenticate(). Error during "
                    "decryption in HANDSHAKE_2_SENT state.");
                return NULL;
            }
            HS_nonce_t hs;
            parse_handshake(decrypted, &hs);
            free(decrypted);
            // compare my_nonce and received_nonce
            if (strncmp((const char *)hs.reply_nonce,
                        (const char *)server_nonce, HS_NONCE_SIZE) != 0) {
                SST_print_error(
                    "Comm init failed: server NOT verified, nonce NOT matched, "
                    "disconnecting...");
                return NULL;
            } else {
                SST_print_debug(
                    "Server authenticated/authorized by solving nonce!");
            }
            update_validity(s_key);
            SST_print_debug("Switching to IN_COMM.");
            entity_server_state = IN_COMM;
            memcpy(&session_ctx->s_key, s_key, sizeof(session_key_t));
            return session_ctx;
        }
    }
    SST_print_error("Unrecognized or invalid state for server.");
    return NULL;
}

void *receive_thread_read_one_each(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char data_buf[MAX_SECURE_COMM_MSG_LENGTH];
    int data_buf_length = 0;
    while (1) {
        data_buf_length = read_secure_message(data_buf, session_ctx);
        if (data_buf_length < 0) {
            SST_print_error("Failed to read_secure_message().");
            return NULL;
        }
        SST_print_log("Received: %.*s", data_buf_length, data_buf);
    }
}

int read_secure_message(unsigned char *plaintext,
                        SST_session_ctx_t *session_ctx) {
    unsigned char message_type;
    int bytes_read;
    unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
    bytes_read = read_header_return_data_buf_pointer(
        session_ctx->sock, &message_type, received_buf,
        MAX_SECURE_COMM_MSG_LENGTH);
    if (bytes_read < 0) {
        SST_print_error("Failed to read_header_return_data_buf_pointer().");
        return -1;
    }
    if (check_SECURE_COMM_MSG_type(message_type) < 0) {
        SST_print_error(
            "Failed check_SECURE_COMM_MSG_type(). Wrong message_type.");
        return -1;
    }
    unsigned int decrypted_length;
    unsigned char seq_num_and_plaintext[MAX_SECURE_COMM_MSG_LENGTH];
    if (decrypt_received_message(received_buf, bytes_read,
                                 seq_num_and_plaintext, &decrypted_length,
                                 session_ctx) < 0) {
        SST_print_error("Failed decrypt_received_message().");
        return -1;
    }
    // Copy the plaintext payload to the buffer declared by user.
    memcpy(plaintext, seq_num_and_plaintext + SEQ_NUM_SIZE,
           decrypted_length - SEQ_NUM_SIZE);
    // Return plaintext length.
    return decrypted_length - SEQ_NUM_SIZE;
}

int send_secure_message(char *msg, unsigned int msg_length,
                        SST_session_ctx_t *session_ctx) {
    return send_SECURE_COMM_message(msg, msg_length, session_ctx);
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

int encrypt_buf_with_session_key_without_malloc(
    session_key_t *s_key, unsigned char *plaintext,
    unsigned int plaintext_length, unsigned char *encrypted,
    unsigned int *encrypted_length) {
    return encrypt_or_decrypt_buf_with_session_key_without_malloc(
        s_key, plaintext, plaintext_length, encrypted, encrypted_length, 1);
}

int decrypt_buf_with_session_key_without_malloc(
    session_key_t *s_key, unsigned char *encrypted,
    unsigned int encrypted_length, unsigned char *decrypted,
    unsigned int *decrypted_length) {
    return encrypt_or_decrypt_buf_with_session_key_without_malloc(
        s_key, encrypted, encrypted_length, decrypted, decrypted_length, 0);
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
        SST_print_error("Failed to fopen()");
        return -1;  // Error opening file
    } else {
        // Save the malloced pointer
        session_key_t *s = session_key_list->s_key;

        // Read the session_key_list_t structure
        size_t items_read = fread(session_key_list, sizeof(session_key_list_t),
                                  1, load_file_fp);
        if (items_read != 1) {
            fclose(load_file_fp);
            SST_print_error("Failed to fread()");
            return -1;  // Error reading session_key_list_t structure
        }

        // Reload the saved pointer
        session_key_list->s_key = s;

        // Read the dynamically allocated memory pointed to by s_key
        items_read = fread(session_key_list->s_key, sizeof(session_key_t),
                           MAX_SESSION_KEY, load_file_fp);
        if (items_read != MAX_SESSION_KEY) {
            fclose(load_file_fp);
            SST_print_error("Failed to fread()");
            return -1;  // Error reading session keys
        }

        fclose(load_file_fp);
        return 0;  // Success
    }
}

int save_session_key_list_with_password(session_key_list_t *session_key_list,
                                        const char *file_path,
                                        const char *password,
                                        unsigned int password_len,
                                        const char *salt,
                                        unsigned int salt_len) {
    // Generate IV.
    unsigned char iv[AES_BLOCK_SIZE];
    if (generate_nonce(AES_BLOCK_SIZE, iv) < 0) {
        SST_print_error("Failed generate_nonce().");
        return -1;
    }

    // Serialize session_key_list into buffer.
    unsigned int buffer_len = sizeof(session_key_list_t) +
                              sizeof(session_key_t) * session_key_list->num_key;
    unsigned char buffer[buffer_len];
    memcpy(buffer, session_key_list, sizeof(session_key_list_t));
    memcpy(buffer + sizeof(session_key_list_t), session_key_list->s_key,
           sizeof(session_key_t) * session_key_list->num_key);
    // Create a salted password, and digest it to 32 bytes.
    unsigned char salted_password[SHA256_DIGEST_LENGTH];
    if (create_salted_password_to_32bytes(password, password_len, salt,
                                          salt_len, salted_password) < 0) {
        SST_print_error("Failed create_salted_password_to_32bytes().");
        return -1;
    }
    unsigned char ciphertext[sizeof(buffer)];
    unsigned int ciphertext_len;
    // Encrypt using the session key's encryption mode.
    // The hashed salt will be the encryption key.
    if (encrypt_AES(buffer, buffer_len, salted_password, iv, AES_128_CBC,
                    ciphertext, &ciphertext_len) < 0) {
        SST_print_error("AES encryption failed!");
        return -1;
    }

    FILE *saved_file_fp = fopen(file_path, "wb");
    if (!saved_file_fp) {
        SST_print_error("Failed to open file: %s", file_path);
        return -1;
    }
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
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[sizeof(session_key_list_t) +
                             sizeof(session_key_t) * MAX_SESSION_KEY];
    unsigned char buffer[sizeof(session_key_list_t) +
                         sizeof(session_key_t) * MAX_SESSION_KEY];
    FILE *saved_file_fp;
    int ciphertext_len;

    saved_file_fp = fopen(file_path, "rb");
    if (!saved_file_fp) {
        SST_print_error("Failed to open file for reading!");
        return -1;
    }

    // Read the IV
    size_t iv_read = fread(iv, 1, sizeof(iv), saved_file_fp);
    if (iv_read != sizeof(iv)) {
        SST_print_error("Failed to read IV!");
        fclose(saved_file_fp);
        return -1;
    }

    // Read the encrypted data
    ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), saved_file_fp);
    fclose(saved_file_fp);

    if (ciphertext_len <= 0) {
        SST_print_error("Failed to read encrypted data!");
        return -1;
    }

    // Create a salted password, and digest it to 32 bytes.
    unsigned char salted_password[SHA256_DIGEST_LENGTH];

    if (create_salted_password_to_32bytes(password, password_len, salt,
                                          salt_len, salted_password) < 0) {
        SST_print_error("Failed create_salted_password_to_32bytes().");
        return -1;
    }
    // Decrypt the data.
    unsigned int plaintext_len;
    if (decrypt_AES(ciphertext, ciphertext_len, salted_password, iv,
                    AES_128_CBC, buffer, &plaintext_len) < 0) {
        SST_print_error("AES decryption failed!");
        return -1;
    }

    // Deserialize the buffer into session_key_list
    memcpy(session_key_list, buffer, sizeof(session_key_list_t));
    session_key_list->s_key = malloc(sizeof(session_key_t) * MAX_SESSION_KEY);
    if (!session_key_list->s_key) {
        SST_print_error("Memory allocation failed!");
        return -1;
    }
    memcpy(session_key_list->s_key, buffer + sizeof(session_key_list_t),
           sizeof(session_key_t) * MAX_SESSION_KEY);

    return 0;
}

unsigned int convert_skid_buf_to_int(unsigned char *buf, int byte_length) {
    return read_unsigned_int_BE(buf, byte_length);
}

int generate_random_nonce(int length, unsigned char *buf) {
    if (generate_nonce(length, buf) < 0) {
        SST_print_error("Failed generate_nonce().");
        return -1;
    }
    return 0;
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

int secure_rand(int min, int max) {
    unsigned int range = max - min + 1;
    unsigned int rand_num;
    unsigned char buffer[4];

    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        fprintf(stderr, "RAND_bytes failed");
        return -1;  // handle error
    }

    rand_num = ((unsigned int)buffer[0] << 24) |
               ((unsigned int)buffer[1] << 16) |
               ((unsigned int)buffer[2] << 8) | ((unsigned int)buffer[3]);

    return (rand_num % range) + min;
}
