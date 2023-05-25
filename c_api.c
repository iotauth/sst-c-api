#include "c_api.h"

extern unsigned char entity_client_state;
extern unsigned char entity_server_state;

SST_ctx_t *init_SST(char *config_path) {
    SST_ctx_t *ctx = malloc(sizeof(SST_ctx_t));
    ctx->config = load_config(config_path);
    int numkey = ctx->config->numkey;

    ctx->pub_key = load_auth_public_key(ctx->config->auth_pubkey_path);
    ctx->priv_key = load_entity_private_key(ctx->config->entity_privkey_path);
    if (numkey > MAX_SESSION_KEY) {
        printf(
            "Too much requests of session keys. The max number of requestable "
            "session keys are %d",
            MAX_SESSION_KEY);
    }
    return ctx;
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
        earned_s_key_list = send_session_key_req_via_UDP(ctx);
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
    // Initialize SST_session_ctx_t
    SST_session_ctx_t *session_ctx = malloc(sizeof(SST_session_ctx_t));
    session_ctx->received_seq_num = 0;
    session_ctx->sent_seq_num = 0;

    int sock;
    connect_as_client((const char *)ctx->config->entity_server_ip_addr,
                      (const char *)ctx->config->entity_server_port_num, &sock);
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
        read(sock, received_buf, sizeof(received_buf));
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SKEY_HANDSHAKE_2) {
        if (entity_client_state != HANDSHAKE_1_SENT) {
            error_handling(
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
        int received_buf_length =
            read(clnt_sock, received_buf, HANDSHAKE_1_LENGTH);
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_1) {
            printf("received session key handshake1\n");
            if (entity_server_state != IDLE) {
                error_handling(
                    "Error during comm init - in wrong state, expected: IDLE, "
                    "disconnecting...\n");
            }
            printf("switching to HANDSHAKE_1_RECEIVED state.\n");
            entity_server_state = HANDSHAKE_1_RECEIVED;
            unsigned char expected_key_id[SESSION_KEY_ID_SIZE];
            memcpy(expected_key_id, data_buf, SESSION_KEY_ID_SIZE);
            unsigned int expected_key_id_int =
                read_unsigned_int_BE(expected_key_id, SESSION_KEY_ID_SIZE);

            // If the entity_server already has the corresponding session key,
            // it does not have to request session key from Auth
            int session_key_found = -1;
            if (existing_s_key_list != NULL) {
                for (int i = 0; i < existing_s_key_list->num_key; i++) {
                    session_key_found = check_session_key(
                        expected_key_id_int, existing_s_key_list, i);
                }
            }
            if (session_key_found >= 0) {
                s_key = &existing_s_key_list->s_key[session_key_found];
            } else if (session_key_found == -1) {
                // WARNING: The following line overwrites the purpose.
                sprintf(ctx->config->purpose, "{\"keyId\":%d}",
                        expected_key_id_int);

                session_key_list_t *s_key_list;
                s_key_list = send_session_key_request_check_protocol(
                    ctx, expected_key_id);
                s_key = s_key_list->s_key;
                if (existing_s_key_list != NULL) {
                    add_session_key_to_list(s_key, existing_s_key_list);
                }
            }
            if (entity_server_state != HANDSHAKE_1_RECEIVED) {
                error_handling(
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
        int received_buf_length =
            read(clnt_sock, received_buf, HANDSHAKE_3_LENGTH);
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == SKEY_HANDSHAKE_3) {
            printf("received session key handshake3!\n");
            if (entity_server_state != HANDSHAKE_2_SENT) {
                error_handling(
                    "Error during comm init - in wrong state, expected: IDLE, "
                    "disconnecting...\n");
            }
            unsigned int decrypted_length;
            unsigned char *decrypted = symmetric_decrypt_authenticate(
                data_buf, data_buf_length, s_key->mac_key, MAC_KEY_SIZE,
                s_key->cipher_key, CIPHER_KEY_SIZE, AES_CBC_128_IV_SIZE,
                &decrypted_length);
            HS_nonce_t hs;
            parse_handshake(decrypted, &hs);
            free(decrypted);
            // compare my_nonce and received_nonce
            if (strncmp((const char *)hs.reply_nonce,
                        (const char *)server_nonce, HS_NONCE_SIZE) != 0) {
                error_handling(
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
}

void *receive_thread(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length = 0;
    while (1) {
        received_buf_length =
            read(session_ctx->sock, received_buf, sizeof(received_buf));
        if (received_buf_length == 0) {
            printf("Socket closed!\n");
            close(session_ctx->sock);
            return 0;
        }
        if (received_buf_length == -1) {
            printf("Connection error!\n");
            return 0;
        }
        receive_message(received_buf, received_buf_length, session_ctx);
    }
}

void *receive_thread_read_one_each(void *SST_session_ctx) {
    SST_session_ctx_t *session_ctx = (SST_session_ctx_t *)SST_session_ctx;
    unsigned char data_buf[MAX_PAYLOAD_LENGTH];
    unsigned int data_buf_length = 0;
    while (1) {
        unsigned char message_type;
        if (1 != read_header_return_data_buf_pointer(session_ctx->sock,
                                                     &message_type, data_buf,
                                                     &data_buf_length)) {
            return 0;
        }
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
                                    SST_session_ctx_t *session_ctx) {
    unsigned char message_type;
    unsigned int data_buf_length;
    unsigned char *data_buf = parse_received_message(
        received_buf, received_buf_length, &message_type, &data_buf_length);
    if (message_type == SECURE_COMM_MSG) {
        return decrypt_received_message(data_buf, data_buf_length, session_ctx);
    }
}

void send_secure_message(char *msg, unsigned int msg_length,
                         SST_session_ctx_t *session_ctx) {
    if (check_session_key_validity(&session_ctx->s_key)) {
        error_handling("Session key expired!\n");
    }
    unsigned char buf[SEQ_NUM_SIZE + msg_length];
    memset(buf, 0, SEQ_NUM_SIZE + msg_length);
    write_in_n_bytes(session_ctx->sent_seq_num, SEQ_NUM_SIZE, buf);
    memcpy(buf + SEQ_NUM_SIZE, (unsigned char *)msg, msg_length);

    // encrypt
    unsigned int encrypted_length;
    unsigned char *encrypted = symmetric_encrypt_authenticate(
        buf, SEQ_NUM_SIZE + msg_length, session_ctx->s_key.mac_key,
        MAC_KEY_SIZE, session_ctx->s_key.cipher_key, CIPHER_KEY_SIZE,
        AES_CBC_128_IV_SIZE, &encrypted_length);

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
    write(session_ctx->sock, sender_buf, sender_buf_length);
}

void free_session_key_list_t(session_key_list_t *session_key_list) {
    free(session_key_list->s_key);
    free(session_key_list);
}

void free_SST_ctx_t(SST_ctx_t *ctx) {
    OPENSSL_free(ctx->priv_key);
    OPENSSL_free(ctx->pub_key);
    free_config_t(ctx->config);
}

void ipfs_add_command_save_result()
{
    char buff[BUFF_SIZE];
    FILE *fp, *fout_0;
    char *file_name = "enc.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s 파일이 존재합니다.\n", file_name);
        exit();
    }
    else
    {
        fp = popen("ipfs add enc.txt", "r");
    }
    if (NULL == fp)
    {
            perror("popen() failed");
    }
    while (fgets(buff, BUFF_SIZE, fp))
        printf("%s\n", buff);
    
    int first_order = 0;
    int second_order = 0;
    for (int i=0; i<BUFF_SIZE;i++)
    {
        if (first_order==0 & (buff[i] == 0x20))
            {
                first_order = i+1;
            }
        else if (first_order!=0 & (buff[i] == 0x20))
            {
                second_order = i-1;
                break;
            }
    }
    unsigned char *buffer = NULL;
    buffer = malloc(sizeof(char)* (second_order-first_order));
    memcpy(buffer,buff+first_order,second_order-first_order+1);    
    printf("Hash value: %s\n", buffer);
    // Hash value save
    fout_0 = fopen("hash_result.txt", "w");
    fwrite(buffer, 1, second_order-first_order+1, fout_0);
    printf("Save the file for hash value");
    pclose(fp);
    fclose(fout_0);
}


void file_encrypt_upload(SST_session_ctx_t *session_ctx)
{
    FILE *fin, *fout, *fenc;
    unsigned int cipher_key_size = 16;
    fin = fopen("/Users/yeongbin/Desktop/project/IPFS-with-SST/plain_text.txt","r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    if (fin != NULL) {

        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));

            // 이 내용이 없으면 제대로 동작하지 않음!!!
            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; 
            }
        }
    }
    fclose(fin);
    printf("hello\n");
    printf("File size: %ld\n", bufsize);
    unsigned char iv[IV_SIZE];
    unsigned char prov_info[] = "yeongbin";
    int prov_info_len = sizeof(prov_info);
    printf("%d %d,\n",prov_info_len, IV_SIZE);
    unsigned int encrypted_length = (((bufsize) / IV_SIZE) + 1) * IV_SIZE;
    unsigned char *encrypted = (unsigned char *)malloc(encrypted_length);
    generate_nonce(IV_SIZE, iv);
    printf("IV:");
    print_buf(iv, 16);
    printf("File buffer:");
    print_buf(file_buf,10);

    //// encrypt ////
    AES_CBC_128_encrypt(file_buf, bufsize, session_ctx->s_key.cipher_key, cipher_key_size, iv,
                        IV_SIZE, encrypted, &encrypted_length);
    printf("Encrypted length: %ld\n", encrypted_length);
    printf("Enc_value:");
    print_buf(encrypted, 10);
    
    //// encrypt save ////
    char *file_name = "enc.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s 파일이 존재합니다.\n", file_name);
        exit();
    }
    else
    {
        fenc = fopen("enc.txt", "w");
    }
    // fenc = fopen("enc.txt", "w");
    unsigned char * enc_save = (unsigned char *) malloc(encrypted_length+1+IV_SIZE+1+prov_info_len);
    enc_save[0] = prov_info_len;
    memcpy(enc_save+1,prov_info,prov_info_len);
    enc_save[prov_info_len+1] = IV_SIZE;
    memcpy(enc_save+1+prov_info_len+1,iv,IV_SIZE);
    memcpy(enc_save+1+prov_info_len+1+IV_SIZE,encrypted,encrypted_length);
    printf("Total Length: %d\n",encrypted_length+1+IV_SIZE+1+prov_info_len);
    fwrite(enc_save, 1, encrypted_length+1+IV_SIZE+1+prov_info_len, fenc);
    fclose(fenc);
    // if there is no delay, encrypted file is not generated.
    sleep(1);
    // Do command 'ipfs add file' and save the hash result
    ipfs_add_command_save_result();
}

void file_download_decrypt(SST_session_ctx_t *session_ctx)
{
    unsigned int cipher_key_size = 16;
    FILE *fp, *fin, *fout;
    char *file_name = "enc.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s 파일이 존재합니다.\n", file_name);
        exit();
    }
    else
    {
        fp = popen("ipfs cat QmX5NKpskdhPeEBwVLztE3hKjYJF8mLi93qrM67orVfdAY > enc.txt", "r");
        pclose(fp);
    }
    
    fin = fopen("enc.txt","r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    if (fin != NULL) {

        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));

            // 이 내용이 없으면 제대로 동작하지 않음!!!
            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; 
            }
        }
    fclose(fin);
    }    

    printf("File size: %ld\n", bufsize);

    unsigned int prov_info_num = file_buf[0];
    unsigned int iv_size = file_buf[1+prov_info_num];

    printf("%d, %d \n", prov_info_num,iv_size);
    unsigned char prov_info[prov_info_num];
    memcpy(prov_info,file_buf+1,prov_info_num);
    print_buf(prov_info,prov_info_num);
    unsigned char iv[iv_size];
    memcpy(iv,file_buf+1+prov_info_num+1,iv_size);
    print_buf(iv,iv_size);

    print_buf(file_buf,1+IV_SIZE+1+prov_info_num);

    unsigned long int enc_length = bufsize - (1+IV_SIZE+1+prov_info_num);

    unsigned int ret_length = (enc_length + iv_size) / iv_size * iv_size;
    unsigned char *ret = (unsigned char *)malloc(ret_length);
    AES_CBC_128_decrypt(file_buf+1+IV_SIZE+1+prov_info_num, enc_length, session_ctx->s_key.cipher_key, cipher_key_size, iv,
                        iv_size, ret, &ret_length);
    printf("decrypted length: %ld\n", ret_length);

    printf("dec_value:");
    print_buf(ret, 10);

    fout = fopen("rpi_result.txt", "w");
    fwrite(ret, 1,ret_length, fout);
    free(ret);
    fclose(fout);
}