#include "ipfs.h"

const char IPFS_ADD_COMMAND[] = "ipfs add ";
const char TXT_FILE_EXTENSION[] = ".txt";
const char ENCRYPTED_FILE_NAME[] = "encrypted";
const char RESULT_FILE_NAME[] = "result";
const char DOWNLOAD_FILE_NAME[] = "download";

void get_file_content(FILE* fin, unsigned char* file_buf, unsigned long bufsize) {
    if (fseek(fin, 0L, SEEK_SET) != 0) {
        error_handling("Start point is not zero.\n");
        exit(1);
    }
    size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
    if (ferror(fin) != 0) {
        error_handling("Error reading file.\n");
        exit(1);
    }
    file_buf[newLen++] = '\0';
}

unsigned long file_size_return(FILE* fin) {
    unsigned long bufsize;
    if (fin == NULL) {
        error_handling("Cannot read the file.\n");
        exit(1);
    }
    if (fseek(fin, 0L, SEEK_END) != 0) {
        error_handling("Cannot move pointer to the end of file.\n");
    }
    bufsize = ftell(fin);

    return bufsize;
}

void file_duplication_check(const char* file_name, const char* file_extension, char* file_name_buf) {
    int suffix_num = 0;
    // Copy file name.
    memcpy(file_name_buf, file_name, strlen(file_name));
    memcpy(file_name_buf + strlen(file_name), file_extension, strlen(file_extension));
    file_name_buf[strlen(file_name) + strlen(file_extension)] = 0;
    for (;;) {
        if (suffix_num == MAX_REPLY_NUM) {
            printf("Cannot save the file. \n");
            exit(1);
        }
        if (0 == access(file_name_buf, F_OK)) {
            printf("File already exists: %s\n", file_name_buf);
            // Copy suffix and file extension.
            char suffix_in_string[5];
            sprintf(suffix_in_string, "%d", suffix_num);
            memcpy(file_name_buf + strlen(file_name), suffix_in_string, strlen(suffix_in_string));
            memcpy(file_name_buf + strlen(file_name) + strlen(suffix_in_string), file_extension, strlen(file_extension));
            file_name_buf[strlen(file_name) + strlen(suffix_in_string) + strlen(file_extension)] = 0;
            suffix_num += 1;
        }
        else {
            break;
        }
    }
}

int execute_command_and_save_result(char* file_name, unsigned char* hash_value) {
    char buff[BUFF_SIZE];
    FILE* fp;
    char command[BUFF_SIZE];
    memcpy(command, IPFS_ADD_COMMAND, sizeof(IPFS_ADD_COMMAND));
    memcpy(command + sizeof(IPFS_ADD_COMMAND) - 1, file_name, strlen(file_name));
    printf("Command: %s\n", command);
    fp = popen(command, "r");
    if (fp == NULL) {
        error_handling("Popen failed.\n");
        exit(1);
    }
    while (fgets(buff, BUFF_SIZE, fp))
        printf("%s\n", buff);
    pclose(fp);
    char* result;
    strtok(buff, " ");
    result = strtok(NULL, " ");
    memcpy(hash_value, result, strlen(result));
    return strlen(result);
}

int file_encrypt_upload(session_key_t* s_key, SST_ctx_t* ctx, char* my_file_path, unsigned char* hash_value) {
    FILE* fgen, * fin, * fout, * fenc;
    fin = fopen(my_file_path, "r");
    unsigned long bufsize;
    bufsize = file_size_return(fin);
    unsigned char* file_buf = NULL;
    file_buf = malloc(sizeof(char) * (bufsize + 1));
    get_file_content(fin, file_buf, bufsize);
    fclose(fin);

    unsigned char iv[AES_CBC_128_IV_SIZE];
    int provider_len = sizeof(ctx->config->name);
    unsigned int encrypted_length = (((bufsize) / AES_CBC_128_IV_SIZE) + 1) * AES_CBC_128_IV_SIZE;
    unsigned char* encrypted = (unsigned char*)malloc(encrypted_length);
    generate_nonce(AES_CBC_128_IV_SIZE, iv);
    AES_CBC_128_encrypt(file_buf, bufsize, s_key->cipher_key, CIPHER_KEY_SIZE, iv,
        AES_CBC_128_IV_SIZE, encrypted, &encrypted_length);
    free(file_buf);
    printf("\nFile encryption was successful.\n");

    char file_name_buffer[20];
    file_duplication_check(ENCRYPTED_FILE_NAME, TXT_FILE_EXTENSION, &file_name_buffer[0]);

    // File descriptor for the encrypted file.
    fenc = fopen(file_name_buffer, "w");
    unsigned char* enc_save = (unsigned char*)malloc(encrypted_length + 1 + AES_CBC_128_IV_SIZE + 1 + provider_len);
    enc_save[0] = provider_len;
    memcpy(enc_save + 1, ctx->config->name, provider_len);
    enc_save[provider_len + 1] = AES_CBC_128_IV_SIZE;
    memcpy(enc_save + 1 + provider_len + 1, iv, AES_CBC_128_IV_SIZE);
    memcpy(enc_save + 1 + provider_len + 1 + AES_CBC_128_IV_SIZE, encrypted, encrypted_length);
    free(encrypted);
    fwrite(enc_save, 1, encrypted_length + 1 + AES_CBC_128_IV_SIZE + 1 + provider_len, fenc);
    free(enc_save);
    printf("File was saved: %s.\n", file_name_buffer);
    fclose(fenc);
    sleep(1);
    return execute_command_and_save_result(&file_name_buffer[0], hash_value);
}

void file_download_decrypt(session_key_t s_key, char* file_name) {
    FILE* fp, * fin, * fout;
    fin = fopen(file_name, "r");
    unsigned long bufsize;
    bufsize = file_size_return(fin);
    unsigned char* file_buf = NULL;
    file_buf = malloc(sizeof(char) * (bufsize + 1));
    get_file_content(fin, file_buf, bufsize);
    fclose(fin);

    unsigned int owner_name_len = file_buf[0];
    unsigned char owner_name[owner_name_len];
    memcpy(owner_name, file_buf + 1, owner_name_len);
    unsigned char iv[AES_CBC_128_IV_SIZE];
    memcpy(iv, file_buf + 1 + owner_name_len + 1, AES_CBC_128_IV_SIZE);

    unsigned long int enc_length = bufsize - (1 + AES_CBC_128_IV_SIZE + 1 + owner_name_len);
    unsigned int ret_length = (enc_length + AES_CBC_128_IV_SIZE) / AES_CBC_128_IV_SIZE * AES_CBC_128_IV_SIZE;
    unsigned char* ret = (unsigned char*)malloc(ret_length);
    sleep(1);
    AES_CBC_128_decrypt(file_buf + 1 + AES_CBC_128_IV_SIZE + 1 + owner_name_len, enc_length, s_key.cipher_key, CIPHER_KEY_SIZE, iv,
        AES_CBC_128_IV_SIZE, ret, &ret_length);
    free(file_buf);

    int reply_num = 0;
    char result_file_name[20];
    file_duplication_check(RESULT_FILE_NAME, TXT_FILE_EXTENSION, &result_file_name[0]);
    fout = fopen(result_file_name, "w");
    fwrite(ret, 1, ret_length, fout);
    free(ret);
    fclose(fout);
    printf("Completed decryption and saved the file: %s\n", result_file_name);
}

void upload_to_file_system_manager(session_key_t* s_key, SST_ctx_t* ctx, unsigned char* hash_value, int hash_value_len) {
    int sock;
    connect_as_client((const char*)ctx->config->file_system_manager_ip_addr,
        (const char*)ctx->config->file_system_manager_port_num, &sock);
    int key_id_size, name_size, purpose_size;
    key_id_size = sizeof(s_key->key_id);
    name_size = sizeof(ctx->config->name);
    unsigned char data[MAX_PAYLOAD_LENGTH];
    data[0] = UPLOAD_INDEX;
    data[1] = name_size;
    memcpy(data + 2, ctx->config->name, name_size);
    data[2 + name_size] = key_id_size;
    memcpy(data + 3 + name_size, s_key->key_id, key_id_size);
    data[3 + name_size + key_id_size] = hash_value_len;
    memcpy(data + 4 + name_size + key_id_size, hash_value, hash_value_len);
    write(sock, data, 4 + name_size + key_id_size + hash_value_len);
    printf("Send the data such as sessionkey id, hash value for file. \n");
}

void download_from_file_system_manager(unsigned char* skey_id_in_str, SST_ctx_t* ctx, char* file_name) {
    FILE* fin;
    int sock;
    connect_as_client((const char*)ctx->config->file_system_manager_ip_addr,
        (const char*)ctx->config->file_system_manager_port_num, &sock);
    int name_size;
    name_size = sizeof(ctx->config->name);
    unsigned char data[BUFF_SIZE];
    data[0] = DOWNLOAD_INDEX;
    data[1] = name_size;
    memcpy(data + 2, ctx->config->name, name_size);
    write(sock, data, 2 + name_size);
    sleep(1);
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length =
        read(sock, received_buf, sizeof(received_buf));
    printf("Receive the information for file.\n");
    int command_size;
    command_size = received_buf[2 + KEY_ID_SIZE];
    memcpy(skey_id_in_str, received_buf + 2, KEY_ID_SIZE);
    char command[BUFF_SIZE];
    memcpy(command, received_buf + 3 + KEY_ID_SIZE, command_size);
    file_duplication_check(DOWNLOAD_FILE_NAME, TXT_FILE_EXTENSION, file_name);
    memcpy(command + command_size - 1, file_name, strlen(file_name));
    printf("Command: %s \n", command);
    fin = popen(command, "r");
    pclose(fin);
    printf("Download the file: %s\n", file_name);
}

void send_add_reader_req_via_TCP(SST_ctx_t *ctx, char* add_reader) {
    int sock;
    connect_as_client((const char *)ctx->config->auth_ip_addr,
                      (const char *)ctx->config->auth_port_num, &sock);
    unsigned char entity_nonce[NONCE_SIZE];
    while (1) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
        unsigned int received_buf_length =
            read(sock, received_buf, sizeof(received_buf));
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == AUTH_HELLO) {
            unsigned int auth_Id;
            unsigned char auth_nonce[NONCE_SIZE];
            auth_Id = read_unsigned_int_BE(data_buf, AUTH_ID_LEN);
            memcpy(auth_nonce, data_buf + AUTH_ID_LEN, NONCE_SIZE);
            RAND_bytes(entity_nonce, NONCE_SIZE);

            unsigned int serialized_length;
            unsigned char *serialized = serialize_message_for_auth(
                entity_nonce, auth_nonce, 0,
                ctx->config->name, add_reader, &serialized_length);
            send_request_message(serialized, serialized_length, ctx, sock, 0);
        } else if (message_type == ADD_READER_RESP_WITH_DIST_KEY) {
            signed_data_t signed_data;
            size_t key_size = RSA_KEY_SIZE;

            // parse data
            unsigned int encrypted_entity_nonce_length =
                data_buf_length - (key_size * 2);
            unsigned char encrypted_entity_nonce[encrypted_entity_nonce_length];
            memcpy(signed_data.data, data_buf, key_size);
            memcpy(signed_data.sign, data_buf + key_size, key_size);
            memcpy(encrypted_entity_nonce, data_buf + key_size * 2,
                   encrypted_entity_nonce_length);

            // verify
            SHA256_verify(signed_data.data, key_size, signed_data.sign,
                          key_size, ctx->pub_key);
            printf("auth signature verified\n");

            // decrypt encrypted_distribution_key
            size_t decrypted_dist_key_buf_length;
            unsigned char *decrypted_dist_key_buf =
                private_decrypt(signed_data.data, key_size, RSA_PKCS1_PADDING,
                                ctx->priv_key, &decrypted_dist_key_buf_length);

            // parse decrypted_dist_key_buf to mac_key & cipher_key
            parse_distribution_key(&ctx->dist_key, decrypted_dist_key_buf,
                                   decrypted_dist_key_buf_length);
            free(decrypted_dist_key_buf);
            
            // decrypt entity_nonce with decrypted_dist_key_buf
            unsigned int decrypted_entity_nonce_length;
            unsigned char *decrypted_entity_nonce =
                symmetric_decrypt_authenticate(
                    encrypted_entity_nonce, encrypted_entity_nonce_length,
                    ctx->dist_key.mac_key, ctx->dist_key.mac_key_size,
                    ctx->dist_key.cipher_key, ctx->dist_key.cipher_key_size,
                    AES_CBC_128_IV_SIZE, &decrypted_entity_nonce_length);

            // parse decrypted_entity_nonce for nonce comparison
            printf("reply_nonce in addReaderResp: ");
            print_buf(decrypted_entity_nonce, NONCE_SIZE);

            if (strncmp((const char *)decrypted_entity_nonce, (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                error_handling("auth nonce NOT verified");
            } else {
                printf("auth nonce verified!\n");
            }
            printf("Add a file reader to the database.\n");
            close(sock);
            break;
        } else if (message_type == ADD_READER_RESP) {
            unsigned int decrypted_entity_nonce_length;
            unsigned char *decrypted_entity_nonce = symmetric_decrypt_authenticate(
                data_buf, data_buf_length, ctx->dist_key.mac_key,
                ctx->dist_key.mac_key_size, ctx->dist_key.cipher_key,
                ctx->dist_key.cipher_key_size, AES_CBC_128_IV_SIZE,
                &decrypted_entity_nonce_length);
            // parse decrypted_entity_nonce for nonce comparison
            printf("reply_nonce in addReaderResp: ");
            print_buf(decrypted_entity_nonce, NONCE_SIZE);

            if (strncmp((const char *)decrypted_entity_nonce, (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                error_handling("auth nonce NOT verified");
            } else {
                printf("auth nonce verified!\n");
            }
            printf("Add a file reader to the database.\n");
            close(sock);
            break;
        }
    }
}