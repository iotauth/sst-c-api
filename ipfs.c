#include "ipfs.h"

#include "c_secure_comm.h"

const char IPFS_ADD_COMMAND[] = "ipfs add ";
const char TXT_FILE_EXTENSION[] = ".txt";
const char ENCRYPTED_FILE_NAME[] = "encrypted";
const char RESULT_FILE_NAME[] = "result";
const char DOWNLOAD_FILE_NAME[] = "download";

void get_file_content(FILE *fin, unsigned char *file_buf,
                      unsigned long bufsize) {
    if (fseek(fin, 0L, SEEK_SET) != 0) {
        error_exit("Start point is not zero.\n");
        exit(1);
    }
    size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
    if (ferror(fin) != 0) {
        error_exit("Error reading file.\n");
        exit(1);
    }
    file_buf[newLen++] = '\0';
}

unsigned long file_size_return(FILE *fin) {
    unsigned long bufsize;
    if (fin == NULL) {
        error_exit("Cannot read the file.\n");
        exit(1);
    }
    if (fseek(fin, 0L, SEEK_END) != 0) {
        error_exit("Cannot move pointer to the end of file.\n");
    }
    bufsize = ftell(fin);

    return bufsize;
}

void file_duplication_check(const char *file_name, const char *file_extension,
                            char *file_name_buf) {
    int suffix_num = 0;
    // Copy file name.
    memcpy(file_name_buf, file_name, strlen(file_name));
    memcpy(file_name_buf + strlen(file_name), file_extension,
           strlen(file_extension));
    file_name_buf[strlen(file_name) + strlen(file_extension)] = '\0';
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
            memcpy(file_name_buf + strlen(file_name), suffix_in_string,
                   strlen(suffix_in_string));
            memcpy(file_name_buf + strlen(file_name) + strlen(suffix_in_string),
                   file_extension, strlen(file_extension));
            file_name_buf[strlen(file_name) + strlen(suffix_in_string) +
                          strlen(file_extension)] = '\0';
            suffix_num += 1;
        } else {
            break;
        }
    }
}

int execute_command_and_save_result(char *file_name, unsigned char *hash_value,
                                    estimate_time_t *estimate_time) {
    char buff[BUFF_SIZE];
    FILE *fp;
    char command[BUFF_SIZE];
    struct timeval upload_start, upload_end;
    gettimeofday(&upload_start, NULL);
    memcpy(command, IPFS_ADD_COMMAND, sizeof(IPFS_ADD_COMMAND));
    memcpy(command + sizeof(IPFS_ADD_COMMAND) - 1, file_name,
           strlen(file_name));
    printf("Command: %s\n", command);
    fp = popen(command, "r");
    if (fp == NULL) {
        error_exit("Popen failed.\n");
        exit(1);
    }
    while (fgets(buff, BUFF_SIZE, fp)) printf("%s\n", buff);
    pclose(fp);
    char *result;
    strtok(buff, " ");
    result = strtok(NULL, " ");
    memcpy(hash_value, result, strlen(result));
    gettimeofday(&upload_end, NULL);
    float upload_time = (upload_end.tv_sec - upload_start.tv_sec);
    float upload_utime = (upload_end.tv_usec - upload_start.tv_usec);
    estimate_time->up_download_time = upload_time + upload_utime / 1000000;
    return strlen(result);
}

int file_encrypt_upload(session_key_t *s_key, SST_ctx_t *ctx,
                        char *my_file_path, unsigned char *hash_value,
                        estimate_time_t *estimate_time) {
    FILE *fgen, *fin, *fout, *fenc;
    struct timeval encrypt_start, encrypt_end;
    gettimeofday(&encrypt_start, NULL);
    fin = fopen(my_file_path, "r");
    unsigned long bufsize;
    bufsize = file_size_return(fin);
    unsigned char *file_buf = NULL;
    file_buf = malloc(sizeof(char) * (bufsize + 1));
    get_file_content(fin, file_buf, bufsize);
    fclose(fin);

    unsigned char iv[AES_128_CBC_IV_SIZE];
    int provider_len = sizeof(ctx->config->name);
    unsigned int encrypted_length =
        (((bufsize) / AES_128_CBC_IV_SIZE) + 1) * AES_128_CBC_IV_SIZE;
    unsigned char *encrypted = (unsigned char *)malloc(encrypted_length);
    generate_nonce(AES_128_CBC_IV_SIZE, iv);
    if (encrypt_AES(file_buf, bufsize, s_key->cipher_key, iv, s_key->enc_mode,
                    encrypted, &encrypted_length)) {
        printf("Encryption failed!\n");
    }
    free(file_buf);
    printf("\nFile encryption was successful.\n");

    char file_name_buffer[20];
    file_duplication_check(ENCRYPTED_FILE_NAME, TXT_FILE_EXTENSION,
                           &file_name_buffer[0]);

    // File descriptor for the encrypted file.
    fenc = fopen(file_name_buffer, "w");
    unsigned char *enc_save = (unsigned char *)malloc(
        encrypted_length + 1 + AES_128_CBC_IV_SIZE + 1 + provider_len);
    enc_save[0] = provider_len;
    memcpy(enc_save + 1, ctx->config->name, provider_len);
    enc_save[provider_len + 1] = AES_128_CBC_IV_SIZE;
    memcpy(enc_save + 1 + provider_len + 1, iv, AES_128_CBC_IV_SIZE);
    memcpy(enc_save + 1 + provider_len + 1 + AES_128_CBC_IV_SIZE, encrypted,
           encrypted_length);
    free(encrypted);
    fwrite(enc_save, 1,
           encrypted_length + 1 + AES_128_CBC_IV_SIZE + 1 + provider_len, fenc);
    free(enc_save);
    printf("File was saved: %s.\n", file_name_buffer);
    fclose(fenc);
    gettimeofday(&encrypt_end, NULL);
    float encrypt_time = encrypt_end.tv_sec - encrypt_start.tv_sec;
    float encrypt_utime = encrypt_end.tv_usec - encrypt_start.tv_usec;
    estimate_time->enc_dec_time = encrypt_time + encrypt_utime / 1000000;
    sleep(1);
    return execute_command_and_save_result(&file_name_buffer[0], hash_value,
                                           estimate_time);
}

void file_decrypt_save(session_key_t s_key, char *file_name) {
    FILE *fp, *fin, *fout;
    fin = fopen(file_name, "r");
    unsigned long bufsize;
    bufsize = file_size_return(fin);
    unsigned char *file_buf = NULL;
    file_buf = malloc(sizeof(char) * (bufsize + 1));
    get_file_content(fin, file_buf, bufsize);
    fclose(fin);

    unsigned int owner_name_len = file_buf[0];
    unsigned char owner_name[owner_name_len];
    memcpy(owner_name, file_buf + 1, owner_name_len);
    unsigned char iv[AES_128_CBC_IV_SIZE];
    memcpy(iv, file_buf + 1 + owner_name_len + 1, AES_128_CBC_IV_SIZE);

    unsigned long int enc_length =
        bufsize - (1 + AES_128_CBC_IV_SIZE + 1 + owner_name_len);
    unsigned int ret_length = (enc_length + AES_128_CBC_IV_SIZE) /
                              AES_128_CBC_IV_SIZE * AES_128_CBC_IV_SIZE;
    unsigned char *ret = (unsigned char *)malloc(ret_length);
    if (decrypt_AES(file_buf + 1 + AES_128_CBC_IV_SIZE + 1 + owner_name_len,
                    enc_length, s_key.cipher_key, iv, s_key.enc_mode, ret,
                    &ret_length)) {
        printf("Error while decrypting.\n");
    }
    free(file_buf);

    int reply_num = 0;
    char result_file_name[20];
    file_duplication_check(RESULT_FILE_NAME, TXT_FILE_EXTENSION,
                           &result_file_name[0]);
    fout = fopen(result_file_name, "w");
    fwrite(ret, 1, ret_length, fout);
    free(ret);
    fclose(fout);
    printf("Completed decryption and saved the file: %s\n", result_file_name);
}

void upload_to_file_system_manager(session_key_t *s_key, SST_ctx_t *ctx,
                                   unsigned char *hash_value,
                                   int hash_value_len) {
    int sock;
    connect_as_client((const char *)ctx->config->file_system_manager_ip_addr,
                      (const char *)ctx->config->file_system_manager_port_num,
                      &sock);
    int key_id_size, name_size;
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

int make_upload_req_buffer(session_key_t *s_key, SST_ctx_t *ctx,
                           unsigned char *hash_value, int hash_value_len,
                           char *concat_buffer) {
    int key_id_size, name_size;
    key_id_size = sizeof(s_key->key_id);
    name_size = sizeof(ctx->config->name);
    int index = 0;
    concat_buffer[index] = UPLOAD_INDEX;
    index += 1;
    concat_buffer[index] = name_size;
    index += 1;
    memcpy(concat_buffer + index, ctx->config->name, name_size);
    index += name_size;
    concat_buffer[index] = key_id_size;
    index += 1;
    memcpy(concat_buffer + index, s_key->key_id, key_id_size);
    index += key_id_size;
    concat_buffer[index] = hash_value_len;
    index += 1;
    memcpy(concat_buffer + index, hash_value, hash_value_len);
    index += hash_value_len;
    return index;
}

int make_download_req_buffer(SST_ctx_t *ctx, char *concat_buffer) {
    int name_size;
    name_size = sizeof(ctx->config->name);
    int index = 0;
    concat_buffer[index] = DOWNLOAD_INDEX;
    index += 1;
    concat_buffer[index] = name_size;
    index += 1;
    memcpy(concat_buffer + index, ctx->config->name, name_size);
    index += name_size;
    return index;
}

void receive_data_and_download_file(unsigned char *skey_id_in_str,
                                    SST_ctx_t *ctx, char *file_name,
                                    estimate_time_t *estimate_time) {
    FILE *fin;
    int sock;
    struct timeval filemanager_start, filemanager_end;
    gettimeofday(&filemanager_start, NULL);
    connect_as_client((const char *)ctx->config->file_system_manager_ip_addr,
                      (const char *)ctx->config->file_system_manager_port_num,
                      &sock);
    int name_size;
    name_size = sizeof(ctx->config->name);
    unsigned char data[BUFF_SIZE];
    data[0] = DOWNLOAD_INDEX;
    data[1] = name_size;
    memcpy(data + 2, ctx->config->name, name_size);
    write(sock, data, 2 + name_size);
    unsigned char received_buf[MAX_PAYLOAD_LENGTH];
    unsigned int received_buf_length =
        read_from_socket(sock, received_buf, sizeof(received_buf));
    printf("Receive the information for file.\n");
    gettimeofday(&filemanager_end, NULL);
    float filemanager_time =
        (filemanager_end.tv_sec - filemanager_start.tv_sec);
    float filemanager_utime =
        (filemanager_end.tv_usec - filemanager_start.tv_usec);
    estimate_time->filemanager_time =
        filemanager_time + filemanager_utime / 1000000;
    struct timeval download_start, download_end;
    gettimeofday(&download_start, NULL);
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
    gettimeofday(&download_end, NULL);
    float download_time = (download_end.tv_sec - download_start.tv_sec);
    float download_utime = (download_end.tv_usec - download_start.tv_usec);
    estimate_time->up_download_time = download_time + download_utime / 1000000;
}

void download_file(unsigned char *received_buf, unsigned char *skey_id_in_str,
                   char *file_name) {
    FILE *fin;
    int command_size;
    command_size = received_buf[2 + KEY_ID_SIZE];
    memcpy(skey_id_in_str, received_buf + 2, KEY_ID_SIZE);
    char command[BUFF_SIZE];
    memcpy(command, received_buf + 3 + KEY_ID_SIZE, command_size);
    file_duplication_check(DOWNLOAD_FILE_NAME, TXT_FILE_EXTENSION, file_name);
    memcpy(command + command_size - 1, file_name, strlen(file_name));
    memcpy(command + command_size + strlen(file_name) - 1, "\n", 1);
    printf("Command: %s \n", command);
    fin = popen(command, "r");
    pclose(fin);
    printf("Success for downloading %s.\n", file_name);
}

void send_add_reader_req_via_TCP(SST_ctx_t *ctx, char *add_reader) {
    int sock;
    connect_as_client((const char *)ctx->config->auth_ip_addr,
                      (const char *)ctx->config->auth_port_num, &sock);
    unsigned char entity_nonce[NONCE_SIZE];
    for (;;) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
        unsigned int received_buf_length =
            read_from_socket(sock, received_buf, sizeof(received_buf));
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
                entity_nonce, auth_nonce, 0, ctx->config->name, add_reader,
                &serialized_length);
            send_auth_request_message(serialized, serialized_length, ctx, sock,
                                      0);
        } else if (message_type == ADD_READER_RESP_WITH_DIST_KEY) {
            size_t key_size = RSA_KEY_SIZE;
            unsigned int encrypted_entity_nonce_length =
                data_buf_length - (key_size * 2);
            unsigned char encrypted_entity_nonce[encrypted_entity_nonce_length];
            memcpy(encrypted_entity_nonce, data_buf + key_size * 2,
                   encrypted_entity_nonce_length);
            save_distribution_key(data_buf, ctx, key_size);
            unsigned int decrypted_entity_nonce_length;
            unsigned char *decrypted_entity_nonce;
            if (symmetric_decrypt_authenticate(
                    encrypted_entity_nonce, encrypted_entity_nonce_length,
                    ctx->dist_key.mac_key, ctx->dist_key.mac_key_size,
                    ctx->dist_key.cipher_key, ctx->dist_key.cipher_key_size,
                    AES_128_CBC_IV_SIZE, AES_128_CBC, 0,
                    &decrypted_entity_nonce, &decrypted_entity_nonce_length)) {
                error_exit(
                    "Error during decryption after receiving "
                    "ADD_READER_RESP_WITH_DIST_KEY.\n");
            }
            if (strncmp((const char *)decrypted_entity_nonce,
                        (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                error_exit("Auth nonce NOT verified");
            } else {
                printf("Auth nonce verified!\n");
            }
            printf("Add a file reader to the database.\n");
            close(sock);
            break;
        } else if (message_type == ADD_READER_RESP) {
            unsigned int decrypted_entity_nonce_length;
            unsigned char *decrypted_entity_nonce;
            if (symmetric_decrypt_authenticate(
                    data_buf, data_buf_length, ctx->dist_key.mac_key,
                    ctx->dist_key.mac_key_size, ctx->dist_key.cipher_key,
                    ctx->dist_key.cipher_key_size, AES_128_CBC_IV_SIZE,
                    AES_128_CBC, 0, &decrypted_entity_nonce,
                    &decrypted_entity_nonce_length)) {
                error_exit(
                    "Error during decryption after receiving "
                    "ADD_READER_RESP.\n");
            }
            if (strncmp((const char *)decrypted_entity_nonce,
                        (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                error_exit("Auth nonce NOT verified");
            } else {
                printf("Auth nonce verified!\n");
            }
            printf("Add a file reader to the database.\n");
            close(sock);
            break;
        }
    }
}
