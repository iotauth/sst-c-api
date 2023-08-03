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
    memcpy(file_name_buf + strlen(file_name), file_extension, strlen(file_name));
    file_name_buf[strlen(file_name) + strlen(file_name)] = 0;
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
    printf("Success file encryption.\n\n");

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
    printf("File is saved: %s.\n", file_name_buffer);
    fclose(fenc);
    sleep(1);
    return execute_command_and_save_result(&file_name_buffer[0], hash_value);
}

void file_download_decrypt(session_key_t* s_key, char* file_name) {
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
    AES_CBC_128_decrypt(file_buf + 1 + AES_CBC_128_IV_SIZE + 1 + owner_name_len, enc_length, s_key->cipher_key, CIPHER_KEY_SIZE, iv,
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

void download_from_file_system_manager(session_key_t* s_key, SST_ctx_t* ctx, char* file_name) {
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
    unsigned char key_id[KEY_ID_SIZE];
    command_size = received_buf[2 + KEY_ID_SIZE];
    memcpy(key_id, received_buf + 2, KEY_ID_SIZE);

    if (strcmp((const char*)s_key->key_id, (const char*)key_id) == 0) {
        printf("Already have sessionkey:\n");
        print_buf(key_id, KEY_ID_SIZE);
    }
    // TODO: Sessionkey request to Auth.
    // else
    char command[BUFF_SIZE];
    memcpy(command, received_buf + 3 + KEY_ID_SIZE, command_size);
    file_duplication_check(DOWNLOAD_FILE_NAME, TXT_FILE_EXTENSION, file_name);
    memcpy(command + command_size - 1, file_name, strlen(file_name));
    printf("Command: %s \n", command);
    fin = popen(command, "r");
    pclose(fin);
    printf("Download the file: %s\n", file_name);
}
