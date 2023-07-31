
#include "ipfs.h"

const char IPFS_ADD_COMMAND[] = "ipfs add ";
const char TXT_NAME[] = ".txt";
const char ENCRYPTED_NAME[] = "encrypted";
const char RESULT_NAME[] = "result";
const char DOWNLOAD_NAME[] = "download";


void file_duplication_check(unsigned char* file_name, unsigned char* file_extension, unsigned char* file_buf)
{
    int suffix_num = 0;
    int file_check_index = DEFAULT_CHECK_INDEX;
    memcpy(file_buf, file_name, strlen(file_name));
    memcpy(file_buf + strlen(file_name), file_extension, sizeof(file_extension));
    while (file_check_index) {
        if (suffix_num == MAX_REPLY_NUM) {
            printf("Cannot save the file. \n");
            exit(1);
        }
        if (0 == access(file_buf, F_OK)) {
            printf("File already exists: %s\n", file_buf);
            char suffix_cnum[10];
            sprintf(suffix_cnum, "%d", suffix_num);
            memcpy(file_buf + sizeof(file_name), suffix_cnum, strlen(suffix_cnum));
            memcpy(file_buf + sizeof(file_name) + strlen(suffix_cnum), file_extension, sizeof(file_extension));
            suffix_num += 1;
        }
        else {
            file_check_index = CHECK_PASS;
            break;
        }
    }
}

void ipfs_add_command_save_result(char* file_name, unsigned char* hash_value)
{
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
}


void file_encrypt_upload(SST_session_ctx_t* session_ctx, SST_ctx_t* ctx, char* my_file_path, unsigned char* hash_value)
{
    FILE* fgen, * fin, * fout, * fenc;
    fin = fopen(my_file_path, "r");
    unsigned char* file_buf = NULL;
    unsigned long bufsize;
    if (fin == NULL) {
        error_handling("Cannot read the file. \n");
        exit(1);
    }
    else {
        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));
            if (fseek(fin, 0L, SEEK_SET) != 0) {
                error_handling("Start point is not zero.\n");
                exit(1);
            }
            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if (ferror(fin) != 0) {
                error_handling("Error reading file.\n");
                exit(1);
            }
            else {
                file_buf[newLen++] = '\0';
            }
        }
    }
    fclose(fin);
    unsigned char iv[AES_CBC_128_IV_SIZE];
    int provider_len = sizeof(ctx->config->name);
    unsigned int encrypted_length = (((bufsize) / AES_CBC_128_IV_SIZE) + 1) * AES_CBC_128_IV_SIZE;
    unsigned char* encrypted = (unsigned char*)malloc(encrypted_length);
    generate_nonce(AES_CBC_128_IV_SIZE, iv);
    AES_CBC_128_encrypt(file_buf, bufsize, session_ctx->s_key.cipher_key, CIPHER_KEY_SIZE, iv,
        AES_CBC_128_IV_SIZE, encrypted, &encrypted_length);
    free(file_buf);
    printf("Success file encryption.\n\n");

    unsigned char file_buffer[20];
    file_duplication_check(ENCRYPTED_NAME, TXT_NAME, &file_buffer);

    fenc = fopen(file_buffer, "w");
    unsigned char* enc_save = (unsigned char*)malloc(encrypted_length + 1 + AES_CBC_128_IV_SIZE + 1 + provider_len);
    enc_save[0] = provider_len;
    memcpy(enc_save + 1, ctx->config->name, provider_len);
    enc_save[provider_len + 1] = AES_CBC_128_IV_SIZE;
    memcpy(enc_save + 1 + provider_len + 1, iv, AES_CBC_128_IV_SIZE);
    memcpy(enc_save + 1 + provider_len + 1 + AES_CBC_128_IV_SIZE, encrypted, encrypted_length);
    fwrite(enc_save, 1, encrypted_length + 1 + AES_CBC_128_IV_SIZE + 1 + provider_len, fenc);
    free(enc_save);
    printf("File is saved: %s.\n", file_buffer);
    fclose(fenc);
    free(encrypted);
    sleep(1);
    ipfs_add_command_save_result(&file_buffer, hash_value);
}

void file_download_decrypt(SST_session_ctx_t* session_ctx, unsigned char* file_name)
{
    FILE* fp, * fin, * fout;
    fin = fopen(file_name, "r");
    unsigned char* file_buf = NULL;
    unsigned long bufsize;
    if (fin == NULL) {
        error_handling("Cannot read the file. \n");
        exit(1);
    }
    else {
        // Move the pointer to the end of the file and save the length of the buffer to buffsize.
        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));
            if (fseek(fin, 0L, SEEK_SET) != 0) {
                error_handling("Start point is not zero.\n");
                exit(1);
            }
            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if (ferror(fin) != 0)
            {
                error_handling("Error reading file\n");
                exit(1);
            }
            else {
                file_buf[newLen++] = '\0';
            }
        }
        fclose(fin);
    }
    unsigned int owner_name_len = file_buf[0];
    unsigned char owner_name[owner_name_len];
    memcpy(owner_name, file_buf + 1, owner_name_len);
    unsigned char iv[AES_CBC_128_IV_SIZE];
    memcpy(iv, file_buf + 1 + owner_name_len + 1, AES_CBC_128_IV_SIZE);

    unsigned long int enc_length = bufsize - (1 + AES_CBC_128_IV_SIZE + 1 + owner_name_len);
    unsigned int ret_length = (enc_length + AES_CBC_128_IV_SIZE) / AES_CBC_128_IV_SIZE * AES_CBC_128_IV_SIZE;
    unsigned char* ret = (unsigned char*)malloc(ret_length);
    sleep(1);
    AES_CBC_128_decrypt(file_buf + 1 + AES_CBC_128_IV_SIZE + 1 + owner_name_len, enc_length, session_ctx->s_key.cipher_key, CIPHER_KEY_SIZE, iv,
        AES_CBC_128_IV_SIZE, ret, &ret_length);
    free(file_buf);

    int reply_num = 0;
    unsigned char result_name[20];
    file_duplication_check(RESULT_NAME, TXT_NAME, result_name);
    fout = fopen(result_name, "w");
    fwrite(ret, 1, ret_length, fout);
    free(ret);
    fclose(fout);
    printf("Complete decryption and save the file: %s\n", result_name);

}

void upload_to_datamanagement(SST_session_ctx_t* session_ctx, SST_ctx_t* ctx, unsigned char* hash_value)
{
    int sock;
    connect_as_client((const char*)ctx->config->datamanagement_ip_addr,
        (const char*)ctx->config->datamanagement_port_num, &sock);
    int key_id_size, name_size, purpose_size;
    key_id_size = sizeof(session_ctx->s_key.key_id);
    name_size = sizeof(ctx->config->name);
    unsigned char data[MAX_PAYLOAD_LENGTH];
    data[0] = UPLOAD_INDEX;
    data[1] = name_size;
    memcpy(data + 2, ctx->config->name, name_size);
    data[2 + name_size] = key_id_size;
    memcpy(data + 3 + name_size, session_ctx->s_key.key_id, key_id_size);
    data[3 + name_size + key_id_size] = strlen(hash_value);
    memcpy(data + 4 + name_size + key_id_size, hash_value, strlen(hash_value));
    write(sock, data, 4 + name_size + key_id_size + strlen(hash_value));
    printf("Send the data such as sessionkey id, hash value for file. \n");
}

void download_from_datamanagement(SST_session_ctx_t* session_ctx, SST_ctx_t* ctx, unsigned char* file_name)
{
    FILE* fin;
    int sock;
    connect_as_client((const char*)ctx->config->datamanagement_ip_addr,
        (const char*)ctx->config->datamanagement_port_num, &sock);
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

    if (strcmp((const char*)session_ctx->s_key.key_id, key_id) == 0)
        printf("Already have sessionkey: %x\n", key_id);
    // TODO: Sessionkey request to Auth.
    // else
    unsigned char command[BUFF_SIZE];
    memcpy(command, received_buf + 3 + KEY_ID_SIZE, command_size);
    file_duplication_check(DOWNLOAD_NAME, TXT_NAME, file_name);
    memcpy(command + command_size - 1, file_name, strlen(file_name));
    printf("Command: %s \n", command);
    fin = popen(command, "r");
    pclose(fin);
    printf("Download the file: %s\n", file_name);
}