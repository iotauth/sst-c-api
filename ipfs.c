#include "ipfs.h"

#include <sys/time.h>
#include <unistd.h>

#include "c_common.h"
#include "c_crypto.h"
#include "c_secure_comm.h"

#define MAX_FILE_SUFFIX_LENGTH 5
#define MAX_FILENAME_LENGTH 512

const char IPFS_ADD_COMMAND[] = "ipfs add --quiet ";
const char TXT_FILE_EXTENSION[] = ".txt";
const char ENCRYPTED_FILE_NAME[] = "encrypted";
const char RESULT_FILE_NAME[] = "result";
const char DOWNLOAD_FILE_NAME[] = "download";

int get_file_content(FILE *fin, unsigned char *file_buf,
                     unsigned long bufsize) {
    if (fseek(fin, 0L, SEEK_SET) != 0) {
        SST_print_error("Start point is not zero.");
        return -1;
    }
    size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
    if (ferror(fin) != 0) {
        SST_print_error("Error reading file.");
        return -1;
    }
    file_buf[newLen++] = '\0';
    return 0;
}

int64_t file_size_return(FILE *fin) {
    if (fin == NULL) {
        SST_print_error("Cannot read the file.");
        return -1;
    }
    if (fseek(fin, 0L, SEEK_END) != 0) {
        SST_print_error("Cannot move pointer to the end of file.");
        return -1;
    }
    int64_t bufsize = ftell(fin);

    return bufsize;
}

void file_duplication_check(const char *file_name, const char *file_extension,
                            char *file_name_buf) {
    int suffix_num = 0;

    while (suffix_num < MAX_REPLY_NUM) {
        if (suffix_num == 0) {
            // First attempt: plain name + extension
            snprintf(file_name_buf, MAX_FILENAME_LENGTH, "%s%s", file_name,
                     file_extension);
        } else {
            // Build suffixed version: name + suffix + extension
            char suffix_in_string[MAX_FILE_SUFFIX_LENGTH + 1];
            snprintf(suffix_in_string, sizeof(suffix_in_string), "%d",
                     suffix_num);

            snprintf(file_name_buf, MAX_FILENAME_LENGTH, "%s%s%s", file_name,
                     suffix_in_string, file_extension);
        }

        if (access(file_name_buf, F_OK) == 0) {
            // File already exists
            SST_print_log("File already exists: %s.", file_name_buf);
            suffix_num++;
        } else {
            // Found a non-existing name
            return;
        }
    }

    SST_print_error(
        "Cannot save the file as file name's suffix number exceeds max.");
}

int execute_command_and_save_result(char *file_name, unsigned char *hash_value,
                                    estimate_time_t *estimate_time) {
    char buff[BUFF_SIZE];
    FILE *fp;
    char command[BUFF_SIZE];
    struct timeval upload_start, upload_end;
    gettimeofday(&upload_start, NULL);
    snprintf(command, sizeof(command), "%s%s", IPFS_ADD_COMMAND, file_name);
    SST_print_log("Command: %s", command);
    fp = popen(command, "r");
    if (fp == NULL) {
        SST_print_error("popen() failed.");
        return -1;
    }
    if (fgets(buff, sizeof(buff), fp) == NULL) {
        SST_print_error("Failed to read CID from ipfs output.");
        pclose(fp);
        return -1;
    }
    pclose(fp);
    // Strip newline
    buff[strcspn(buff, "\r\n")] = '\0';
    size_t cid_len = strlen(buff);
    memcpy(hash_value, buff, cid_len + 1);  // +1 to include null terminator
    gettimeofday(&upload_end, NULL);
    float upload_time = (upload_end.tv_sec - upload_start.tv_sec);
    float upload_utime = (upload_end.tv_usec - upload_start.tv_usec);
    estimate_time->up_download_time = upload_time + upload_utime / 1000000;
    return cid_len;
}

int file_encrypt_upload(session_key_t *s_key, SST_ctx_t *ctx,
                        char *my_file_path, unsigned char *hash_value,
                        estimate_time_t *estimate_time) {
    struct timeval encrypt_start, encrypt_end;
    gettimeofday(&encrypt_start, NULL);
    FILE *fin = fopen(my_file_path, "r");
    int64_t bufsize = file_size_return(fin);
    if (bufsize < 0) {
        SST_print_error("Failed file_size_return()");
    }
    unsigned char *file_buf = NULL;
    file_buf = malloc(sizeof(char) * (bufsize + 1));
    if (get_file_content(fin, file_buf, bufsize) < 0) {
        SST_print_error("Failed get_file_content()");
        free(file_buf);
        return -1;
    }
    fclose(fin);

    unsigned char iv[AES_128_CBC_IV_SIZE];
    int provider_len = sizeof(ctx->config->name);
    unsigned int encrypted_length =
        (((bufsize) / AES_128_CBC_IV_SIZE) + 1) * AES_128_CBC_IV_SIZE;
    unsigned char *encrypted = (unsigned char *)malloc(encrypted_length);
    if (generate_nonce(AES_128_CBC_IV_SIZE, iv) < 0) {
        SST_print_error("Failed generate_nonce().");
        return -1;
    }
    if (encrypt_AES(file_buf, bufsize, s_key->cipher_key, iv, s_key->enc_mode,
                    encrypted, &encrypted_length) < 0) {
        SST_print_error("Encryption failed!");
        return -1;
    }
    free(file_buf);
    SST_print_log("File encryption was successful.");

    char file_name_buffer[20];
    file_duplication_check(ENCRYPTED_FILE_NAME, TXT_FILE_EXTENSION,
                           &file_name_buffer[0]);

    // File descriptor for the encrypted file.
    FILE *fenc = fopen(file_name_buffer, "w");
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
    SST_print_log("File was saved: %s.", file_name_buffer);
    fclose(fenc);
    gettimeofday(&encrypt_end, NULL);
    float encrypt_time = encrypt_end.tv_sec - encrypt_start.tv_sec;
    float encrypt_utime = encrypt_end.tv_usec - encrypt_start.tv_usec;
    estimate_time->enc_dec_time = encrypt_time + encrypt_utime / 1000000;
    sleep(1);
    int ret = execute_command_and_save_result(&file_name_buffer[0], hash_value,
                                              estimate_time);
    if (ret < 0) {
        SST_print_error("Failed execute_command_and_save_result()");
    }
    return ret;
}

int file_decrypt_save(session_key_t s_key, char *file_name) {
    FILE *fin = fopen(file_name, "r");
    int64_t bufsize = file_size_return(fin);
    if (bufsize < 0) {
        SST_print_error("Failed file_size_return()");
    }
    unsigned char *file_buf = NULL;
    file_buf = malloc(sizeof(char) * (bufsize + 1));
    if (get_file_content(fin, file_buf, bufsize) < 0) {
        SST_print_error("Failed get_file_content()");
        free(file_buf);
        return -1;
    }
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
                    &ret_length) < 0) {
        SST_print_error("Error while decrypting.");
        return -1;
    }
    free(file_buf);

    char result_file_name[20];
    file_duplication_check(RESULT_FILE_NAME, TXT_FILE_EXTENSION,
                           &result_file_name[0]);
    FILE *fout = fopen(result_file_name, "w");
    fwrite(ret, 1, ret_length, fout);
    free(ret);
    fclose(fout);
    SST_print_log("Completed decryption and saved the file: %s",
                  result_file_name);
    return 0;
}

int upload_to_file_system_manager(session_key_t *s_key, SST_ctx_t *ctx,
                                  unsigned char *hash_value,
                                  int hash_value_len) {
    int sock;
    if (connect_as_client(
            (const char *)ctx->config->file_system_manager_ip_addr,
            ctx->config->file_system_manager_port_num, &sock) < 0) {
        SST_print_error("Failed connect_as_client().");
        return -1;
    }
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
    int bytes_written = sst_write_to_socket(
        sock, data, 4 + name_size + key_id_size + hash_value_len);
    if (bytes_written < 0) {
        SST_print_error("Failed sst_write_to_socket().");
        return -1;
    }
    SST_print_log("Send the data such as sessionkey id, hash value for file. ");
    return 0;
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

int receive_data_and_download_file(unsigned char *skey_id_in_str,
                                   SST_ctx_t *ctx, char *file_name,
                                   estimate_time_t *estimate_time) {
    FILE *fin;
    int sock;
    struct timeval filemanager_start, filemanager_end;
    gettimeofday(&filemanager_start, NULL);
    if (connect_as_client(
            (const char *)ctx->config->file_system_manager_ip_addr,
            ctx->config->file_system_manager_port_num, &sock) < 0) {
        SST_print_error("Failed connect_as_client().");
        return -1;
    }
    int name_size;
    name_size = sizeof(ctx->config->name);
    unsigned char data[BUFF_SIZE];
    data[0] = DOWNLOAD_INDEX;
    data[1] = name_size;
    memcpy(data + 2, ctx->config->name, name_size);
    int bytes_written = sst_write_to_socket(sock, data, 2 + name_size);
    if (bytes_written < 0) {
        SST_print_error("Failed sst_write_to_socket().");
        return -1;
    }
    unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
    int received_buf_length =
        sst_read_from_socket(sock, received_buf, sizeof(received_buf));
    if (received_buf_length < 0) {
        SST_print_error("Socket read error in sst_read_from_socket().");
        return -1;
    }
    SST_print_log("Receive the information for file.");
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
    char base_command[BUFF_SIZE];
    memcpy(base_command, received_buf + 3 + KEY_ID_SIZE, command_size);
    base_command[command_size] = '\0';  // Null-terminate it
    file_duplication_check(DOWNLOAD_FILE_NAME, TXT_FILE_EXTENSION, file_name);
    snprintf(command, sizeof(command), "%s%s", base_command, file_name);
    SST_print_log("Command: %s", command);
    fin = popen(command, "r");
    pclose(fin);
    SST_print_log("Download the file: %s", file_name);
    gettimeofday(&download_end, NULL);
    float download_time = (download_end.tv_sec - download_start.tv_sec);
    float download_utime = (download_end.tv_usec - download_start.tv_usec);
    estimate_time->up_download_time = download_time + download_utime / 1000000;
    return 0;
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
    SST_print_log("Command: %s ", command);
    fin = popen(command, "r");
    pclose(fin);
    SST_print_log("Success for downloading %s.", file_name);
}

int send_add_reader_req_via_TCP(SST_ctx_t *ctx, char *add_reader) {
    int sock;
    if (connect_as_client((const char *)ctx->config->auth_ip_addr,
                          ctx->config->auth_port_num, &sock) < 0) {
        SST_print_error("Failed connect_as_client().");
        return -1;
    }
    unsigned char entity_nonce[NONCE_SIZE];
    for (;;) {
        unsigned char received_buf[MAX_AUTH_COMM_LENGTH];
        int received_buf_length =
            sst_read_from_socket(sock, received_buf, sizeof(received_buf));
        if (received_buf_length < 0) {
            SST_print_error(
                "Socket read error in send_add_reader_req_via_TCP().");
            return -1;
        }
        unsigned char message_type;
        unsigned int data_buf_length;
        unsigned char *data_buf = parse_received_message(
            received_buf, received_buf_length, &message_type, &data_buf_length);
        if (message_type == AUTH_HELLO) {
            if (handle_AUTH_HELLO(data_buf, ctx, entity_nonce, sock, 0,
                                  add_reader, 0) < 0) {
                SST_print_error("AUTH_HELLO handling failed.");
                return -1;
            }
        } else if (message_type == ADD_READER_RESP_WITH_DIST_KEY) {
            size_t key_size = RSA_KEY_SIZE;
            unsigned int encrypted_entity_nonce_length =
                data_buf_length - (key_size * 2);
            unsigned char encrypted_entity_nonce[encrypted_entity_nonce_length];
            memcpy(encrypted_entity_nonce, data_buf + key_size * 2,
                   encrypted_entity_nonce_length);
            if (save_distribution_key(data_buf, ctx, key_size) < 0) {
                SST_print_error("Failed save_distribution_key().");
                return -1;
            }
            unsigned int decrypted_entity_nonce_length;
            unsigned char *decrypted_entity_nonce = NULL;
            if (symmetric_decrypt_authenticate(
                    encrypted_entity_nonce, encrypted_entity_nonce_length,
                    ctx->dist_key.mac_key, ctx->dist_key.mac_key_size,
                    ctx->dist_key.cipher_key, ctx->dist_key.cipher_key_size,
                    AES_128_CBC_IV_SIZE, ctx->config->encryption_mode, 0,
                    &decrypted_entity_nonce,
                    &decrypted_entity_nonce_length) < 0) {
                SST_print_error(
                    "Error during decryption after receiving "
                    "ADD_READER_RESP_WITH_DIST_KEY.");
                return -1;
            }
            if (strncmp((const char *)decrypted_entity_nonce,
                        (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                SST_print_error("Auth nonce NOT verified");
                return -1;
            } else {
                SST_print_debug("Auth nonce verified!");
            }
            SST_print_log("Add a file reader to the database.");
            close(sock);
            break;
        } else if (message_type == ADD_READER_RESP) {
            unsigned int decrypted_entity_nonce_length;
            unsigned char *decrypted_entity_nonce = NULL;
            if (symmetric_decrypt_authenticate(
                    data_buf, data_buf_length, ctx->dist_key.mac_key,
                    ctx->dist_key.mac_key_size, ctx->dist_key.cipher_key,
                    ctx->dist_key.cipher_key_size, AES_128_CBC_IV_SIZE,
                    AES_128_CBC, 0, &decrypted_entity_nonce,
                    &decrypted_entity_nonce_length) < 0) {
                SST_print_error(
                    "Error during decryption after receiving "
                    "ADD_READER_RESP.");
                return -1;
            }
            if (strncmp((const char *)decrypted_entity_nonce,
                        (const char *)entity_nonce,
                        NONCE_SIZE) != 0) {  // compare generated entity's nonce
                                             // & received entity's nonce.
                SST_print_error("Auth nonce NOT verified");
                return -1;
            } else {
                SST_print_debug("Auth nonce verified!");
            }
            SST_print_log("Add a file reader to the database.");
            close(sock);
            break;
        }
    }
    return 0;
}
