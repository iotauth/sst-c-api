#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../ipfs.h"

#define MAX_PAYLOAD_LENGTH 1024

void* SST_read_thread(void* SST_session_ctx) {
    SST_session_ctx_t* session_ctx = (SST_session_ctx_t*)SST_session_ctx;
    unsigned char data_buf[512];
    unsigned int data_buf_length = 0;
    while (1) {
        data_buf_length = SST_read(session_ctx, data_buf, 512);
        if (data_buf_length < 0) {
            printf("Read failed.\n");
            break;
        } else if (data_buf_length == 0) {
            printf("Disconnected.\n");
            break;
        }
        printf("Received from client: %s\n", data_buf);
        printf("--------------------\n");
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fputs("Enter config path, file path, and reader path.", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);

    FILE* add_reader_file = fopen(add_reader_path, "r");
    char addReader[64];
    if (add_reader_file == NULL) {
        fputs("Cannot open file.", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    while (fgets(addReader, sizeof(addReader), add_reader_file) != NULL) {
        send_add_reader_req_via_TCP(ctx, addReader);
    }
    fclose(add_reader_file);

    // Set purpose to make session key request for file sharing.
    ctx->config->purpose_index = 1;
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len;
    estimate_time_t estimate_time[5];
    hash_value_len =
        file_encrypt_upload(&s_key_list_0->s_key[0], ctx, my_file_path,
                            &hash_value[0], &estimate_time[0]);
    char concat_buffer[MAX_PAYLOAD_LENGTH];
    int concat_buffer_size =
        make_upload_req_buffer(&s_key_list_0->s_key[0], ctx, &hash_value[0],
                               hash_value_len, &concat_buffer[0]);
    ctx->config->purpose_index = 0;
    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    sleep(1);
    pthread_t thread;
    pthread_create(&thread, NULL, &SST_read_thread, (void*)session_ctx);
    SST_write(session_ctx, "Hello", strlen("Hello"));
    sleep(1);
    SST_write(session_ctx, concat_buffer, concat_buffer_size);
    free_SST_ctx_t(ctx);
    pthread_join(thread, NULL);
}