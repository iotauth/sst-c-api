#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../../ipfs.h"

#define MAX_PAYLOAD_LENGTH 1024

int main(int argc, char* argv[]) {
    if (argc != 4) {
        SST_print_error_exit(
            "Usage: %s <config_path> <my_file_path> <add_reader_path>",
            argv[0]);
    }
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }

    FILE* add_reader_file = fopen(add_reader_path, "r");
    char addReader[64];
    if (add_reader_file == NULL) {
        fputs("Cannot open file.", stderr);
        SST_print_error_exit("File open failed.");
    }
    while (fgets(addReader, sizeof(addReader), add_reader_file) != NULL) {
        if (send_add_reader_req_via_TCP(ctx, addReader) < 0) {
            SST_print_error_exit("Failed send_add_reader_req_via_TCP().");
        }
    }
    fclose(add_reader_file);

    // Set purpose to make session key request for file sharing.
    ctx->config->purpose_index = 1;
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    if (s_key_list_0 == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len;
    estimate_time_t estimate_time[5];
    hash_value_len =
        file_encrypt_upload(&s_key_list_0->s_key[0], ctx, my_file_path,
                            &hash_value[0], &estimate_time[0]);
    if (hash_value_len < 0) {
        SST_print_error_exit("Failed file_encrypt_upload()");
    }
    char concat_buffer[MAX_PAYLOAD_LENGTH];
    int concat_buffer_size =
        make_upload_req_buffer(&s_key_list_0->s_key[0], ctx, &hash_value[0],
                               hash_value_len, &concat_buffer[0]);
    ctx->config->purpose_index = 0;
    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error_exit("Failed get_session_key().");
    }
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }
    sleep(1);
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread_read_one_each,
                   (void*)session_ctx);
    int msg = send_secure_message("Hello", strlen("Hello"), session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    sleep(1);
    msg = send_secure_message(concat_buffer, concat_buffer_size, session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }
    free_SST_ctx_t(ctx);
    pthread_cancel(thread);
}
