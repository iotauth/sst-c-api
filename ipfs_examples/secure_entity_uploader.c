#include "../ipfs.h"
#include <string.h>
#include <stdlib.h>

#define MAX_PAYLOAD_LENGTH 1024

int main(int argc, char* argv[]) {
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);
    
    FILE* add_reader_file = fopen(add_reader_path,"r");
    char addReader[64];
    if (add_reader_file == NULL) {
        fputs("Cannot open file.", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    while(fgets(addReader, sizeof(addReader), add_reader_file) != NULL) {
        send_add_reader_req_via_TCP(ctx, addReader);
    }
    fclose(add_reader_file);

    // Set purpose to make session key request for file sharing.
    ctx->config->purpose_index = 1;
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len;
    estimate_time_t estimate_time[5];
    hash_value_len = file_encrypt_upload(&s_key_list_0->s_key[0], ctx, my_file_path, &hash_value[0], &estimate_time[0]);
    char concat_buffer[MAX_PAYLOAD_LENGTH];
    int concat_buffer_size = make_upload_req_buffer(&s_key_list_0->s_key[0], ctx, &hash_value[0], hash_value_len, &concat_buffer);
    ctx->config->purpose_index = 0;
    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    printf("finished\n");
    sleep(1);
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread_read_one_each, (void *)session_ctx);
    send_secure_message("Hello", strlen("Hello"), session_ctx);
    sleep(1);
    send_secure_message(concat_buffer, concat_buffer_size, session_ctx);
    free_SST_ctx_t(ctx);
    pthread_cancel(thread);

}